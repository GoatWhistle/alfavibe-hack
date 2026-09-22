//! Внешний NER-сервис (HTTP).

use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};

use crate::domain::document::Span;
use crate::domain::entity::{Candidate, DetectorSource};
use crate::domain::errors::NerError;
use crate::domain::pd_type::PdType;
use crate::domain::traits::NerEngine;

use super::circuit_breaker::SharedCircuitBreaker;

/// HTTP/HTTPS NER-клиент.
pub struct HttpNerEngine {
    pub url: String,
    pub timeout_ms: u64,
    pub circuit_breaker: Option<SharedCircuitBreaker>,
    pub client: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
}

impl HttpNerEngine {
    pub fn new(url: String, timeout_ms: u64, circuit_breaker: Option<SharedCircuitBreaker>) -> Self {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = hyper_util::client::legacy::Client::builder(
            hyper_util::rt::TokioExecutor::new(),
        )
        .build(https);
        Self {
            url,
            timeout_ms,
            circuit_breaker,
            client,
        }
    }
}

#[async_trait]
impl NerEngine for HttpNerEngine {
    fn name(&self) -> &str {
        "http"
    }

    async fn recognize(
        &self,
        text: &str,
        windows: &[Span],
        deadline: Instant,
    ) -> Result<Vec<Candidate>, NerError> {
        if let Some(cb) = &self.circuit_breaker {
            if !cb.allow() {
                return Err(NerError::Unavailable("circuit open".into()));
            }
        }
        let _ = deadline;
        // Собрать тексты окон.
        let texts: Vec<String> = windows
            .iter()
            .map(|w| text[w.start..w.end].to_string())
            .collect();
        let body = serde_json::json!({ "texts": texts }).to_string();

        let req = http::Request::builder()
            .method("POST")
            .uri(&self.url)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| NerError::Internal(e.to_string()))?;

        let timeout = std::time::Duration::from_millis(self.timeout_ms);
        let result = tokio::time::timeout(timeout, self.client.request(req)).await;

        match result {
            Ok(Ok(resp)) => {
                let status = resp.status();
                let body = resp.into_body().collect().await.map_err(|e| NerError::Internal(e.to_string()))?.to_bytes();
                if !status.is_success() {
                    if let Some(cb) = &self.circuit_breaker {
                        cb.record(false);
                    }
                    return Err(NerError::Unavailable(format!("status {status}")));
                }
                if let Some(cb) = &self.circuit_breaker {
                    cb.record(true);
                }
                parse_ner_response(&body)
            }
            Ok(Err(e)) => {
                if let Some(cb) = &self.circuit_breaker {
                    cb.record(false);
                }
                Err(NerError::Unavailable(e.to_string()))
            }
            Err(_) => {
                if let Some(cb) = &self.circuit_breaker {
                    cb.record(false);
                }
                Err(NerError::Timeout)
            }
        }
    }

    async fn health(&self) -> bool {
        true
    }
}

fn parse_ner_response(body: &[u8]) -> Result<Vec<Candidate>, NerError> {
    let v: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| NerError::Internal(format!("bad ner response: {e}")))?;
    let mut out = Vec::new();
    if let Some(entities) = v.get("entities").and_then(|e| e.as_array()) {
        for e in entities {
            let label = e.get("label").and_then(|l| l.as_str()).unwrap_or("");
            let start = e.get("start").and_then(|s| s.as_u64()).unwrap_or(0) as usize;
            let end = e.get("end").and_then(|s| s.as_u64()).unwrap_or(0) as usize;
            let score = e.get("score").and_then(|s| s.as_f64()).unwrap_or(0.0) as f32;
            let pd_type = match label {
                "PER" => PdType::new(PdType::FIO),
                "LOC" => PdType::new(PdType::ADDR_CITY),
                _ => continue,
            };
            out.push(Candidate::new(
                pd_type,
                Span::new(start, end),
                score * 0.9,
                DetectorSource::Ner { model: "http".into() },
            ));
        }
    }
    Ok(out)
}