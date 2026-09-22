//! HTTP-клиент к LLM upstream.

use std::collections::HashMap;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};

use crate::domain::errors::UpstreamError;
use crate::domain::traits::{LlmClient, UpstreamId};

use super::circuit_breaker::SharedCircuitBreaker;

/// Конфигурация upstream.
pub struct UpstreamConfig {
    pub url: String,
    pub auth_header: String,
    pub auth_value: String,
    pub timeout_ms: u64,
    pub pass_headers: Vec<String>,
}

/// HTTP/HTTPS-клиент к LLM.
pub struct HttpLlmClient {
    pub upstreams: HashMap<String, UpstreamConfig>,
    pub circuit_breakers: HashMap<String, SharedCircuitBreaker>,
    pub client: hyper_util::client::legacy::Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
}

impl HttpLlmClient {
    pub fn new(
        upstreams: HashMap<String, UpstreamConfig>,
        circuit_breakers: HashMap<String, SharedCircuitBreaker>,
    ) -> Self {
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
            upstreams,
            circuit_breakers,
            client,
        }
    }
}

#[async_trait]
impl LlmClient for HttpLlmClient {
    async fn send(
        &self,
        upstream: &UpstreamId,
        req: Request<Full<Bytes>>,
        deadline: Instant,
    ) -> Result<Response<Bytes>, UpstreamError> {
        let Some(cfg) = self.upstreams.get(upstream) else {
            return Err(UpstreamError::Other(format!("unknown upstream {upstream}")));
        };
        let cb = self.circuit_breakers.get(upstream);
        if let Some(cb) = cb {
            if !cb.allow() {
                return Err(UpstreamError::Other("circuit open".into()));
            }
        }

        // Собрать URL.
        let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let url = format!("{}{}", cfg.url.trim_end_matches('/'), path);
        let uri: http::Uri = url
            .parse()
            .map_err(|e: http::uri::InvalidUri| UpstreamError::Other(e.to_string()))?;

        let mut builder = Request::builder()
            .method(req.method())
            .uri(uri)
            .version(req.version());
        // Заголовки из allowlist.
        for h in &cfg.pass_headers {
            if let Some(v) = req.headers().get(h) {
                builder = builder.header(h, v);
            }
        }
        if !cfg.auth_header.is_empty() && !cfg.auth_value.is_empty() {
            builder = builder.header(&cfg.auth_header, &cfg.auth_value);
        }
        let body = req.into_body();
        let out_req = builder
            .body(body)
            .map_err(|e| UpstreamError::Other(e.to_string()))?;

        // Таймаут = минимальный из deadline и cfg.timeout_ms.
        let cfg_timeout = std::time::Duration::from_millis(cfg.timeout_ms);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = remaining.min(cfg_timeout);
        let result = tokio::time::timeout(timeout, self.client.request(out_req)).await;

        match result {
            Ok(Ok(resp)) => {
                if let Some(cb) = cb {
                    cb.record(true);
                }
                let (parts, body) = resp.into_parts();
                let bytes = body
                    .collect()
                    .await
                    .map_err(|e| UpstreamError::Other(e.to_string()))?
                    .to_bytes();
                Ok(Response::from_parts(parts, bytes))
            }
            Ok(Err(e)) => {
                if let Some(cb) = cb {
                    cb.record(false);
                }
                Err(UpstreamError::Connect(e.to_string()))
            }
            Err(_) => {
                if let Some(cb) = cb {
                    cb.record(false);
                }
                Err(UpstreamError::Timeout)
            }
        }
    }
}