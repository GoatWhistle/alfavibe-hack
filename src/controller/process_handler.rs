//! Обработчик POST /process.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use serde::Serialize;

use crate::config::compiled::CompiledConfig;
use crate::service::guard_service::GuardService;
use crate::service::policy_resolver::PolicyResolver;

use super::dto::{DemaskResponse, ErrorBody, ErrorResponse, MaskResponse, ProcessRequest, StatsDto};
use super::error_mapper::ServiceError;
use super::middleware;

/// DTO сущности в ответе.
#[derive(Debug, Serialize)]
pub struct EntityDto {
    pub r#type: String,
    pub start: usize,
    pub end: usize,
    pub masked_start: usize,
    pub masked_end: usize,
    pub replacement: String,
    pub score: f32,
    pub source: String,
}

/// Обработчик /process.
pub struct ProcessHandler {
    pub cfg: Arc<CompiledConfig>,
    pub service: Arc<GuardService>,
    pub resolver: Arc<PolicyResolver>,
    pub token_counter: Arc<dyn crate::domain::traits::TokenCounter>,
    pub inflight: middleware::InflightGuard,
}

impl ProcessHandler {
    pub async fn handle(&self, req: Request<hyper::body::Incoming>) -> Response<Bytes> {
        let start = Instant::now();
        let request_id = middleware::new_request_id();

        // Backpressure: max_inflight.
        let _permit = match self.inflight.try_acquire() {
            Some(p) => p,
            None => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    ServiceError::Overloaded,
                    &request_id,
                );
            }
        };

        // Аутентификация.
        let auth = middleware::authenticate(&self.cfg, req.headers());
        let (system_id, request_id) = match auth {
            Ok(ctx) => (ctx.system_id, ctx.request_id),
            Err(status) => {
                return error_response(status, ServiceError::Unauthorized, &request_id);
            }
        };

        // Лимит тела.
        let body_len = req.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|s| s.parse().ok()).unwrap_or(0);
        if let Err(status) = middleware::check_body_limit(&self.cfg, body_len) {
            return error_response(status, ServiceError::PayloadTooLarge, &request_id);
        }

        // Чтение тела.
        let body = match read_body(req, self.cfg.raw.server.max_body_bytes).await {
            Ok(b) => b,
            Err(e) => return error_response(e.status(), e, &request_id),
        };

        // Парсинг DTO.
        let dto: ProcessRequest = match serde_json::from_slice(&body) {
            Ok(d) => d,
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    ServiceError::BadRequest("Невалидный JSON".into()),
                    &request_id,
                );
            }
        };

        // Резолв политики.
        let policy = match self.resolver.resolve(&system_id, dto.route.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                let se: ServiceError = e.into();
                return error_response(se.status(), se, &request_id);
            }
        };

        let deadline = Instant::now() + std::time::Duration::from_millis(self.cfg.raw.server.request_timeout_ms);

        match dto.operation.as_str() {
            "mask" => {
                let text = dto.text.clone().unwrap_or_default();
                let timeout = deadline.saturating_duration_since(Instant::now());
                let result = tokio::time::timeout(
                    timeout,
                    self.service
                        .mask(&policy, &system_id, &text, dto.session_id.as_deref(), deadline),
                )
                .await;
                let result = match result {
                    Ok(r) => r,
                    Err(_) => {
                        return error_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            ServiceError::UpstreamTimeout,
                            &request_id,
                        );
                    }
                };
                match result {
                    Ok(mask_result) => {
                        let entities: Vec<EntityDto> = mask_result
                            .entities
                            .iter()
                            .map(|e| EntityDto {
                                r#type: e.pd_type.clone(),
                                start: e.start,
                                end: e.end,
                                masked_start: e.masked_start,
                                masked_end: e.masked_end,
                                replacement: e.replacement.clone(),
                                score: e.score,
                                source: e.source.clone(),
                            })
                            .collect();
                        let tokens = self.token_counter.count(&text);
                        crate::infra::metrics::inc_requests(&system_id, dto.route.as_deref().unwrap_or(""), "mask", 200);
                        crate::infra::metrics::observe_request_duration(&system_id, dto.route.as_deref().unwrap_or(""), "mask", start.elapsed().as_secs_f64());
                        crate::infra::metrics::inc_tokens(&system_id, "mask", tokens as u64);
                        for e in &mask_result.entities {
                            crate::infra::metrics::inc_entities(&e.pd_type, &e.source);
                        }
                        tracing::info!(
                            request_id = %request_id,
                            system_id = %system_id,
                            operation = "mask",
                            status = 200,
                            tokens,
                            degraded = mask_result.degraded,
                            entities = mask_result.entities.len(),
                            latency_ms = start.elapsed().as_secs_f64() * 1000.0,
                            "processed"
                        );
                        let resp = MaskResponse {
                            request_id: request_id.clone(),
                            session_id: mask_result.session_id,
                            text: mask_result.text,
                            entities,
                            degraded: mask_result.degraded,
                            mask_context: mask_result.mask_context,
                            stats: StatsDto {
                                tokens,
                                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                            },
                        };
                        json_response(StatusCode::OK, &resp)
                    }
                    Err(e) => {
                        let se = match e {
                            crate::domain::errors::VaultError::Unavailable(_) => ServiceError::VaultUnavailable,
                            _ => ServiceError::Internal,
                        };
                        error_response(se.status(), se, &request_id)
                    }
                }
            }
            "demask" => {
                let session_id = dto.session_id.clone().unwrap_or_default();
                if session_id.is_empty() {
                    return error_response(StatusCode::BAD_REQUEST, ServiceError::BadRequest("session_id required".into()), &request_id);
                }
                let text = dto.text.clone().unwrap_or_default();
                let timeout = deadline.saturating_duration_since(Instant::now());
                let result = tokio::time::timeout(
                    timeout,
                    self.service
                        .demask(&policy, &system_id, &text, &session_id, dto.mask_context.as_deref(), deadline),
                )
                .await;
                let result = match result {
                    Ok(r) => r,
                    Err(_) => {
                        return error_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            ServiceError::UpstreamTimeout,
                            &request_id,
                        );
                    }
                };
                match result {
                    Ok(demask_result) => {
                        crate::infra::metrics::inc_requests(&system_id, dto.route.as_deref().unwrap_or(""), "demask", 200);
                        crate::infra::metrics::observe_request_duration(&system_id, dto.route.as_deref().unwrap_or(""), "demask", start.elapsed().as_secs_f64());
                        tracing::info!(
                            request_id = %request_id,
                            system_id = %system_id,
                            operation = "demask",
                            status = 200,
                            restored = demask_result.restored,
                            unresolved = demask_result.unresolved,
                            latency_ms = start.elapsed().as_secs_f64() * 1000.0,
                            "processed"
                        );
                        let resp = DemaskResponse {
                            request_id: request_id.clone(),
                            session_id,
                            text: demask_result.text,
                            restored: demask_result.restored,
                            unresolved: demask_result.unresolved,
                            degraded: demask_result.degraded,
                        };
                        json_response(StatusCode::OK, &resp)
                    }
                    Err(e) => {
                        let se = match e {
                            crate::domain::errors::VaultError::Unavailable(_) => ServiceError::SessionNotFound,
                            _ => ServiceError::Internal,
                        };
                        error_response(se.status(), se, &request_id)
                    }
                }
            }
            _ => error_response(
                StatusCode::BAD_REQUEST,
                ServiceError::BadRequest("operation must be mask or demask".into()),
                &request_id,
            ),
        }
    }
}

async fn read_body(req: Request<hyper::body::Incoming>, limit: usize) -> Result<Bytes, ServiceError> {
    let body = req.into_body();
    let limited = http_body_util::Limited::new(body, limit);
    let collected = limited
        .collect()
        .await
        .map_err(|_| ServiceError::PayloadTooLarge)?;
    Ok(collected.to_bytes())
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<Bytes> {
    let body = serde_json::to_vec(value).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Bytes::from(body))
        .unwrap()
}

fn error_response(status: StatusCode, se: ServiceError, request_id: &str) -> Response<Bytes> {
    crate::infra::metrics::inc_requests("", "", "", status.as_u16());
    let resp = ErrorResponse {
        error: ErrorBody {
            code: se.code().to_string(),
            message: se.message(),
            request_id: request_id.to_string(),
        },
    };
    let body = serde_json::to_vec(&resp).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Bytes::from(body))
        .unwrap()
}