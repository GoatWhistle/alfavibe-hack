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

use super::dto::{BatchItem, BatchRequest, BatchResponse, DemaskResponse, ErrorBody, ErrorResponse, MaskResponse, ProcessRequest, StatsDto, TzResponse};
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
    pub rate_limiter: Arc<crate::infra::rate_limit::RateLimiter>,
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

        // Аутентификация. Проверяющая система по Приложению B шлёт /process без
        // заголовков, поэтому запрос совсем без учётных данных обслуживается
        // системой по умолчанию, если она задана в конфиге. Неверный ключ —
        // всегда отказ.
        let auth = middleware::authenticate(&self.cfg, req.headers());
        let (system_id, request_id) = match auth {
            Ok(ctx) => (ctx.system_id, ctx.request_id),
            Err(middleware::AuthFailure::Missing)
                if !self.cfg.raw.security.default_system_id.is_empty() =>
            {
                (
                    self.cfg.raw.security.default_system_id.clone(),
                    request_id,
                )
            }
            Err(failure) => {
                return error_response(failure.status(), ServiceError::Unauthorized, &request_id);
            }
        };

        // OPS-03: ограничение частоты по системам.
        let rps = self.cfg.system_rate_limit.get(&system_id).copied().unwrap_or(0);
        if let Err(retry_after) = self.rate_limiter.check(&system_id, rps) {
            let secs = retry_after.as_secs().max(1);
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("retry-after", secs.to_string())
                .body(Bytes::from(
                    serde_json::to_vec(&ErrorResponse {
                        error: ErrorBody {
                            code: "rate_limited".into(),
                            message: "rate limit exceeded".into(),
                            request_id: request_id.clone(),
                        },
                    })
                    .unwrap_or_default(),
                ))
                .unwrap();
        }

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

        // Контракт Приложения A: {payload, payload_id} → {result}.
        if let Some(payload_id) = dto.payload_id.as_deref() {
            return self
                .handle_tz(
                    &policy,
                    &system_id,
                    payload_id,
                    dto.payload.as_deref().unwrap_or_default(),
                    &request_id,
                    deadline,
                    start,
                )
                .await;
        }

        let operation = dto.operation.as_deref().unwrap_or_default();
        match operation {
            "mask" => {
                let text = dto.text.clone().unwrap_or_default();
                let timeout = deadline.saturating_duration_since(Instant::now());
                let result = tokio::time::timeout(
                    timeout,
                    self.service
                        .mask(&policy, &system_id, &text, dto.session_id.as_deref(), deadline, dto.dry_run),
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
                        // OPS-06: перечень типов ПД с количеством находок (без значений).
                        let mut type_counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
                        for e in &mask_result.entities {
                            *type_counts.entry(e.pd_type.as_str()).or_insert(0) += 1;
                        }
                        let type_counts_json = serde_json::to_string(&type_counts).unwrap_or_default();
                        tracing::info!(
                            request_id = %request_id,
                            system_id = %system_id,
                            operation = "mask",
                            status = 200,
                            tokens,
                            degraded = mask_result.degraded,
                            entities = mask_result.entities.len(),
                            entity_types = %type_counts_json,
                            entity_spans = %entity_spans(&self.cfg, &mask_result.entities),
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
                        crate::infra::metrics::inc_tokens(&system_id, "demask", self.token_counter.count(&text) as u64);
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

impl ProcessHandler {
    /// Обработка формы Приложения A. Ответ всегда `{"result": "…"}`.
    #[allow(clippy::too_many_arguments)]
    async fn handle_tz(
        &self,
        policy: &crate::domain::traits::EffectivePolicy,
        system_id: &str,
        payload_id: &str,
        payload: &str,
        request_id: &str,
        deadline: Instant,
        start: Instant,
    ) -> Response<Bytes> {
        let timeout = deadline.saturating_duration_since(Instant::now());
        let outcome = tokio::time::timeout(
            timeout,
            self.service
                .process_tz(policy, system_id, payload_id, payload, deadline),
        )
        .await;

        let outcome = match outcome {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => {
                let se = match e {
                    crate::domain::errors::VaultError::Unavailable(_) => {
                        ServiceError::VaultUnavailable
                    }
                    _ => ServiceError::Internal,
                };
                return error_response(se.status(), se, request_id);
            }
            Err(_) => {
                return error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    ServiceError::UpstreamTimeout,
                    request_id,
                );
            }
        };

        let step = outcome.step();
        let tokens = self.token_counter.count(payload);
        crate::infra::metrics::inc_requests(system_id, "", step, 200);
        crate::infra::metrics::observe_request_duration(
            system_id,
            "",
            step,
            start.elapsed().as_secs_f64(),
        );
        crate::infra::metrics::inc_tokens(system_id, step, tokens as u64);

        // OPS-06: по каждому запросу логируем типы найденных ПД, без значений.
        match &outcome {
            crate::service::guard_service::TzOutcome::Masked(m) => {
                for e in &m.entities {
                    crate::infra::metrics::inc_entities(&e.pd_type, &e.source);
                }
                let mut type_counts: std::collections::BTreeMap<&str, usize> =
                    std::collections::BTreeMap::new();
                for e in &m.entities {
                    *type_counts.entry(e.pd_type.as_str()).or_insert(0) += 1;
                }
                tracing::info!(
                    request_id = %request_id,
                    system_id = %system_id,
                    operation = step,
                    status = 200,
                    tokens,
                    degraded = m.degraded,
                    entities = m.entities.len(),
                    entity_types = %serde_json::to_string(&type_counts).unwrap_or_default(),
                    entity_spans = %entity_spans(&self.cfg, &m.entities),
                    latency_ms = start.elapsed().as_secs_f64() * 1000.0,
                    "processed"
                );
            }
            crate::service::guard_service::TzOutcome::Restored { restored, .. } => {
                tracing::info!(
                    request_id = %request_id,
                    system_id = %system_id,
                    operation = step,
                    status = 200,
                    tokens,
                    restored,
                    latency_ms = start.elapsed().as_secs_f64() * 1000.0,
                    "processed"
                );
            }
            crate::service::guard_service::TzOutcome::Repeated(_) => {
                tracing::info!(
                    request_id = %request_id,
                    system_id = %system_id,
                    operation = step,
                    status = 200,
                    tokens,
                    latency_ms = start.elapsed().as_secs_f64() * 1000.0,
                    "processed"
                );
            }
        }

        json_response(
            StatusCode::OK,
            &TzResponse {
                result: outcome.text().to_string(),
            },
        )
    }
}

/// OPS-06: позиции найденных сущностей (тип и границы, без значений).
/// Включается флагом logging.log_entity_offsets.
fn entity_spans(
    cfg: &CompiledConfig,
    entities: &[crate::service::pipeline::MaskedEntityInfo],
) -> String {
    if !cfg.raw.logging.log_entity_offsets || entities.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(entities.len() * 16);
    for (i, e) in entities.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{}:{}-{}", e.pd_type, e.start, e.end));
    }
    out
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

impl ProcessHandler {
    /// Обработчик POST /process/batch (NET-03).
    pub async fn handle_batch(&self, req: Request<hyper::body::Incoming>) -> Response<Bytes> {
        let start = Instant::now();
        let request_id = middleware::new_request_id();

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

        let auth = middleware::authenticate(&self.cfg, req.headers());
        let (system_id, request_id) = match auth {
            Ok(ctx) => (ctx.system_id, ctx.request_id),
            Err(failure) => {
                return error_response(failure.status(), ServiceError::Unauthorized, &request_id);
            }
        };

        // OPS-03: ограничение частоты.
        let rps = self.cfg.system_rate_limit.get(&system_id).copied().unwrap_or(0);
        if let Err(retry_after) = self.rate_limiter.check(&system_id, rps) {
            let secs = retry_after.as_secs().max(1);
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("retry-after", secs.to_string())
                .body(Bytes::from(
                    serde_json::to_vec(&ErrorResponse {
                        error: ErrorBody {
                            code: "rate_limited".into(),
                            message: "rate limit exceeded".into(),
                            request_id: request_id.clone(),
                        },
                    })
                    .unwrap_or_default(),
                ))
                .unwrap();
        }

        let body = match read_body(req, self.cfg.raw.server.max_body_bytes).await {
            Ok(b) => b,
            Err(e) => return error_response(e.status(), e, &request_id),
        };
        let dto: BatchRequest = match serde_json::from_slice(&body) {
            Ok(d) => d,
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    ServiceError::BadRequest("Невалидный JSON".into()),
                    &request_id,
                );
            }
        };
        let policy = match self.resolver.resolve(&system_id, dto.route.as_deref()) {
            Ok(p) => p,
            Err(e) => {
                let se: ServiceError = e.into();
                return error_response(se.status(), se, &request_id);
            }
        };

        let deadline = Instant::now() + std::time::Duration::from_millis(self.cfg.raw.server.request_timeout_ms);
        let mut results = Vec::with_capacity(dto.texts.len());
        for (i, text) in dto.texts.iter().enumerate() {
            let item = match dto.operation.as_str() {
                "mask" => {
                    let timeout = deadline.saturating_duration_since(Instant::now());
                    let r = tokio::time::timeout(
                        timeout,
                        self.service.mask(&policy, &system_id, text, None, deadline, false),
                    )
                    .await;
                    match r {
                        Ok(Ok(mask_result)) => {
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
                            BatchItem {
                                index: i,
                                session_id: mask_result.session_id,
                                text: mask_result.text,
                                entities,
                                degraded: mask_result.degraded,
                                mask_context: mask_result.mask_context,
                                error: None,
                            }
                        }
                        Ok(Err(e)) => BatchItem {
                            index: i,
                            session_id: String::new(),
                            text: text.clone(),
                            entities: Vec::new(),
                            degraded: false,
                            mask_context: None,
                            error: Some(e.to_string()),
                        },
                        Err(_) => BatchItem {
                            index: i,
                            session_id: String::new(),
                            text: text.clone(),
                            entities: Vec::new(),
                            degraded: false,
                            mask_context: None,
                            error: Some("timeout".into()),
                        },
                    }
                }
                _ => BatchItem {
                    index: i,
                    session_id: String::new(),
                    text: text.clone(),
                    entities: Vec::new(),
                    degraded: false,
                    mask_context: None,
                    error: Some("operation must be mask".into()),
                },
            };
            results.push(item);
        }

        crate::infra::metrics::inc_requests(&system_id, dto.route.as_deref().unwrap_or(""), "batch", 200);
        crate::infra::metrics::observe_request_duration(&system_id, dto.route.as_deref().unwrap_or(""), "batch", start.elapsed().as_secs_f64());
        tracing::info!(
            request_id = %request_id,
            system_id = %system_id,
            operation = "batch",
            status = 200,
            items = results.len(),
            latency_ms = start.elapsed().as_secs_f64() * 1000.0,
            "processed"
        );
        let resp = BatchResponse { request_id, results };
        json_response(StatusCode::OK, &resp)
    }
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