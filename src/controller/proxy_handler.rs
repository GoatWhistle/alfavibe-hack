//! Обработчик прокси-режима: /proxy/{route_id}/...

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};

use crate::config::compiled::CompiledConfig;
use crate::service::guard_service::GuardService;
use crate::service::json_paths;
use crate::service::policy_resolver::PolicyResolver;

use super::error_mapper::ServiceError;
use super::middleware;

/// Обработчик прокси.
pub struct ProxyHandler {
    pub cfg: Arc<CompiledConfig>,
    pub service: Arc<GuardService>,
    pub resolver: Arc<PolicyResolver>,
}

impl ProxyHandler {
    pub async fn handle(&self, req: Request<hyper::body::Incoming>) -> Response<Bytes> {
        let request_id = middleware::new_request_id();
        let auth = middleware::authenticate(&self.cfg, req.headers());
        let (system_id, request_id) = match auth {
            Ok(ctx) => (ctx.system_id, ctx.request_id),
            Err(status) => {
                return error_response(status, ServiceError::Unauthorized, &request_id);
            }
        };

        // Найти маршрут по path.
        let path = req.uri().path().to_string();
        let route_path = path.strip_prefix("/proxy/").unwrap_or("").to_string();
        let route = self
            .cfg
            .routes
            .iter()
            .find(|r| {
                let method_match = r.r#match.method == req.method().as_str();
                let path_match = if !r.r#match.path.is_empty() {
                    route_path == r.r#match.path
                } else if !r.r#match.path_prefix.is_empty() {
                    route_path.starts_with(&r.r#match.path_prefix)
                } else {
                    false
                };
                method_match && path_match
            });

        let Some(route) = route else {
            return error_response(StatusCode::NOT_FOUND, ServiceError::BadRequest("route not found".into()), &request_id);
        };

        // action bypass/block.
        if let Some(action) = &route.action {
            if action == "block" {
                return error_response(StatusCode::FORBIDDEN, ServiceError::Forbidden, &request_id);
            }
            if action == "bypass" {
                // Проксировать без маскирования.
                return self.proxy_raw(req, route, &request_id).await;
            }
        }

        // Резолв политики.
        let policy = match self.resolver.resolve(&system_id, Some(&route.id)) {
            Ok(p) => p,
            Err(e) => {
                let se: ServiceError = e.into();
                return error_response(se.status(), se, &request_id);
            }
        };

        // Чтение тела.
        let method = req.method().clone();
        let uri = req.uri().clone();
        let version = req.version();
        let headers = req.headers().clone();
        let body = match read_body(req, self.cfg.raw.server.max_body_bytes).await {
            Ok(b) => b,
            Err(e) => return error_response(e.status(), e, &request_id),
        };

        // Маскирование по json_paths.
        let mut json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                return error_response(StatusCode::BAD_REQUEST, ServiceError::BadRequest("invalid json".into()), &request_id);
            }
        };

        let deadline = Instant::now() + std::time::Duration::from_millis(self.cfg.raw.server.request_timeout_ms);
        let degraded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Одна сессия на весь прокси-запрос (запрос → ответ).
        let session_id = uuid::Uuid::now_v7().to_string();

        for path_str in &route.request.json_paths {
            let path = json_paths::parse_path(path_str);
            let Some(path) = path else { continue };
            let service = self.service.clone();
            let policy = policy.clone();
            let degraded_flag = degraded.clone();
            let dl = deadline;
            let sid = session_id.clone();
            let sys = system_id.clone();
            json_paths::replace_async(&mut json, &path, &mut |s| {
                let service = service.clone();
                let policy = policy.clone();
                let degraded_flag = degraded_flag.clone();
                let sid = sid.clone();
                let sys = sys.clone();
                let s = s.to_string();
                async move {
                    match service.mask(&policy, &sys, &s, Some(&sid), dl).await {
                        Ok(r) => {
                            if r.degraded {
                                degraded_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            r.text
                        }
                        Err(_) => s,
                    }
                }
            })
            .await;
        }

        // Отправить в upstream.
        let new_body = serde_json::to_vec(&json).unwrap_or_default();
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .version(version);
        for (k, v) in &headers {
            builder = builder.header(k, v);
        }
        let out_req = builder.body(Full::new(Bytes::from(new_body))).unwrap();

        let upstream = route.upstream.clone();
        let llm = self.service.llm.clone();
        let Some(llm) = llm else {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, ServiceError::Internal, &request_id);
        };

        let result = llm.send(&upstream, out_req, deadline).await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.into_body();
                let mut resp = Response::builder().status(status);
                if degraded.load(std::sync::atomic::Ordering::Relaxed) {
                    resp = resp.header("x-pd-degraded", "ner");
                }
                // Демаскирование ответа LLM по response.json_paths.
                if route.response.demask && !route.response.json_paths.is_empty() {
                    let body = demask_response(&self.service, &policy, &system_id, &session_id, body, &route.response.json_paths).await;
                    resp.body(body).unwrap()
                } else {
                    resp.body(body).unwrap()
                }
            }
            Err(_) => error_response(StatusCode::BAD_GATEWAY, ServiceError::UpstreamError, &request_id),
        }
    }

    async fn proxy_raw(&self, req: Request<hyper::body::Incoming>, route: &crate::config::model::RouteConfig, request_id: &str) -> Response<Bytes> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let version = req.version();
        let headers = req.headers().clone();
        let body = match read_body(req, self.cfg.raw.server.max_body_bytes).await {
            Ok(b) => b,
            Err(e) => return error_response(e.status(), e, request_id),
        };
        let deadline = Instant::now() + std::time::Duration::from_millis(self.cfg.raw.server.request_timeout_ms);
        let upstream = route.upstream.clone();
        let llm = self.service.llm.clone();
        let Some(llm) = llm else {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, ServiceError::Internal, request_id);
        };
        let mut builder = Request::builder().method(method).uri(uri).version(version);
        for (k, v) in &headers {
            builder = builder.header(k, v);
        }
        let out_req = builder.body(Full::new(body)).unwrap();
        let result = llm.send(&upstream, out_req, deadline).await;
        match result {
            Ok(resp) => resp,
            Err(_) => error_response(StatusCode::BAD_GATEWAY, ServiceError::UpstreamError, request_id),
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

/// Демаскирует ответ LLM по json_paths.
async fn demask_response(
    service: &Arc<GuardService>,
    policy: &Arc<crate::domain::traits::EffectivePolicy>,
    system_id: &str,
    session_id: &str,
    body: Bytes,
    json_paths: &[String],
) -> Bytes {
    let mut json: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return body,
    };
    for path_str in json_paths {
        let path = json_paths::parse_path(path_str);
        let Some(path) = path else { continue };
        let service = service.clone();
        let policy = policy.clone();
        let sid = session_id.to_string();
        let sys = system_id.to_string();
        json_paths::replace_async(&mut json, &path, &mut |s| {
            let service = service.clone();
            let policy = policy.clone();
            let sid = sid.clone();
            let sys = sys.clone();
            let s = s.to_string();
            async move {
                match service.demask(&policy, &sys, &s, &sid, None, Instant::now() + std::time::Duration::from_secs(1)).await {
                    Ok(r) => r.text,
                    Err(_) => s,
                }
            }
        })
        .await;
    }
    serde_json::to_vec(&json).map(Bytes::from).unwrap_or(body)
}

fn error_response(status: StatusCode, se: ServiceError, request_id: &str) -> Response<Bytes> {
    let resp = super::dto::ErrorResponse {
        error: super::dto::ErrorBody {
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