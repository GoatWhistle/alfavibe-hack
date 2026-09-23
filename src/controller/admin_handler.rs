//! Служебные эндпоинты: /health/*, /metrics, /admin/config/reload.

use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode};

use crate::config::compiled::CompiledConfig;
use crate::infra::metrics;

/// Обработчик служебных эндпоинтов.
pub struct AdminHandler {
    pub cfg: Arc<CompiledConfig>,
    pub vault_health: Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync>,
    pub reload: Arc<dyn Fn() -> Result<(), String> + Send + Sync>,
}

impl AdminHandler {
    pub fn health_live(&self) -> Response<Bytes> {
        Response::builder()
            .status(StatusCode::OK)
            .body(Bytes::from("ok"))
            .unwrap()
    }

    pub async fn health_ready(&self) -> Response<Bytes> {
        let vault_ok = (self.vault_health)().await;
        let body = serde_json::json!({
            "ready": vault_ok,
            "vault": vault_ok,
            "config_version": self.cfg.version,
        });
        let status = if vault_ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Bytes::from(body.to_string()))
            .unwrap()
    }

    pub fn metrics(&self) -> Response<Bytes> {
        let body = metrics::render();
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Bytes::from(body))
            .unwrap()
    }

    pub fn config_reload(&self, req: Request<hyper::body::Incoming>) -> Response<Bytes> {
        // Проверка admin-токена.
        let token = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        let expected = &self.cfg.admin_token_sha256;
        // Fail closed: не настроен токен — ручка недоступна, а не открыта всем.
        if expected.is_empty() {
            tracing::warn!("config reload rejected: security.admin_token_sha256 не задан");
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Bytes::from("admin token not configured"))
                .unwrap();
        }
        let token_hash = crate::infra::crypto::sha256_hex(token.as_bytes());
        if token_hash != *expected {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Bytes::from("unauthorized"))
                .unwrap();
        }
        match (self.reload)() {
            Ok(()) => Response::builder()
                .status(StatusCode::OK)
                .body(Bytes::from("reloaded"))
                .unwrap(),
            Err(e) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Bytes::from(format!("reload failed: {e}")))
                .unwrap(),
        }
    }
}