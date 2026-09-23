//! Роутер: сопоставление method+path → handler.

use http::{Request, StatusCode};

use super::admin_handler;
use super::process_handler;
use super::proxy_handler;

/// Обработчик запроса.
pub type Handler = Box<
    dyn Fn(
            Request<hyper::body::Incoming>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = http::Response<bytes::Bytes>> + Send>,
        > + Send
        + Sync,
>;

/// Роутер.
pub struct Router {
    pub process: process_handler::ProcessHandler,
    pub proxy: proxy_handler::ProxyHandler,
    pub admin: admin_handler::AdminHandler,
}

impl Router {
    pub async fn route(&self, req: Request<hyper::body::Incoming>) -> http::Response<bytes::Bytes> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        match (method.as_str(), path.as_str()) {
            ("POST", "/process") => self.process.handle(req).await,
            ("POST", "/process/batch") => self.process.handle_batch(req).await,
            // Пробы живости остаются на публичном порту — их опрашивает оркестратор.
            ("GET", "/health/live") => self.admin.health_live(),
            ("GET", "/health/ready") => self.admin.health_ready().await,
            _ if path.starts_with("/proxy/") => self.proxy.handle(req).await,
            _ => not_found(),
        }
    }

    /// Служебный роутер: слушает только admin_listen (по умолчанию 127.0.0.1).
    /// Метрики и перезагрузка конфига на публичный порт не выносятся.
    pub async fn route_admin(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> http::Response<bytes::Bytes> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        match (method.as_str(), path.as_str()) {
            ("GET", "/metrics") => self.admin.metrics(),
            ("GET", "/health/live") => self.admin.health_live(),
            ("GET", "/health/ready") => self.admin.health_ready().await,
            ("POST", "/admin/config/reload") => self.admin.config_reload(req),
            _ => not_found(),
        }
    }
}

fn not_found() -> http::Response<bytes::Bytes> {
    http::Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(bytes::Bytes::from("not found"))
        .unwrap()
}