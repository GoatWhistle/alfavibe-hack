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
            ("GET", "/health/live") => self.admin.health_live(),
            ("GET", "/health/ready") => self.admin.health_ready().await,
            ("GET", "/metrics") => self.admin.metrics(),
            ("POST", "/admin/config/reload") => self.admin.config_reload(req),
            _ if path.starts_with("/proxy/") => self.proxy.handle(req).await,
            _ => http::Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(bytes::Bytes::from("not found"))
                .unwrap(),
        }
    }
}