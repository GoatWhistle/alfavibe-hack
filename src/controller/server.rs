//! hyper-сервер с graceful shutdown.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use super::router::Router;

/// Запускает HTTP-сервер. `admin = true` — служебные маршруты (метрики, reload).
pub async fn serve_kind(listen: &str, router: Arc<Router>, admin: bool) -> anyhow::Result<()> {
    let addr: SocketAddr = listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, kind = if admin { "admin" } else { "public" }, "listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let router = router.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let router = router.clone();
                async move {
                    let resp = if admin {
                        router.route_admin(req).await
                    } else {
                        router.route(req).await
                    };
                    let (parts, body) = resp.into_parts();
                    let full = http_body_util::Full::new(body);
                    Ok::<_, std::convert::Infallible>(http::Response::from_parts(parts, full))
                }
            });
            let conn = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, service);
            let _ = conn.await;
        });
    }
}

/// Публичный сервер (совместимость со старым именем).
pub async fn serve(listen: &str, router: Arc<Router>) -> anyhow::Result<()> {
    serve_kind(listen, router, false).await
}

/// Запускает сервер и ждёт сигнала завершения.
pub async fn run(listen: &str, router: Arc<Router>) -> anyhow::Result<()> {
    let server = serve_kind(listen, router, false);
    tokio::select! {
        r = server => r,
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received");
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        sig.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}