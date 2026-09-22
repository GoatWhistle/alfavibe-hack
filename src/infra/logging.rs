//! Настройка логирования (tracing, JSON).

use tracing_subscriber::EnvFilter;

/// Инициализирует tracing-subscriber. `format` = "json" | "text".
pub fn init(level: &str, format: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    if format == "json" {
        builder.json().init();
    } else {
        builder.init();
    }
}