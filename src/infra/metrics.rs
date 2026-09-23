//! Метрики Prometheus.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use once_cell::sync::OnceCell;

/// Глобальный handle для рендера метрик (устанавливается в install).
static HANDLE: OnceCell<PrometheusHandle> = OnceCell::new();

/// Устанавливает глобальный recorder и сохраняет handle ТОГО ЖЕ рекордера.
///
/// Раньше handle брался от второго, никуда не установленного рекордера, и
/// `GET /metrics` всегда отдавал пустую строку.
pub fn install() -> anyhow::Result<()> {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder)
        .map_err(|e| anyhow::anyhow!("failed to set metrics recorder: {e}"))?;
    HANDLE
        .set(handle)
        .map_err(|_| anyhow::anyhow!("metrics handle already installed"))?;
    Ok(())
}

/// Фоновая уборка гистограмм. Требует запущенного tokio-runtime.
pub fn spawn_upkeep() {
    let Some(handle) = HANDLE.get().cloned() else {
        return;
    };
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            ticker.tick().await;
            handle.run_upkeep();
        }
    });
}

/// Возвращает текущий Prometheus-текст.
pub fn render() -> String {
    match HANDLE.get() {
        Some(h) => h.render(),
        None => String::new(),
    }
}

/// Инкремент счётчика запросов.
pub fn inc_requests(system: &str, route: &str, operation: &str, status: u16) {
    metrics::counter!("pdg_requests_total", "system" => system.to_string(), "route" => route.to_string(), "operation" => operation.to_string(), "status" => status.to_string()).increment(1);
}

/// Гистограмма длительности запроса.
pub fn observe_request_duration(system: &str, route: &str, operation: &str, secs: f64) {
    metrics::histogram!("pdg_request_duration_seconds", "system" => system.to_string(), "route" => route.to_string(), "operation" => operation.to_string()).record(secs);
}

/// Гистограмма длительности стадии.
pub fn observe_stage_duration(stage: &str, secs: f64) {
    metrics::histogram!("pdg_stage_duration_seconds", "stage" => stage.to_string()).record(secs);
}

/// Счётчик токенов.
pub fn inc_tokens(system: &str, operation: &str, n: u64) {
    metrics::counter!("pdg_tokens_processed_total", "system" => system.to_string(), "operation" => operation.to_string()).increment(n);
}

/// Счётчик сущностей.
pub fn inc_entities(pd_type: &str, source: &str) {
    metrics::counter!("pdg_entities_total", "pd_type" => pd_type.to_string(), "source" => source.to_string()).increment(1);
}

/// Счётчик деградаций.
pub fn inc_degraded(reason: &str) {
    metrics::counter!("pdg_degraded_total", "reason" => reason.to_string()).increment(1);
}

/// Счётчик NER-запросов.
pub fn inc_ner_requests(status: &str) {
    metrics::counter!("pdg_ner_requests_total", "status" => status.to_string()).increment(1);
}

/// Счётчик усечённых окон NER.
pub fn inc_ner_windows_truncated() {
    metrics::counter!("pdg_ner_windows_truncated_total").increment(1);
}

/// Счётчик операций vault.
pub fn inc_vault_ops(op: &str, status: &str) {
    metrics::counter!("pdg_vault_ops_total", "op" => op.to_string(), "status" => status.to_string()).increment(1);
}

/// Счётчик неизвестных плейсхолдеров.
pub fn inc_demask_unknown_placeholder() {
    metrics::counter!("pdg_demask_unknown_placeholder_total").increment(1);
}

/// Gauge in-flight запросов.
pub fn set_inflight(n: i64) {
    metrics::gauge!("pdg_inflight_requests").set(n as f64);
}

/// Счётчик ошибок перезагрузки конфига.
pub fn inc_config_reload_failures() {
    metrics::counter!("pdg_config_reload_failures_total").increment(1);
}

/// Gauge версии конфига.
pub fn set_config_version(v: u64) {
    metrics::gauge!("pdg_config_version").set(v as f64);
}

/// Счётчик утечек, обнаруженных самопроверкой после маскирования (DET-06).
pub fn inc_leak_detected(pd_type: &str) {
    metrics::counter!("pdg_leak_detected_total", "pd_type" => pd_type.to_string()).increment(1);
}