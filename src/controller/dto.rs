//! DTO JSON-контракта. Только здесь живёт контракт.

use serde::{Deserialize, Serialize};

/// Запрос на /process.
///
/// Поддерживает две формы: контракт Приложения A ТЗ (`payload` + `payload_id`,
/// направление определяется по повторению id) и расширенную форму сервиса
/// (`operation` + `text`), где шаг задаётся явно.
#[derive(Debug, Deserialize)]
pub struct ProcessRequest {
    #[serde(default)]
    pub operation: Option<String>,
    /// Приложение A: строка для обработки.
    #[serde(default)]
    pub payload: Option<String>,
    /// Приложение A: ключ корреляции «маскирование → демаскирование».
    #[serde(default)]
    pub payload_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub mask_context: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub route: Option<String>,
    /// FEAT-05: dry_run — вернуть перечень того, что было бы замаскировано.
    #[serde(default)]
    pub dry_run: bool,
}

/// Ответ на mask.
#[derive(Debug, Serialize)]
pub struct MaskResponse {
    pub request_id: String,
    pub session_id: String,
    pub text: String,
    pub entities: Vec<super::process_handler::EntityDto>,
    pub degraded: bool,
    pub mask_context: Option<String>,
    pub stats: StatsDto,
}

#[derive(Debug, Serialize)]
pub struct StatsDto {
    pub tokens: usize,
    pub latency_ms: f64,
}

/// Ответ на demask.
#[derive(Debug, Serialize)]
pub struct DemaskResponse {
    pub request_id: String,
    pub session_id: String,
    pub text: String,
    pub restored: usize,
    pub unresolved: usize,
    pub degraded: bool,
}

/// Ответ по контракту Приложения A.
#[derive(Debug, Serialize)]
pub struct TzResponse {
    pub result: String,
}

/// Формат ошибки.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: String,
}

/// Запрос на /process/batch (NET-03).
#[derive(Debug, Deserialize)]
pub struct BatchRequest {
    pub operation: String,
    #[serde(default)]
    pub texts: Vec<String>,
    #[serde(default)]
    pub route: Option<String>,
}

/// Один элемент ответа батча.
#[derive(Debug, Serialize)]
pub struct BatchItem {
    pub index: usize,
    pub session_id: String,
    pub text: String,
    pub entities: Vec<super::process_handler::EntityDto>,
    pub degraded: bool,
    pub mask_context: Option<String>,
    pub error: Option<String>,
}

/// Ответ на /process/batch.
#[derive(Debug, Serialize)]
pub struct BatchResponse {
    pub request_id: String,
    pub results: Vec<BatchItem>,
}