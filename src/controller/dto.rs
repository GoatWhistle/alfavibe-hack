//! DTO JSON-контракта. Только здесь живёт контракт.

use serde::{Deserialize, Serialize};

/// Запрос на /process.
#[derive(Debug, Deserialize)]
pub struct ProcessRequest {
    pub operation: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub mask_context: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub route: Option<String>,
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