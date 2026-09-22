//! Middleware: request_id, auth, лимит тела, таймаут, метрики.

use std::sync::Arc;

use http::{HeaderMap, StatusCode};
use subtle::ConstantTimeEq;

use crate::config::compiled::CompiledConfig;

/// Контекст запроса.
pub struct RequestCtx {
    pub request_id: String,
    pub system_id: String,
}

/// Генерирует request_id.
pub fn new_request_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Проверяет аутентификацию системы.
pub fn authenticate(
    cfg: &CompiledConfig,
    headers: &HeaderMap,
) -> Result<RequestCtx, StatusCode> {
    let system_id = headers
        .get(&cfg.raw.security.system_id_header)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let key = headers
        .get(&cfg.raw.security.auth_header)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let expected = cfg
        .system_keys
        .get(system_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // SHA-256 ключа → сравнение constant-time.
    let key_hash = crate::infra::crypto::sha256_hex(key.as_bytes());
    let expected_bytes = expected.as_bytes();
    let key_bytes = key_hash.as_bytes();
    if key_bytes.len() != expected_bytes.len() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if key_bytes.ct_eq(expected_bytes).unwrap_u8() != 1 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(RequestCtx {
        request_id: headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(new_request_id),
        system_id: system_id.to_string(),
    })
}

/// Проверяет лимит тела.
pub fn check_body_limit(cfg: &CompiledConfig, len: usize) -> Result<(), StatusCode> {
    if len > cfg.raw.server.max_body_bytes {
        Err(StatusCode::PAYLOAD_TOO_LARGE)
    } else {
        Ok(())
    }
}

/// Семафор для max_inflight.
pub struct InflightGuard {
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl InflightGuard {
    pub fn new(max: usize) -> Self {
        Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(max)),
        }
    }

    pub fn try_acquire(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        self.semaphore.try_acquire().ok()
    }
}