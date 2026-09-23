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

/// Почему аутентификация не прошла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// Заголовков нет вовсе — кандидат на анонимный доступ по контракту ТЗ.
    Missing,
    /// Заголовки есть, но система неизвестна или ключ неверен.
    Invalid,
}

impl AuthFailure {
    pub fn status(self) -> StatusCode {
        StatusCode::UNAUTHORIZED
    }
}

/// Проверяет аутентификацию системы.
pub fn authenticate(
    cfg: &CompiledConfig,
    headers: &HeaderMap,
) -> Result<RequestCtx, AuthFailure> {
    let system_id = headers
        .get(&cfg.raw.security.system_id_header)
        .and_then(|v| v.to_str().ok());
    let key = headers
        .get(&cfg.raw.security.auth_header)
        .and_then(|v| v.to_str().ok());
    let (system_id, key) = match (system_id, key) {
        (Some(s), Some(k)) => (s, k),
        // Ни одного заголовка — запрос вообще без учётных данных.
        (None, None) => return Err(AuthFailure::Missing),
        _ => return Err(AuthFailure::Invalid),
    };

    let expected = cfg
        .system_keys
        .get(system_id)
        .ok_or(AuthFailure::Invalid)?;

    // PERF-06: SHA-256 ключа → сравнение 32 сырых байт в constant-time, без hex-строк.
    let key_hash = crate::infra::crypto::sha256_raw(key.as_bytes());
    let ok = match cfg.system_key_bytes.get(system_id) {
        Some(expected_bytes) => key_hash.ct_eq(expected_bytes).unwrap_u8() == 1,
        // Фолбэк для не-hex ключей: hex-сравнение.
        None => {
            let key_hex = crate::infra::crypto::sha256_hex(key.as_bytes());
            key_hex.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1
        }
    };
    if !ok {
        return Err(AuthFailure::Invalid);
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