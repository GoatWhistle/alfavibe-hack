//! Маппинг ошибок в HTTP-ответы.

use http::StatusCode;

use crate::config::loader::PolicyError;

/// Ошибка сервисного слоя.
#[derive(Debug, Clone)]
pub enum ServiceError {
    Unauthorized,
    Forbidden,
    BadRequest(String),
    PayloadTooLarge,
    SessionNotFound,
    Overloaded,
    DependencyUnavailable,
    VaultUnavailable,
    UpstreamError,
    UpstreamTimeout,
    Internal,
}

impl ServiceError {
    pub fn status(&self) -> StatusCode {
        match self {
            ServiceError::Unauthorized => StatusCode::UNAUTHORIZED,
            ServiceError::Forbidden => StatusCode::FORBIDDEN,
            ServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ServiceError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ServiceError::SessionNotFound => StatusCode::NOT_FOUND,
            ServiceError::Overloaded => StatusCode::SERVICE_UNAVAILABLE,
            ServiceError::DependencyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ServiceError::VaultUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ServiceError::UpstreamError => StatusCode::BAD_GATEWAY,
            ServiceError::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            ServiceError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            ServiceError::Unauthorized => "UNAUTHORIZED",
            ServiceError::Forbidden => "FORBIDDEN",
            ServiceError::BadRequest(_) => "BAD_REQUEST",
            ServiceError::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            ServiceError::SessionNotFound => "SESSION_NOT_FOUND",
            ServiceError::Overloaded => "OVERLOADED",
            ServiceError::DependencyUnavailable => "DEPENDENCY_UNAVAILABLE",
            ServiceError::VaultUnavailable => "VAULT_UNAVAILABLE",
            ServiceError::UpstreamError => "UPSTREAM_ERROR",
            ServiceError::UpstreamTimeout => "UPSTREAM_ERROR",
            ServiceError::Internal => "INTERNAL",
        }
    }

    pub fn message(&self) -> String {
        match self {
            ServiceError::Unauthorized => "Неверный ключ или неизвестная система".into(),
            ServiceError::Forbidden => "Доступ запрещён".into(),
            ServiceError::BadRequest(m) => m.clone(),
            ServiceError::PayloadTooLarge => "Тело запроса слишком большое".into(),
            ServiceError::SessionNotFound => "Сессия не найдена или истекла".into(),
            ServiceError::Overloaded => "Сервис перегружен, повторите позже".into(),
            ServiceError::DependencyUnavailable => "Зависимость временно недоступна".into(),
            ServiceError::VaultUnavailable => "Хранилище масок временно недоступно, повторите запрос позже".into(),
            ServiceError::UpstreamError => "Ошибка вышестоящего сервиса".into(),
            ServiceError::UpstreamTimeout => "Таймаут вышестоящего сервиса".into(),
            ServiceError::Internal => "Внутренняя ошибка".into(),
        }
    }
}

impl From<PolicyError> for ServiceError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::UnknownSystem => ServiceError::Unauthorized,
            PolicyError::SystemDisabled => ServiceError::Forbidden,
            PolicyError::RouteForbidden => ServiceError::Forbidden,
        }
    }
}