//! Ошибки доменного слоя.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NerError {
    #[error("NER engine unavailable: {0}")]
    Unavailable(String),
    #[error("NER timeout")]
    Timeout,
    #[error("NER internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("upstream connection error: {0}")]
    Connect(String),
    #[error("upstream timeout")]
    Timeout,
    #[error("upstream returned status {0}")]
    Status(u16),
    #[error("upstream error: {0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault unavailable: {0}")]
    Unavailable(String),
    #[error("vault crypto error: {0}")]
    Crypto(String),
    #[error("vault serialization error: {0}")]
    Serialization(String),
    #[error("vault internal error: {0}")]
    Internal(String),
}