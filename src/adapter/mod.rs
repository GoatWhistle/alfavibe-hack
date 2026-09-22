//! Исходящие адаптеры.

pub mod circuit_breaker;
pub mod llm_client;
pub mod ner_http;
pub mod vault_memory;

#[cfg(feature = "redis")]
pub mod vault_redis;

#[cfg(feature = "ner-onnx")]
pub mod ner_onnx;