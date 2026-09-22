//! NER в процессе (ONNX Runtime). Требует feature `ner-onnx` и crates `ort`, `tokenizers`.
//! Заглушка: полная реализация требует добавления ort/tokenizers в Cargo.toml.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;

use crate::domain::document::Span;
use crate::domain::entity::Candidate;
use crate::domain::errors::NerError;
use crate::domain::traits::NerEngine;

/// ONNX NER-движок (заглушка).
pub struct OnnxNerEngine;

impl OnnxNerEngine {
    pub fn new(_model_path: &str, _tokenizer_path: &str) -> anyhow::Result<Self> {
        anyhow::bail!("onnx NER requires ort/tokenizers crates; add them to Cargo.toml under feature ner-onnx")
    }
}

#[async_trait]
impl NerEngine for OnnxNerEngine {
    fn name(&self) -> &str {
        "onnx"
    }
    async fn recognize(
        &self,
        _text: &str,
        _windows: &[Span],
        _deadline: Instant,
    ) -> Result<Vec<Candidate>, NerError> {
        Err(NerError::Unavailable("onnx engine not built".into()))
    }
    async fn health(&self) -> bool {
        false
    }
}