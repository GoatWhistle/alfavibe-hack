//! Нормализация текста (обёртка над Document).

use crate::domain::document::Document;
use crate::domain::traits::Normalizer;

/// Стандартный нормализатор.
pub struct DefaultNormalizer;

impl Normalizer for DefaultNormalizer {
    fn normalize<'a>(&self, text: &'a str) -> Document<'a> {
        Document::new(text)
    }
}