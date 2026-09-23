//! Контекстный скоринг: ключевые слова в окне вокруг кандидата.

use crate::domain::document::Document;
use crate::domain::entity::Candidate;
use crate::domain::traits::ContextScorer;

/// Проверка границ: символ перед start и после end не должен быть буквой/цифрой.
pub fn is_boundary(doc: &Document<'_>, start: usize, end: usize) -> bool {
    let norm = doc.norm.as_bytes();
    if start > 0 {
        let prev = norm[start - 1];
        if prev.is_ascii_alphanumeric() || is_cyrillic(prev) {
            return false;
        }
    }
    if end < norm.len() {
        let next = norm[end];
        if next.is_ascii_alphanumeric() || is_cyrillic(next) {
            return false;
        }
    }
    true
}

fn is_cyrillic(b: u8) -> bool {
    (0xC0..=0xFF).contains(&b) || b == 0xD0 || b == 0xD1
}

/// Безопасное окно нормализованного текста с выравниванием на границы символов.
pub fn window<'a>(doc: &'a Document<'_>, start: usize, end: usize) -> &'a str {
    let norm = &doc.norm;
    let mut s = start.min(norm.len());
    let mut e = end.min(norm.len());
    while s > 0 && !norm.is_char_boundary(s) {
        s -= 1;
    }
    while e < norm.len() && !norm.is_char_boundary(e) {
        e += 1;
    }
    &norm[s..e]
}

/// Ищет ключевые слова в окне [start-left, end+right] нормализованного текста.
/// Возвращает true, если найдено хотя бы одно позитивное слово.
pub fn has_context_word(
    doc: &Document<'_>,
    span_start: usize,
    span_end: usize,
    left: usize,
    right: usize,
    words: &[&str],
) -> bool {
    let norm = &doc.norm;
    let lo = span_start.saturating_sub(left);
    let hi = (span_end + right).min(norm.len());
    let window = &norm[lo..hi];
    words.iter().any(|w| window.contains(w))
}

/// Проверяет, есть ли слово в тексте как отдельное слово (с границами слов).
/// DET-04: `contains("ип")` не должен срабатывать на «тип»/«принцип».
pub fn has_word(text: &str, word: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric())
        .any(|w| w == word)
}

/// Проверяет, есть ли хотя бы одно из слов как отдельное слово.
pub fn has_any_word(text: &str, words: &[&str]) -> bool {
    words.iter().any(|w| has_word(text, w))
}

/// Проверяет, начинается ли какое-нибудь слово текста с одной из основ.
///
/// Нужна там, где в списке контекста стоят основы («водительск», «родил»):
/// точное сравнение их никогда не находит, потому что в тексте стоят
/// «водительское» и «родился».
pub fn has_any_prefix(text: &str, prefixes: &[&str]) -> bool {
    text.split(|c: char| !c.is_alphanumeric())
        .any(|word| !word.is_empty() && prefixes.iter().any(|p| word.starts_with(p)))
}

/// Контекстный скоринг по списку позитивных/негативных слов.
pub struct KeywordContextScorer {
    pub id: String,
    pub pos_words: Vec<String>,
    pub neg_words: Vec<String>,
    pub left: usize,
    pub right: usize,
}

impl ContextScorer for KeywordContextScorer {
    fn score(&self, doc: &Document<'_>, cand: &mut Candidate) {
        let norm = &doc.norm;
        let lo = cand.span.start.saturating_sub(self.left);
        let hi = (cand.span.end + self.right).min(norm.len());
        let window = &norm[lo..hi];

        let pos = self.pos_words.iter().any(|w| window.contains(w.as_str()));
        let neg = self.neg_words.iter().any(|w| window.contains(w.as_str()));

        if pos {
            cand.score = (cand.score + 0.35).min(1.0_f32);
            cand.signals |= crate::domain::entity::SignalFlags::CONTEXT_POS;
        }
        if neg {
            cand.score = (cand.score - 0.5).max(0.0_f32);
            cand.signals |= crate::domain::entity::SignalFlags::CONTEXT_NEG;
        }
    }
}