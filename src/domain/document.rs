//! Документ: исходный текст + нормализованная форма + карта смещений.

use unicode_normalization::UnicodeNormalization;

/// Диапазон [start, end) в байтах исходной строки.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    pub fn contains(&self, other: &Span) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    pub fn overlaps(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Документ с нормализованным текстом и картой смещений norm → original.
pub struct Document<'a> {
    pub original: &'a str,
    /// PERF-16: для ASCII-текста нормализация заимствуется (Cow::Borrowed).
    pub norm: std::borrow::Cow<'a, str>,
    norm_to_orig: Vec<u32>,
}

impl<'a> Document<'a> {
    pub fn new(original: &'a str) -> Self {
        // PERF-16: быстрый путь — если текст не требует свёртки, заимствуем.
        if is_ascii_fast_path(original) {
            return Document {
                original,
                norm: std::borrow::Cow::Borrowed(original),
                norm_to_orig: Vec::new(),
            };
        }

        let mut norm = String::with_capacity(original.len());
        let mut norm_to_orig: Vec<u32> = Vec::with_capacity(original.len() + 1);

        // PERF-14: пишем символы напрямую в преаллоцированную строку,
        // без промежуточных String на каждый символ (nfkc/to_lowercase — итераторы).
        for (orig_byte, ch) in original.char_indices() {
            for nc in ch.nfkc() {
                for lc in nc.to_lowercase() {
                    for mc in normalize_char(lc).chars() {
                        let mut buf = [0u8; 4];
                        let s = mc.encode_utf8(&mut buf);
                        for _ in 0..s.len() {
                            norm_to_orig.push(orig_byte as u32);
                        }
                        norm.push(mc);
                    }
                }
            }
        }
        // sentinel в конце
        norm_to_orig.push(original.len() as u32);

        Document {
            original,
            norm: std::borrow::Cow::Owned(norm),
            norm_to_orig,
        }
    }

    /// Перевод диапазона norm → original. Результат на границах символов.
    pub fn to_original(&self, norm_start: usize, norm_end: usize) -> Span {
        // PERF-16: для ASCII-текста карта тождественна.
        if self.norm_to_orig.is_empty() {
            return Span::new(norm_start, norm_end);
        }
        let ns = norm_start.min(self.norm.len());
        let ne = norm_end.min(self.norm.len());
        let start = self.norm_to_orig[ns] as usize;
        let end = self.norm_to_orig[ne] as usize;
        // Выровнять на границы символов UTF-8.
        let start = self.align_forward(start);
        let end = self.align_forward(end);
        Span::new(start, end)
    }

    pub fn original_slice(&self, span: Span) -> &'a str {
        &self.original[span.start..span.end]
    }

    fn align_forward(&self, mut byte: usize) -> usize {
        while byte < self.original.len() && !self.original.is_char_boundary(byte) {
            byte += 1;
        }
        byte
    }

    /// Нормализованный срез.
    pub fn norm_slice(&self, start: usize, end: usize) -> &str {
        &self.norm[start.min(self.norm.len())..end.min(self.norm.len())]
    }
}

/// PERF-16: проверяет, что текст не требует свёртки (чистый ASCII без заглавных).
fn is_ascii_fast_path(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b.is_ascii_punctuation() || b == b' ')
}

/// Посимвольная нормализация (после NFKC и lowercase).
/// Возвращает Cow, чтобы не аллоцировать для обычных символов (PERF-14).
fn normalize_char(c: char) -> std::borrow::Cow<'static, str> {
    match c {
        'ё' => "е".into(),
        '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' => "-".into(),
        '\u{00a0}' | '\u{2009}' | '\t' | '\u{2000}' | '\u{2001}' | '\u{2002}' | '\u{2003}'
        | '\u{2004}' | '\u{2005}' | '\u{2006}' | '\u{2007}' | '\u{2008}' | '\u{200a}'
        | '\u{202f}' | '\u{205f}' | '\u{3000}' => " ".into(),
        '«' | '»' | '„' | '“' | '”' => "\"".into(),
        _ => c.to_string().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_yo() {
        let d = Document::new("Иванов Иван");
        assert_eq!(d.norm, "иванов иван");
    }

    #[test]
    fn normalizes_dashes_and_quotes() {
        let d = Document::new("серия — 45–09 «тест»");
        assert_eq!(d.norm, "серия - 45-09 \"тест\"");
    }

    #[test]
    fn to_original_maps_back() {
        let d = Document::new("Иванов");
        // "иванов" в norm: 12 байт (6 кириллических символов по 2 байта)
        let span = d.to_original(0, d.norm.len());
        assert_eq!(d.original_slice(span), "Иванов");
    }

    #[test]
    fn to_original_handles_length_change() {
        // 'Ё' (2 байта) → 'е' (2 байта), но lowercase 'И'→'и' сохраняет длину.
        // Проверим с латинской 'İ' (2 байта) → 'i̇' (3 байта) — длина меняется.
        let d = Document::new("İ");
        // norm = "i̇" (i + combining dot, 3 байта)
        let span = d.to_original(0, d.norm.len());
        assert_eq!(d.original_slice(span), "İ");
    }

    #[test]
    fn sentinel_maps_to_end() {
        let d = Document::new("abc");
        let span = d.to_original(3, 3);
        assert_eq!(span, Span::new(3, 3));
    }
}