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
    pub norm: String,
    norm_to_orig: Vec<u32>,
}

impl<'a> Document<'a> {
    pub fn new(original: &'a str) -> Self {
        let mut norm = String::with_capacity(original.len());
        let mut norm_to_orig: Vec<u32> = Vec::with_capacity(original.len() + 1);

        for (orig_byte, ch) in original.char_indices() {
            // 1. NFKC
            let nfkc: String = ch.nfkc().collect();
            for nc in nfkc.chars() {
                // 2. lowercase
                let lower: String = nc.to_lowercase().collect();
                for lc in lower.chars() {
                    let mapped = normalize_char(lc);
                    for mc in mapped.chars() {
                        // Записываем orig_byte для каждого байта norm.
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
            norm,
            norm_to_orig,
        }
    }

    /// Перевод диапазона norm → original. Результат на границах символов.
    pub fn to_original(&self, norm_start: usize, norm_end: usize) -> Span {
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

/// Посимвольная нормализация (после NFKC и lowercase).
fn normalize_char(c: char) -> String {
    match c {
        'ё' => "е".to_string(),
        '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' => "-".to_string(),
        '\u{00a0}' | '\u{2009}' | '\t' | '\u{2000}' | '\u{2001}' | '\u{2002}' | '\u{2003}'
        | '\u{2004}' | '\u{2005}' | '\u{2006}' | '\u{2007}' | '\u{2008}' | '\u{200a}'
        | '\u{202f}' | '\u{205f}' | '\u{3000}' => " ".to_string(),
        '«' | '»' | '„' | '“' | '”' => "\"".to_string(),
        _ => c.to_string(),
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