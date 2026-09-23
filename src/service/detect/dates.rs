//! Детектор дат: BIRTH_DATE, PASSPORT_ISSUE_DATE, DATE.

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector};

use super::context::{has_any_prefix, is_boundary, window};
use super::numwords::parse_numeral_words;
use super::validators::parse_date;

const MONTHS: &[(&str, u32)] = &[
    ("января", 1), ("январь", 1), ("янв", 1), ("january", 1), ("jan", 1),
    ("февраля", 2), ("февраль", 2), ("фев", 2), ("february", 2), ("feb", 2),
    ("марта", 3), ("март", 3), ("мар", 3), ("march", 3), ("mar", 3),
    ("апреля", 4), ("апрель", 4), ("апр", 4), ("april", 4), ("apr", 4),
    ("мая", 5), ("май", 5), ("may", 5),
    ("июня", 6), ("июнь", 6), ("июн", 6), ("june", 6), ("jun", 6),
    ("июля", 7), ("июль", 7), ("июл", 7), ("july", 7), ("jul", 7),
    ("августа", 8), ("август", 8), ("авг", 8), ("august", 8), ("aug", 8),
    ("сентября", 9), ("сентябрь", 9), ("сен", 9), ("сент", 9), ("september", 9), ("sep", 9),
    ("октября", 10), ("октябрь", 10), ("окт", 10), ("october", 10), ("oct", 10),
    ("ноября", 11), ("ноябрь", 11), ("ноя", 11), ("november", 11), ("nov", 11),
    ("декабря", 12), ("декабрь", 12), ("дек", 12), ("december", 12), ("dec", 12),
];

pub struct DateDetector {
    re_numeric: Regex,
    re_text: Regex,
    types: Vec<PdType>,
}

impl Default for DateDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DateDetector {
    pub fn new() -> Self {
        Self {
            re_numeric: Regex::new(r"\d{1,4}[./-]\d{1,2}[./-]\d{1,4}").unwrap(),
            re_text: Regex::new(r"(\d{1,2})\s+([а-яa-z]+)\s+(\d{4})(\s*г(ода?)?\.?)?").unwrap(),
            // classify_date относит находку к BIRTH_DATE/PASSPORT_ISSUE_DATE/DATE,
            // поэтому объявляем все три: конвейер отбирает детекторы по types().
            types: vec![
                PdType::new(PdType::DATE),
                PdType::new(PdType::BIRTH_DATE),
                PdType::new(PdType::PASSPORT_ISSUE_DATE),
            ],
        }
    }
}

impl Detector for DateDetector {
    fn id(&self) -> &str {
        "date"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        // Числовые
        for m in self.re_numeric.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let raw = &doc.norm[m.start()..m.end()];
            if parse_date(raw).is_none() {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let cand = classify_date(doc, span, m.start(), m.end(), 0.95);
            out.push(cand);
        }
        // Текстовые
        for caps in self.re_text.captures_iter(&doc.norm) {
            let m = caps.get(0).unwrap();
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let day: u32 = caps.get(1).unwrap().as_str().parse().unwrap();
            let month_word = caps.get(2).unwrap().as_str();
            let year: u32 = caps.get(3).unwrap().as_str().parse().unwrap();
            let month_ok = MONTHS.iter().any(|(w, _)| *w == month_word);
            if !month_ok {
                continue;
            }
            if !(1..=31).contains(&day) || !(1900..=2100).contains(&year) {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let cand = classify_date(doc, span, m.start(), m.end(), 0.95);
            out.push(cand);
        }
    }
}

fn classify_date(
    doc: &Document<'_>,
    span: crate::domain::document::Span,
    norm_start: usize,
    norm_end: usize,
    base_score: f32,
) -> Candidate {
    let window = window(doc, norm_start.saturating_sub(60), norm_end + 20);
    // Основы, а не целые слова: в тексте стоят «родился», «рождения», «выданного».
    let birth = has_any_prefix(window, &["рожден", "родил", "рождён", "dob", "birth"]);
    let issue = has_any_prefix(window, &["выдач", "выдан", "issue"]);

    let pd_type = if birth {
        PdType::new(PdType::BIRTH_DATE)
    } else if issue {
        PdType::new(PdType::PASSPORT_ISSUE_DATE)
    } else {
        PdType::new(PdType::DATE)
    };

    let mut cand = Candidate::new(
        pd_type,
        span,
        base_score,
        DetectorSource::Regex { id: "date".into() },
    );
    if birth || issue {
        cand.signals |= SignalFlags::CONTEXT_POS;
    }
    cand
}

/// Детектор дат прописью (числа словами).
pub struct NumeralDateDetector {
    re: Regex,
    types: Vec<PdType>,
}

impl Default for NumeralDateDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NumeralDateDetector {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"[а-яё]+(?:\s+[а-яё]+){0,6}\s+(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)(?:\s+[а-яё]+){0,6}").unwrap(),
            types: vec![
                PdType::new(PdType::DATE),
                PdType::new(PdType::BIRTH_DATE),
                PdType::new(PdType::PASSPORT_ISSUE_DATE),
            ],
        }
    }
}

impl Detector for NumeralDateDetector {
    fn id(&self) -> &str {
        "numeral_date"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for m in self.re.find_iter(&doc.norm) {
            let text = &doc.norm[m.start()..m.end()];
            let words: Vec<&str> = text.split_whitespace().collect();
            // ищем месяц
            let month_idx = words
                .iter()
                .position(|w| MONTHS.iter().any(|(mw, _)| mw == w));
            let Some(mi) = month_idx else { continue };
            // день — слова до месяца
            let day_words = &words[..mi];
            let day = parse_numeral_words(day_words);
            if day.is_none() {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let cand = classify_date(doc, span, m.start(), m.end(), 0.9);
            out.push(cand);
        }
    }
}