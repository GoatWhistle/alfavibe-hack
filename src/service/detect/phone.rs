//! Детектор телефона (PHONE).

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector};

use super::context::{has_any_word, is_boundary, window};

pub struct PhoneDetector {
    re_rf: Regex,
    re_intl: Regex,
    types: Vec<PdType>,
}

impl Default for PhoneDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PhoneDetector {
    pub fn new() -> Self {
        Self {
            re_rf: Regex::new(r"(?:\+7|8|7)?[ \-(]{0,2}\d{3}[ \-)]{0,2}\d{3}[ \-]?\d{2}[ \-]?\d{2}").unwrap(),
            re_intl: Regex::new(r"\+\d{1,3}[ \-(]{0,2}\d{1,4}[ \-)]{0,2}\d{2,4}[ \-]?\d{2,4}[ \-]?\d{0,4}").unwrap(),
            types: vec![PdType::new(PdType::PHONE)],
        }
    }
}

impl Detector for PhoneDetector {
    fn id(&self) -> &str {
        "phone"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        // РФ-номера
        for m in self.re_rf.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let digits: String = doc.norm[m.start()..m.end()]
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            let (valid, score) = validate_rf(&digits);
            if !valid {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let window = window(doc, m.start().saturating_sub(60), m.end() + 20);
            let has_context = has_any_word(
                window,
                &["тел", "телефон", "моб", "звоните", "whatsapp", "telegram", "phone"],
            );
            let mut cand = Candidate::new(
                PdType::new(PdType::PHONE),
                span,
                score,
                DetectorSource::Regex { id: "phone".into() },
            );
            if has_context {
                cand.score = (cand.score + 0.35).min(1.0_f32);
                cand.signals |= SignalFlags::CONTEXT_POS;
            }
            out.push(cand);
        }
        // Международные
        for m in self.re_intl.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let digits: String = doc.norm[m.start()..m.end()]
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            if !(8..=15).contains(&digits.len()) {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let cand = Candidate::new(
                PdType::new(PdType::PHONE),
                span,
                0.9,
                DetectorSource::Regex { id: "phone".into() },
            );
            out.push(cand);
        }
    }
}

fn validate_rf(digits: &str) -> (bool, f32) {
    let len = digits.len();
    if len == 10 {
        let first = digits.chars().next().unwrap();
        if matches!(first, '3' | '4' | '8' | '9') {
            let score = if first == '9' { 0.6 } else { 0.8 };
            return (true, score);
        }
        return (false, 0.0);
    }
    if len == 11 {
        let first = digits.chars().next().unwrap();
        if first == '7' || first == '8' {
            let second = digits.chars().nth(1).unwrap();
            if matches!(second, '3' | '4' | '8' | '9') {
                return (true, 0.9);
            }
        }
        return (false, 0.0);
    }
    (false, 0.0)
}