//! Детектор СНИЛС (SNILS).

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector, ValidationResult, Validator};

use super::context::{has_word, is_boundary, window};
use super::validators::SnilsValidator;

pub struct SnilsDetector {
    re: Regex,
    validator: SnilsValidator,
    types: Vec<PdType>,
}

impl Default for SnilsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SnilsDetector {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\d{3}-\d{3}-\d{3}[ -]\d{2}|\d{11}").unwrap(),
            validator: SnilsValidator,
            types: vec![PdType::new(PdType::SNILS)],
        }
    }
}

impl Detector for SnilsDetector {
    fn id(&self) -> &str {
        "snils"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for m in self.re.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let digits: String = doc.norm[m.start()..m.end()]
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            if digits.len() != 11 {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let window = window(doc, m.start().saturating_sub(60), m.end() + 20);
            let has_context = has_word(window, "снилс");
            let mut cand = Candidate::new(
                PdType::new(PdType::SNILS),
                span,
                0.0,
                DetectorSource::Checksum { id: "snils".into() },
            );
            match self.validator.validate(&digits) {
                ValidationResult::Valid => {
                    cand.signals |= SignalFlags::CHECKSUM_OK;
                    cand.signals |= SignalFlags::VALIDATED;
                    cand.score = if has_context { 0.95 } else { 0.85 };
                }
                _ => {
                    if has_context {
                        cand.score = 0.6;
                    } else {
                        continue;
                    }
                }
            }
            out.push(cand);
        }
    }
}