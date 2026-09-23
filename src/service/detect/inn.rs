//! Детектор ИНН (INN / ORG_INN).

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector, ValidationResult, Validator};

use super::context::{has_any_word, has_word, is_boundary, window};
use super::validators::InnValidator;

pub struct InnDetector {
    re: Regex,
    validator: InnValidator,
    types: Vec<PdType>,
}

impl Default for InnDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl InnDetector {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\d{12}|\d{10}").unwrap(),
            validator: InnValidator,
            types: vec![PdType::new(PdType::INN), PdType::new(PdType::ORG_INN)],
        }
    }
}

impl Detector for InnDetector {
    fn id(&self) -> &str {
        "inn"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for m in self.re.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let digits = &doc.norm[m.start()..m.end()];
            let span = doc.to_original(m.start(), m.end());
            let is_org = digits.len() == 10;

            // Негативный контекст для INN: инн организации, ооо, ао, пао, ип (как отдельные слова).
            let window = window(doc, m.start().saturating_sub(60), m.end() + 20);
            let org_context = has_any_word(window, &["ооо", "пао", "ао", "ип"])
                || window.contains("инн организации")
                || window.contains("инн банка");

            let pd_type = if is_org || org_context {
                PdType::new(PdType::ORG_INN)
            } else {
                PdType::new(PdType::INN)
            };

            let mut cand = Candidate::new(
                pd_type,
                span,
                0.0,
                DetectorSource::Checksum { id: "inn".into() },
            );

            let has_inn_context = has_word(window, "инн");
            match self.validator.validate(digits) {
                ValidationResult::Valid => {
                    cand.signals |= SignalFlags::CHECKSUM_OK;
                    cand.signals |= SignalFlags::VALIDATED;
                    cand.score = if has_inn_context { 0.98 } else { 0.85 };
                }
                ValidationResult::Invalid => {
                    if has_inn_context {
                        cand.score = 0.6;
                    } else {
                        continue;
                    }
                }
                ValidationResult::NotApplicable => continue,
            }
            out.push(cand);
        }
    }
}