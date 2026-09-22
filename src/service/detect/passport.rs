//! Детектор паспорта РФ (PASSPORT) и кода подразделения (DIVISION_CODE).

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector, ValidationResult, Validator};

use super::context::{is_boundary, window};
use super::validators::PassportSeriesValidator;

pub struct PassportDetector {
    re: Regex,
    series_validator: PassportSeriesValidator,
    types: Vec<PdType>,
}

impl Default for PassportDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PassportDetector {
    pub fn new() -> Self {
        Self {
            re: Regex::new(
                r"(?:серия\s*)?(?P<s1>\d{2})\s?(?P<s2>\d{2})\s*(?:(?:№|n|no\.?|номер)\s*)?(?P<num>\d{6})",
            )
            .unwrap(),
            series_validator: PassportSeriesValidator,
            types: vec![PdType::new(PdType::PASSPORT)],
        }
    }
}

impl Detector for PassportDetector {
    fn id(&self) -> &str {
        "passport"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for caps in self.re.captures_iter(&doc.norm) {
            let m = caps.get(0).unwrap();
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let s1 = caps.name("s1").map(|c| c.as_str()).unwrap_or("");
            let s2 = caps.name("s2").map(|c| c.as_str()).unwrap_or("");
            let num = caps.name("num").map(|c| c.as_str()).unwrap_or("");
            if s1.is_empty() || s2.is_empty() || num.is_empty() {
                continue;
            }
            let series = format!("{s1}{s2}");
            let span = doc.to_original(m.start(), m.end());
            let mut cand = Candidate::new(
                PdType::new(PdType::PASSPORT),
                span,
                0.0,
                DetectorSource::Regex { id: "passport".into() },
            );

            let window = window(doc, m.start().saturating_sub(60), m.end() + 20);
            let has_context = ["паспорт", "серия", "паспортные данные", "удостоверение личности", "документ"]
                .iter()
                .any(|w| window.contains(w));

            match self.series_validator.validate(&series) {
                ValidationResult::Valid => {
                    cand.signals |= SignalFlags::CHECKSUM_OK;
                    cand.signals |= SignalFlags::VALIDATED;
                    cand.score = if has_context { 0.95 } else { 0.5 };
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

pub struct DivisionCodeDetector {
    re: Regex,
    types: Vec<PdType>,
}

impl Default for DivisionCodeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DivisionCodeDetector {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\d{3}-\d{3}").unwrap(),
            types: vec![PdType::new(PdType::DIVISION_CODE)],
        }
    }
}

impl Detector for DivisionCodeDetector {
    fn id(&self) -> &str {
        "division_code"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for m in self.re.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let digits: Vec<u32> = doc.norm[m.start()..m.end()]
                .chars()
                .filter(|c| c.is_ascii_digit())
                .filter_map(|c| c.to_digit(10))
                .collect();
            if digits.len() != 6 {
                continue;
            }
            let region = digits[0] * 10 + digits[1];
            let kind = digits[2];
            if !(1..=99).contains(&region) || kind > 3 {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let window = window(doc, m.start().saturating_sub(60), m.end() + 20);
            let has_context = ["код подразделения", "к/п", "код подр"]
                .iter()
                .any(|w| window.contains(w));
            let score = if has_context { 0.95 } else { 0.3 };
            let mut cand = Candidate::new(
                PdType::new(PdType::DIVISION_CODE),
                span,
                score,
                DetectorSource::Regex { id: "division_code".into() },
            );
            if has_context {
                cand.signals |= SignalFlags::CONTEXT_POS;
            }
            out.push(cand);
        }
    }
}