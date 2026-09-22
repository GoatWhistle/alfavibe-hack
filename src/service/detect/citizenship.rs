//! Детектор гражданства (CITIZENSHIP).

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector};

pub struct CitizenshipDetector {
    re_value: Regex,
    re_phrase: Regex,
    countries: Vec<String>,
    types: Vec<PdType>,
}

impl CitizenshipDetector {
    pub fn new(countries: Vec<String>) -> Self {
        Self {
            re_value: Regex::new(r"гражданство\s*:?\s*([а-яa-z\s]+)").unwrap(),
            re_phrase: Regex::new(r"граждан(ин|ка|е)\s+([а-яa-z\s]+)").unwrap(),
            countries,
            types: vec![PdType::new(PdType::CITIZENSHIP)],
        }
    }
}

impl Detector for CitizenshipDetector {
    fn id(&self) -> &str {
        "citizenship"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        // гражданство: РФ
        for caps in self.re_value.captures_iter(&doc.norm) {
            let m = caps.get(0).unwrap();
            let value = caps.get(1).map(|c| c.as_str()).unwrap_or("");
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let is_country = self.countries.iter().any(|c| value.contains(c.as_str()))
                || matches!(value, "рф" | "россия" | "российской федерации" | "российская федерация");
            if !is_country {
                continue;
            }
            let value_start = m.start() + caps.get(1).unwrap().start() - m.start();
            let value_end = m.start() + caps.get(1).unwrap().end() - m.start();
            let span = doc.to_original(value_start, value_end);
            let mut cand = Candidate::new(
                PdType::new(PdType::CITIZENSHIP),
                span,
                0.9,
                DetectorSource::Regex { id: "citizenship".into() },
            );
            cand.signals |= SignalFlags::CONTEXT_POS;
            out.push(cand);
        }
        // гражданин Российской Федерации
        for caps in self.re_phrase.captures_iter(&doc.norm) {
            let m = caps.get(0).unwrap();
            let value = caps.get(2).map(|c| c.as_str()).unwrap_or("");
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let is_country = self.countries.iter().any(|c| value.contains(c.as_str()))
                || value.contains("российской");
            if !is_country {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let mut cand = Candidate::new(
                PdType::new(PdType::CITIZENSHIP),
                span,
                0.9,
                DetectorSource::Regex { id: "citizenship".into() },
            );
            cand.signals |= SignalFlags::CONTEXT_POS;
            out.push(cand);
        }
    }
}