//! Детектор email (EMAIL).

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector};

use super::context::is_boundary;

pub struct EmailDetector {
    re: Regex,
    types: Vec<PdType>,
}

impl Default for EmailDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailDetector {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}").unwrap(),
            types: vec![PdType::new(PdType::EMAIL)],
        }
    }
}

impl Detector for EmailDetector {
    fn id(&self) -> &str {
        "email"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for m in self.re.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let cand = Candidate::new(
                PdType::new(PdType::EMAIL),
                span,
                0.95,
                DetectorSource::Regex { id: "email".into() },
            );
            out.push(cand);
        }
    }
}