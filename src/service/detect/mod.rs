//! Детерминированные детекторы.

pub mod context;
pub mod numwords;
pub mod validators;

pub mod address;
pub mod card;
pub mod citizenship;
pub mod dates;
pub mod documents;
pub mod email;
pub mod fio;
pub mod inn;
pub mod passport;
pub mod phone;
pub mod snils;

use std::collections::HashMap;
use std::sync::Arc;

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector, ValidationResult};

use crate::service::detect::context::{is_boundary, window};

/// Реестр детекторов.
#[derive(Default)]
pub struct DetectorRegistry {
    pub detectors: Vec<Arc<dyn Detector>>,
    pub by_id: HashMap<String, Arc<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn register(&mut self, d: Arc<dyn Detector>) {
        self.by_id.insert(d.id().to_string(), d.clone());
        self.detectors.push(d);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Detector>> {
        self.by_id.get(id).cloned()
    }
}

/// Детектор, объявленный в конфиге (раздел 11.5).
pub struct ConfigRegexDetector {
    pd_type: PdType,
    re: Regex,
    value_group: String,
    validator: String,
    base_score: f32,
    context_pos: Vec<String>,
    context_neg: Vec<String>,
    types: Vec<PdType>,
}

impl ConfigRegexDetector {
    pub fn new(
        pd_type: PdType,
        cfg: &crate::config::model::DetectorConfig,
        re: Regex,
    ) -> Self {
        Self {
            types: vec![pd_type.clone()],
            pd_type,
            re,
            value_group: cfg.value_group.clone(),
            validator: cfg.validator.clone(),
            base_score: cfg.base_score,
            context_pos: cfg.context_pos.clone(),
            context_neg: cfg.context_neg.clone(),
        }
    }
}

impl Detector for ConfigRegexDetector {
    fn id(&self) -> &str {
        "config_regex"
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
            let value = caps
                .name(&self.value_group)
                .map(|c| c.as_str())
                .unwrap_or(&doc.norm[m.start()..m.end()]);
            let value_start = caps
                .name(&self.value_group)
                .map(|c| c.start())
                .unwrap_or(m.start());
            let value_end = caps
                .name(&self.value_group)
                .map(|c| c.end())
                .unwrap_or(m.end());

            let span = doc.to_original(value_start, value_end);
            let mut cand = Candidate::new(
                self.pd_type.clone(),
                span,
                self.base_score,
                DetectorSource::Custom { id: "config_regex".into() },
            );

            // Валидатор.
            match self.validator.as_str() {
                "luhn" => {
                    if let Some(v) = validators::get_validator("luhn") {
                        if v.validate(value) == ValidationResult::Valid {
                            cand.signals |= SignalFlags::CHECKSUM_OK;
                        }
                    }
                }
                "inn" => {
                    if let Some(v) = validators::get_validator("inn") {
                        if v.validate(value) == ValidationResult::Valid {
                            cand.signals |= SignalFlags::CHECKSUM_OK;
                        }
                    }
                }
                "snils" => {
                    if let Some(v) = validators::get_validator("snils") {
                        if v.validate(value) == ValidationResult::Valid {
                            cand.signals |= SignalFlags::CHECKSUM_OK;
                        }
                    }
                }
                "date" => {
                    if let Some(v) = validators::get_validator("date") {
                        if v.validate(value) == ValidationResult::Valid {
                            cand.signals |= SignalFlags::CHECKSUM_OK;
                        }
                    }
                }
                _ => {}
            }

            // Контекст.
            let window = window(doc, m.start().saturating_sub(60), m.end() + 20);
            if self.context_pos.iter().any(|w| window.contains(w.as_str())) {
                cand.score = (cand.score + 0.35).min(1.0_f32);
                cand.signals |= SignalFlags::CONTEXT_POS;
            }
            if self.context_neg.iter().any(|w| window.contains(w.as_str())) {
                cand.score = (cand.score - 0.5).max(0.0_f32);
                cand.signals |= SignalFlags::CONTEXT_NEG;
            }
            out.push(cand);
        }
    }
}