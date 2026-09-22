//! Детекторы дополнительных документов: DRIVER_LICENSE, BIRTH_PLACE, PASSPORT_ISSUER.

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector};

use super::context::{is_boundary, window};

/// Водительское удостоверение (DRIVER_LICENSE).
pub struct DriverLicenseDetector {
    re: Regex,
    types: Vec<PdType>,
}

impl Default for DriverLicenseDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DriverLicenseDetector {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\d{2}\s?\d{2}\s?\d{6}|\d{2}\s?[авекмнорстух]{2}\s?\d{6}").unwrap(),
            types: vec![PdType::new(PdType::DRIVER_LICENSE)],
        }
    }
}

impl Detector for DriverLicenseDetector {
    fn id(&self) -> &str {
        "driver_license"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for m in self.re.find_iter(&doc.norm) {
            if !is_boundary(doc, m.start(), m.end()) {
                continue;
            }
            // Только с контекстом.
            let w = window(doc, m.start().saturating_sub(60), m.end() + 20);
            let has_context = ["водительск", "в/у", "ву", "права", "удостоверение водителя", "driver"]
                .iter()
                .any(|k| w.contains(k));
            if !has_context {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let mut cand = Candidate::new(
                PdType::new(PdType::DRIVER_LICENSE),
                span,
                0.9,
                DetectorSource::Regex { id: "driver_license".into() },
            );
            cand.signals |= SignalFlags::CONTEXT_POS;
            out.push(cand);
        }
    }
}

/// Место рождения (BIRTH_PLACE).
pub struct BirthPlaceDetector {
    re_trigger: Regex,
    cities: Vec<String>,
    countries: Vec<String>,
    types: Vec<PdType>,
}

impl Default for BirthPlaceDetector {
    fn default() -> Self {
        Self::new(Vec::new(), Vec::new())
    }
}

impl BirthPlaceDetector {
    pub fn new(cities: Vec<String>, countries: Vec<String>) -> Self {
        Self {
            re_trigger: Regex::new(r"место рождения|уроженец|уроженка|родил(ся|ась) в|place of birth").unwrap(),
            cities,
            countries,
            types: vec![PdType::new(PdType::BIRTH_PLACE)],
        }
    }
}

impl Detector for BirthPlaceDetector {
    fn id(&self) -> &str {
        "birth_place"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for m in self.re_trigger.find_iter(&doc.norm) {
            // Захват до 100 символов до ближайшего ; \n , или даты.
            let start = m.end();
            let rest = &doc.norm[start..];
            let mut end = start;
            for (i, ch) in rest.char_indices() {
                if matches!(ch, ';' | '\n' | ',') {
                    end = start + i;
                    break;
                }
                if i > 100 {
                    end = start + i;
                    break;
                }
            }
            if end <= start {
                continue;
            }
            let value = &doc.norm[start..end];
            // Внутри должен быть топоним.
            let has_toponym = ["г.", "город", "пос.", "с.", "дер.", "обл.", "край", "республика"]
                .iter()
                .any(|k| value.contains(k))
                || self.cities.iter().any(|c| value.contains(c.as_str()))
                || self.countries.iter().any(|c| value.contains(c.as_str()));
            if !has_toponym {
                continue;
            }
            let span = doc.to_original(start, end);
            let mut cand = Candidate::new(
                PdType::new(PdType::BIRTH_PLACE),
                span,
                0.9,
                DetectorSource::Regex { id: "birth_place".into() },
            );
            cand.signals |= SignalFlags::CONTEXT_POS;
            out.push(cand);
        }
    }
}

/// Орган, выдавший паспорт (PASSPORT_ISSUER).
pub struct PassportIssuerDetector {
    re_trigger: Regex,
    authorities: Vec<String>,
    types: Vec<PdType>,
}

impl Default for PassportIssuerDetector {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl PassportIssuerDetector {
    pub fn new(authorities: Vec<String>) -> Self {
        Self {
            re_trigger: Regex::new(r"(выдан|кем выдан|выдавший орган)\s*:?\s*").unwrap(),
            authorities,
            types: vec![PdType::new(PdType::PASSPORT_ISSUER)],
        }
    }
}

impl Detector for PassportIssuerDetector {
    fn id(&self) -> &str {
        "passport_issuer"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for m in self.re_trigger.find_iter(&doc.norm) {
            let start = m.end();
            let rest = &doc.norm[start..];
            let mut end = start;
            for (i, ch) in rest.char_indices() {
                if matches!(ch, ';' | '\n' | '.') {
                    end = start + i;
                    break;
                }
                if i > 150 {
                    end = start + i;
                    break;
                }
            }
            if end <= start {
                continue;
            }
            let value = &doc.norm[start..end];
            // Должен начинаться с аббревиатуры органа.
            let has_authority = self.authorities.iter().any(|a| value.starts_with(a.as_str()))
                || ["уфмс", "оуфмс", "гу мвд", "умвд", "омвд", "овд", "мвд", "отделом", "отделением", "мц"]
                    .iter()
                    .any(|a| value.starts_with(a));
            if !has_authority {
                continue;
            }
            let span = doc.to_original(start, end);
            let mut cand = Candidate::new(
                PdType::new(PdType::PASSPORT_ISSUER),
                span,
                0.9,
                DetectorSource::Regex { id: "passport_issuer".into() },
            );
            cand.signals |= SignalFlags::CONTEXT_POS;
            out.push(cand);
        }
    }
}