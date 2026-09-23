//! Детекторы банковских карт: CARD_NUMBER, CVV, PIN, CARD_HOLDER.

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector, ValidationResult, Validator};

use super::context::is_boundary;
use super::validators::LuhnValidator;

pub struct CardNumberDetector {
    re: Regex,
    luhn: LuhnValidator,
    types: Vec<PdType>,
}

impl Default for CardNumberDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CardNumberDetector {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"\d(?:[ \-]?\d){12,18}").unwrap(),
            luhn: LuhnValidator,
            types: vec![PdType::new(PdType::CARD_NUMBER)],
        }
    }
}

impl Detector for CardNumberDetector {
    fn id(&self) -> &str {
        "card_number"
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
            if digits.len() < 13 || digits.len() > 19 {
                continue;
            }
            let span = doc.to_original(m.start(), m.end());
            let mut cand = Candidate::new(
                PdType::new(PdType::CARD_NUMBER),
                span,
                0.0,
                DetectorSource::Regex {
                    id: "card_number".into(),
                },
            );
            match self.luhn.validate(&digits) {
                ValidationResult::Valid => {
                    cand.signals |= SignalFlags::CHECKSUM_OK;
                    cand.signals |= SignalFlags::VALIDATED;
                    // префикс IIN
                    let prefix = &digits[..2];
                    let known = matches!(
                        prefix,
                        "22" | "23" | "24" | "25" | "26" | "27" | "34" | "35" | "37" | "40"
                            | "41" | "42" | "43" | "44" | "45" | "46" | "47" | "48" | "49"
                            | "51" | "52" | "53" | "54" | "55" | "60" | "62"
                    );
                    cand.score = if known { 0.95 } else { 0.7 };
                }
                ValidationResult::Invalid => continue,
                ValidationResult::NotApplicable => continue,
            }
            out.push(cand);
        }
    }
}

pub struct CvvDetector {
    re: Regex,
    types: Vec<PdType>,
}

impl Default for CvvDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CvvDetector {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"(cvv2?|cvc2?|cvv/cvc|код безопасности|код на обороте|трехзначный код)\D{0,15}(\d{3,4})").unwrap(),
            types: vec![PdType::new(PdType::CVV)],
        }
    }
}

impl Detector for CvvDetector {
    fn id(&self) -> &str {
        "cvv"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for caps in self.re.captures_iter(&doc.norm) {
            let m = caps.get(0).unwrap();
            // span — только цифры (группа 2)
            let digits_start = m.start() + caps.get(2).map(|c| c.start() - m.start()).unwrap_or(0);
            let digits_end = m.start() + caps.get(2).map(|c| c.end() - m.start()).unwrap_or(0);
            let span = doc.to_original(digits_start, digits_end);
            let mut cand = Candidate::new(
                PdType::new(PdType::CVV),
                span,
                0.9,
                DetectorSource::Regex { id: "cvv".into() },
            );
            cand.signals |= SignalFlags::CONTEXT_POS;
            out.push(cand);
        }
    }
}

pub struct PinDetector {
    re: Regex,
    types: Vec<PdType>,
}

impl Default for PinDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PinDetector {
    pub fn new() -> Self {
        Self {
            re: Regex::new(r"(пин|pin)(-| )?(код)?\D{0,15}(\d{4,6})").unwrap(),
            types: vec![PdType::new(PdType::PIN)],
        }
    }
}

impl Detector for PinDetector {
    fn id(&self) -> &str {
        "pin"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for caps in self.re.captures_iter(&doc.norm) {
            let m = caps.get(0).unwrap();
            let digits_start = m.start() + caps.get(4).map(|c| c.start() - m.start()).unwrap_or(0);
            let digits_end = m.start() + caps.get(4).map(|c| c.end() - m.start()).unwrap_or(0);
            let span = doc.to_original(digits_start, digits_end);
            let mut cand = Candidate::new(
                PdType::new(PdType::PIN),
                span,
                0.9,
                DetectorSource::Regex { id: "pin".into() },
            );
            cand.signals |= SignalFlags::CONTEXT_POS;
            out.push(cand);
        }
    }
}

pub struct CardHolderDetector {
    re: Regex,
    types: Vec<PdType>,
}

impl Default for CardHolderDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CardHolderDetector {
    pub fn new() -> Self {
        Self {
            // Триггеры: «держатель карты», «держатель», «на имя», cardholder и т.п.
            // Текст нормализован в нижний регистр, поэтому латиница ищется как [a-z].
            re: Regex::new(
                r"(держател[ьяем]{1,2}|имя\s+держателя|имя\s+на\s+карте|на\s+имя|cardholder(?:\s+name)?|card\s+holder|name\s+on\s+card)(?:\s+карт[ыеу])?\s*:?\s*([a-zа-яё]{2,}(?:\s+[a-zа-яё]{2,}){0,2})",
            )
            .unwrap(),
            types: vec![PdType::new(PdType::CARD_HOLDER)],
        }
    }
}

impl Detector for CardHolderDetector {
    fn id(&self) -> &str {
        "card_holder"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for caps in self.re.captures_iter(&doc.norm) {
            let m = caps.get(0).unwrap();
            let name_start = m.start() + caps.get(2).map(|c| c.start() - m.start()).unwrap_or(0);
            let name_end = m.start() + caps.get(2).map(|c| c.end() - m.start()).unwrap_or(0);
            let span = doc.to_original(name_start, name_end);
            let mut cand = Candidate::new(
                PdType::new(PdType::CARD_HOLDER),
                span,
                0.9,
                DetectorSource::Regex { id: "card_holder".into() },
            );
            cand.signals |= SignalFlags::CONTEXT_POS;
            out.push(cand);
        }
    }
}