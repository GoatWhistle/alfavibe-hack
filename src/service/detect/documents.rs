//! Детекторы дополнительных документов: DRIVER_LICENSE, BIRTH_PLACE, PASSPORT_ISSUER.

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector};

use super::context::{has_any_prefix, is_boundary, window};

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
            // «в/у» разбивается на «в» и «у», поэтому ищем его подстрокой,
            // а основы слов — префиксным сравнением.
            let has_context = has_any_prefix(
                w,
                &["водительск", "удостоверен", "прав", "driver", "license"],
            ) || w.contains("в/у")
                || w.contains("в\\у");
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

/// Захватывает значение после триггера: до разделителя, конца строки или лимита.
///
/// Ключевой момент — значение, упирающееся в конец текста, тоже считается
/// найденным: раньше `end` оставался равен `start`, и «место рождения г. Казань»
/// в конце строки не детектировалось вовсе.
fn capture_value(norm: &str, start: usize, max_bytes: usize, stop_at_dot: bool) -> (usize, &str) {
    let rest = &norm[start..];
    // Ведущие пробелы в значение не входят, иначе маска съедает пробел перед собой.
    let lead: usize = rest
        .char_indices()
        .take_while(|(_, c)| c.is_whitespace())
        .map(|(i, c)| i + c.len_utf8())
        .last()
        .unwrap_or(0);
    let rest = &rest[lead..];
    let mut end = rest.len();
    for (i, ch) in rest.char_indices() {
        if i >= max_bytes {
            end = i;
            break;
        }
        if matches!(ch, ';' | '\n' | ',') {
            end = i;
            break;
        }
        // Точка обрывает значение, только если это не сокращение вида «г.», «ул.»,
        // иначе «ОУФМС России по г. Москве» обрезается на первом же «г.».
        if stop_at_dot && ch == '.' && !is_abbreviation_dot(rest, i) {
            end = i;
            break;
        }
    }
    (lead, rest[..end].trim_end())
}

/// Точка после короткого слова (1–3 буквы) — сокращение, а не конец предложения.
fn is_abbreviation_dot(text: &str, dot_pos: usize) -> bool {
    let before = &text[..dot_pos];
    let word_len = before
        .chars()
        .rev()
        .take_while(|c| c.is_alphabetic())
        .count();
    (1..=3).contains(&word_len)
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
            let (lead, value) = capture_value(&doc.norm, m.end(), 100, false);
            if value.is_empty() {
                continue;
            }
            let start = m.end() + lead;
            let end = start + value.len();
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
            // «выдан 15.03.2015 ОУФМС …»: дату между триггером и органом пропускаем
            // до захвата значения — точка внутри даты иначе обрывает захват.
            // Саму дату заберёт детектор дат как PASSPORT_ISSUE_DATE.
            let after_trigger = m.end() + leading_date_len(&doc.norm[m.end()..]);
            let (lead, value) = capture_value(&doc.norm, after_trigger, 150, true);
            if value.is_empty() {
                continue;
            }
            let start = after_trigger + lead;
            // Должен начинаться с аббревиатуры органа.
            let has_authority = self.authorities.iter().any(|a| value.starts_with(a.as_str()))
                || ["уфмс", "оуфмс", "гу мвд", "умвд", "омвд", "овд", "мвд", "отделом", "отделением", "мц"]
                    .iter()
                    .any(|a| value.starts_with(a));
            if !has_authority {
                continue;
            }
            let end = start + value.len();
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
/// Длина ведущей даты («15.03.2015 ») в байтах, иначе 0.
fn leading_date_len(value: &str) -> usize {
    let digits_dots: usize = value
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == '/')
        .map(|(i, c)| i + c.len_utf8())
        .last()
        .unwrap_or(0);
    if digits_dots == 0 || crate::service::detect::validators::parse_date(&value[..digits_dots]).is_none() {
        return 0;
    }
    let ws: usize = value[digits_dots..]
        .char_indices()
        .take_while(|(_, c)| c.is_whitespace())
        .map(|(i, c)| i + c.len_utf8())
        .last()
        .unwrap_or(0);
    digits_dots + ws
}
