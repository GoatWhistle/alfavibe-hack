//! DET-03: структурный детектор — имя поля как сильный контекстный сигнал.
//! Распознаёт фрагменты вида `"passport": "4509 123456"` или `ключ: значение`.

use regex::Regex;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, DetectorSource, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{DetectCtx, Detector};

/// Соответствие имени поля → тип ПД.
const FIELD_TYPES: &[(&str, &str)] = &[
    ("passport", PdType::PASSPORT),
    ("паспорт", PdType::PASSPORT),
    ("passport_series", PdType::PASSPORT),
    ("birth_date", PdType::BIRTH_DATE),
    ("дата_рождения", PdType::BIRTH_DATE),
    ("дата рождения", PdType::BIRTH_DATE),
    ("birth_place", PdType::BIRTH_PLACE),
    ("место_рождения", PdType::BIRTH_PLACE),
    ("место рождения", PdType::BIRTH_PLACE),
    ("phone", PdType::PHONE),
    ("телефон", PdType::PHONE),
    ("phone_number", PdType::PHONE),
    ("email", PdType::EMAIL),
    ("inn", PdType::INN),
    ("инн", PdType::INN),
    ("snils", PdType::SNILS),
    ("снилс", PdType::SNILS),
    ("card_number", PdType::CARD_NUMBER),
    ("card", PdType::CARD_NUMBER),
    ("номер_карты", PdType::CARD_NUMBER),
    ("cvv", PdType::CVV),
    ("pin", PdType::PIN),
    ("card_holder", PdType::CARD_HOLDER),
    ("держатель", PdType::CARD_HOLDER),
    ("citizenship", PdType::CITIZENSHIP),
    ("гражданство", PdType::CITIZENSHIP),
    ("address", PdType::ADDRESS),
    ("адрес", PdType::ADDRESS),
    ("driver_license", PdType::DRIVER_LICENSE),
    ("division_code", PdType::DIVISION_CODE),
    ("passport_issuer", PdType::PASSPORT_ISSUER),
    ("выдан", PdType::PASSPORT_ISSUER),
    ("fio", PdType::FIO),
    ("фио", PdType::FIO),
    ("full_name", PdType::FIO),
    ("name", PdType::FIO),
];

/// Детектор структурированных полей.
pub struct StructuredFieldDetector {
    re: Regex,
    types: Vec<PdType>,
}

impl Default for StructuredFieldDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StructuredFieldDetector {
    pub fn new() -> Self {
        // `"ключ": "значение"` или `ключ: значение`
        Self {
            re: Regex::new(r#"(?i)"?([a-zа-яё_\- ]+)"?\s*[:=]\s*"?([^",\n}]+)"?"#).unwrap(),
            types: vec![
                PdType::new(PdType::PASSPORT),
                PdType::new(PdType::BIRTH_DATE),
                PdType::new(PdType::BIRTH_PLACE),
                PdType::new(PdType::PHONE),
                PdType::new(PdType::EMAIL),
                PdType::new(PdType::INN),
                PdType::new(PdType::SNILS),
                PdType::new(PdType::CARD_NUMBER),
                PdType::new(PdType::CVV),
                PdType::new(PdType::PIN),
                PdType::new(PdType::CARD_HOLDER),
                PdType::new(PdType::CITIZENSHIP),
                PdType::new(PdType::ADDRESS),
                PdType::new(PdType::DRIVER_LICENSE),
                PdType::new(PdType::DIVISION_CODE),
                PdType::new(PdType::PASSPORT_ISSUER),
                PdType::new(PdType::FIO),
            ],
        }
    }
}

impl Detector for StructuredFieldDetector {
    fn id(&self) -> &str {
        "structured_field"
    }
    fn types(&self) -> &[PdType] {
        &self.types
    }
    fn detect(&self, doc: &Document<'_>, _ctx: &DetectCtx, out: &mut Vec<Candidate>) {
        for caps in self.re.captures_iter(&doc.norm) {
            let key = caps.get(1).map(|c| c.as_str().trim()).unwrap_or("");
            let value = caps.get(2).map(|c| c.as_str().trim()).unwrap_or("");
            if key.is_empty() || value.is_empty() {
                continue;
            }
            // Ищем тип по имени поля.
            let Some((_, pd_type_str)) = FIELD_TYPES.iter().find(|(k, _)| *k == key) else {
                continue;
            };
            let pd_type = PdType::new(*pd_type_str);
            // Значение должно быть непустым и не слишком длинным.
            if value.len() > 200 {
                continue;
            }
            let value_start = caps.get(2).unwrap().start();
            let value_end = caps.get(2).unwrap().end();
            let span = doc.to_original(value_start, value_end);
            let mut cand = Candidate::new(
                pd_type,
                span,
                0.85,
                DetectorSource::Regex { id: "structured_field".into() },
            );
            cand.signals |= SignalFlags::CONTEXT_POS;
            out.push(cand);
        }
    }
}