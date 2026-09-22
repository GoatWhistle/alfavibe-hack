//! Стратегии маскирования.

use crate::domain::entity::{Entity, MaskState};
use crate::domain::traits::{MaskKind, MaskOutput, Masker};

/// Плейсхолдер-маскер: `[ФИО_1]`.
pub struct PlaceholderMasker {
    pub format: String,
    pub labels: std::collections::HashMap<crate::domain::pd_type::PdType, String>,
}

impl Masker for PlaceholderMasker {
    fn kind(&self) -> MaskKind {
        MaskKind::Placeholder
    }
    fn mask(&self, entity: &Entity, _original: &str, state: &mut MaskState) -> MaskOutput {
        let label = self
            .labels
            .get(&entity.pd_type)
            .map(|s| s.as_str())
            .unwrap_or(entity.pd_type.as_str());
        let canonical = entity.canonical.expose().clone();
        let n = state.next_number(&entity.pd_type, &canonical);
        let replacement = self
            .format
            .replace("{label}", label)
            .replace("{n}", &n.to_string());
        let key = format!("{label}_{n}");
        MaskOutput {
            replacement,
            key: Some(key),
        }
    }
    fn reversible(&self) -> bool {
        true
    }
}

/// Redact-маскер: `*****` той же длины.
pub struct RedactMasker;

impl Masker for RedactMasker {
    fn kind(&self) -> MaskKind {
        MaskKind::Redact
    }
    fn mask(&self, _entity: &Entity, original: &str, _state: &mut MaskState) -> MaskOutput {
        let len = original.chars().count();
        MaskOutput {
            replacement: "*".repeat(len),
            key: None,
        }
    }
    fn reversible(&self) -> bool {
        false
    }
}

/// Partial-маскер: сохраняет последние N символов.
pub struct PartialMasker {
    pub keep_last: usize,
}

impl Masker for PartialMasker {
    fn kind(&self) -> MaskKind {
        MaskKind::Partial
    }
    fn mask(&self, entity: &Entity, original: &str, state: &mut MaskState) -> MaskOutput {
        let chars: Vec<char> = original.chars().collect();
        let keep = self.keep_last.min(chars.len());
        let mut out: String = String::new();
        for (i, c) in chars.iter().enumerate() {
            if i >= chars.len() - keep {
                out.push(*c);
            } else if c.is_ascii_digit() {
                out.push('*');
            } else {
                out.push(*c);
            }
        }
        let canonical = entity.canonical.expose().clone();
        let n = state.next_number(&entity.pd_type, &canonical);
        let key = format!("{}_p{}", entity.pd_type.as_str(), n);
        MaskOutput {
            replacement: out,
            key: Some(key),
        }
    }
    fn reversible(&self) -> bool {
        true
    }
}

/// Token-маскер: `tok_FIO_3fa9c2`.
pub struct TokenMasker {
    pub secret: Vec<u8>,
}

impl Masker for TokenMasker {
    fn kind(&self) -> MaskKind {
        MaskKind::Token
    }
    fn mask(&self, entity: &Entity, _original: &str, _state: &mut MaskState) -> MaskOutput {
        let canonical = entity.canonical.expose();
        let token = crate::infra::crypto::hmac_token(&self.secret, &format!("{}|{}", entity.pd_type.as_str(), canonical));
        let replacement = format!("tok_{}_{}", entity.pd_type.as_str(), token);
        MaskOutput {
            replacement: replacement.clone(),
            key: Some(replacement),
        }
    }
    fn reversible(&self) -> bool {
        true
    }
}

/// Hash-маскер: `sha256:...`.
pub struct HashMasker;

impl Masker for HashMasker {
    fn kind(&self) -> MaskKind {
        MaskKind::Hash
    }
    fn mask(&self, entity: &Entity, _original: &str, _state: &mut MaskState) -> MaskOutput {
        let canonical = entity.canonical.expose();
        let hash = crate::infra::crypto::sha256_hex(canonical.as_bytes());
        MaskOutput {
            replacement: format!("sha256:{hash}"),
            key: None,
        }
    }
    fn reversible(&self) -> bool {
        false
    }
}

/// Synthetic-маскер: генерирует реалистичные значения, детерминированные от canonical.
pub struct SyntheticMasker {
    pub secret: Vec<u8>,
    pub first_names: Vec<String>,
    pub surnames: Vec<String>,
}

impl SyntheticMasker {
    fn seed(&self, entity: &Entity) -> u64 {
        let canonical = entity.canonical.expose();
        let token = crate::infra::crypto::hmac_token(&self.secret, &format!("synth|{}|{}", entity.pd_type.as_str(), canonical));
        u64::from_str_radix(&token, 16).unwrap_or(0)
    }

    fn pick(&self, seed: u64, list: &[String]) -> String {
        if list.is_empty() {
            return "Синтетик".to_string();
        }
        list[(seed as usize) % list.len()].clone()
    }
}

impl Masker for SyntheticMasker {
    fn kind(&self) -> MaskKind {
        MaskKind::Synthetic
    }
    fn mask(&self, entity: &Entity, _original: &str, state: &mut MaskState) -> MaskOutput {
        let seed = self.seed(entity);
        let replacement = match entity.pd_type.as_str() {
            crate::domain::pd_type::PdType::FIO => {
                let name = self.pick(seed, &self.first_names);
                let surname = self.pick(seed >> 8, &self.surnames);
                format!("{surname} {name}")
            }
            crate::domain::pd_type::PdType::CARD_NUMBER => {
                // Генерируем карту с валидной Луной.
                let mut digits = String::new();
                let mut s = seed;
                for _ in 0..15 {
                    digits.push((b'0' + (s % 10) as u8) as char);
                    s /= 10;
                }
                // Добавляем контрольную цифру Луны.
                let mut sum = 0u32;
                let mut double = true;
                for c in digits.chars().rev() {
                    let mut d = c.to_digit(10).unwrap();
                    if double {
                        d *= 2;
                        if d > 9 {
                            d -= 9;
                        }
                    }
                    sum += d;
                    double = !double;
                }
                let check = (10 - (sum % 10)) % 10;
                let full = format!("{digits}{check}");
                // Форматируем по 4.
                full.chars()
                    .collect::<Vec<_>>()
                    .chunks(4)
                    .map(|c| c.iter().collect::<String>())
                    .collect::<Vec<_>>()
                    .join(" ")
            }
            crate::domain::pd_type::PdType::PHONE => {
                let mut s = seed;
                let mut digits = String::from("79");
                for _ in 0..10 {
                    digits.push((b'0' + (s % 10) as u8) as char);
                    s /= 10;
                }
                format!("+7 ({}) {}-{}-{}", &digits[2..5], &digits[5..8], &digits[8..10], &digits[10..12])
            }
            crate::domain::pd_type::PdType::INN => {
                // 12 цифр с верной КС.
                let mut digits = String::new();
                let mut s = seed;
                for _ in 0..10 {
                    digits.push((b'0' + (s % 10) as u8) as char);
                    s /= 10;
                }
                let k1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
                let sum1: u32 = k1.iter().zip(digits.chars()).map(|(k, c)| k * c.to_digit(10).unwrap()).sum();
                let c1 = (sum1 % 11) % 10;
                let k2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
                let sum2: u32 = k2.iter().zip(digits.chars().chain(std::iter::once(char::from_digit(c1, 10).unwrap()))).map(|(k, c)| k * c.to_digit(10).unwrap()).sum();
                let c2 = (sum2 % 11) % 10;
                format!("{digits}{c1}{c2}")
            }
            _ => {
                let canonical = entity.canonical.expose();
                format!("synth_{}", crate::infra::crypto::hmac_token(&self.secret, &format!("synth|{}", canonical)))
            }
        };
        let canonical = entity.canonical.expose().clone();
        let n = state.next_number(&entity.pd_type, &canonical);
        let key = format!("{}_s{}", entity.pd_type.as_str(), n);
        MaskOutput {
            replacement,
            key: Some(key),
        }
    }
    fn reversible(&self) -> bool {
        true
    }
}