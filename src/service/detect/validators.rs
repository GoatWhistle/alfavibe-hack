//! Валидаторы форматов и контрольных сумм.

use std::sync::Arc;

use crate::domain::traits::{ValidationResult, Validator};

/// Алгоритм Луна.
pub fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for c in digits.chars().rev() {
        if !c.is_ascii_digit() {
            return false;
        }
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
    sum % 10 == 0
}

/// Валидатор Луна.
pub struct LuhnValidator;

impl Validator for LuhnValidator {
    fn id(&self) -> &str {
        "luhn"
    }
    fn validate(&self, raw: &str) -> ValidationResult {
        let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() < 13 || digits.len() > 19 {
            return ValidationResult::NotApplicable;
        }
        if luhn_valid(&digits) {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid
        }
    }
}

/// Валидатор ИНН (10 и 12 цифр).
pub struct InnValidator;

impl Validator for InnValidator {
    fn id(&self) -> &str {
        "inn"
    }
    fn validate(&self, raw: &str) -> ValidationResult {
        let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
        match digits.len() {
            10 => {
                if inn10_valid(&digits) {
                    ValidationResult::Valid
                } else {
                    ValidationResult::Invalid
                }
            }
            12 => {
                if inn12_valid(&digits) {
                    ValidationResult::Valid
                } else {
                    ValidationResult::Invalid
                }
            }
            _ => ValidationResult::NotApplicable,
        }
    }
}

pub fn inn10_valid(d: &str) -> bool {
    if d.len() != 10 {
        return false;
    }
    let k = [2, 4, 10, 3, 5, 9, 4, 6, 8];
    let sum: u32 = k
        .iter()
        .zip(d.chars())
        .map(|(k, c)| k * c.to_digit(10).unwrap())
        .sum();
    let c = (sum % 11) % 10;
    c == d.chars().nth(9).unwrap().to_digit(10).unwrap()
}

pub fn inn12_valid(d: &str) -> bool {
    if d.len() != 12 {
        return false;
    }
    let k1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
    let sum1: u32 = k1
        .iter()
        .zip(d.chars())
        .map(|(k, c)| k * c.to_digit(10).unwrap())
        .sum();
    let c1 = (sum1 % 11) % 10;
    if c1 != d.chars().nth(10).unwrap().to_digit(10).unwrap() {
        return false;
    }
    let k2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
    let sum2: u32 = k2
        .iter()
        .zip(d.chars())
        .map(|(k, c)| k * c.to_digit(10).unwrap())
        .sum();
    let c2 = (sum2 % 11) % 10;
    c2 == d.chars().nth(11).unwrap().to_digit(10).unwrap()
}

/// Валидатор СНИЛС.
pub struct SnilsValidator;

impl Validator for SnilsValidator {
    fn id(&self) -> &str {
        "snils"
    }
    fn validate(&self, raw: &str) -> ValidationResult {
        let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() != 11 {
            return ValidationResult::NotApplicable;
        }
        if snils_valid(&digits) {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid
        }
    }
}

pub fn snils_valid(d: &str) -> bool {
    if d.len() != 11 {
        return false;
    }
    let sum: u32 = d
        .chars()
        .take(9)
        .enumerate()
        .map(|(i, c)| (9 - i as u32) * c.to_digit(10).unwrap())
        .sum();
    let mut cs = if sum < 100 {
        sum
    } else if sum == 100 || sum == 101 {
        0
    } else {
        sum % 101
    };
    if cs == 100 {
        cs = 0;
    }
    let given: u32 = d.chars().skip(9).take(2).collect::<String>().parse().unwrap();
    cs == given
}

/// Валидатор даты (календарная).
pub struct DateValidator;

impl Validator for DateValidator {
    fn id(&self) -> &str {
        "date"
    }
    fn validate(&self, raw: &str) -> ValidationResult {
        if parse_date(raw).is_some() {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid
        }
    }
}

/// Проверяет, существует ли календарная дата в одной из интерпретаций.
pub fn parse_date(raw: &str) -> Option<(i32, u32, u32)> {
    let digits: Vec<u32> = raw
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    if digits.len() != 3 {
        return None;
    }
    let (a, b, c) = (digits[0], digits[1], digits[2]);
    let year = if c > 100 { c as i32 } else { 2000 + c as i32 };
    if !(1900..=2100).contains(&year) {
        return None;
    }
    // dd.mm.yyyy
    if valid_ymd(year, b, a) {
        return Some((year, b, a));
    }
    // mm.dd.yyyy (если день > 12 во второй позиции)
    if a > 12 && valid_ymd(year, a, b) {
        return Some((year, a, b));
    }
    // yyyy.mm.dd
    if a > 31 && valid_ymd(a as i32, b, c) {
        return Some((a as i32, b, c));
    }
    None
}

fn valid_ymd(year: i32, month: u32, day: u32) -> bool {
    if !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    day <= days_in_month
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Валидатор серии паспорта.
pub struct PassportSeriesValidator;

impl Validator for PassportSeriesValidator {
    fn id(&self) -> &str {
        "passport_series"
    }
    fn validate(&self, raw: &str) -> ValidationResult {
        let digits: Vec<u32> = raw
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        if digits.len() != 4 {
            return ValidationResult::NotApplicable;
        }
        let s1 = digits[0] * 10 + digits[1];
        let s2 = digits[2] * 10 + digits[3];
        if !(1..=99).contains(&s1) {
            return ValidationResult::Invalid;
        }
        // s2 — две последние цифры года выпуска бланка: 97..99 или 00..(текущий%100+1)
        let cur = (time::OffsetDateTime::now_utc().year() % 100) as u32;
        let valid_s2 = (97..=99).contains(&s2) || s2 <= (cur + 1) % 100;
        if valid_s2 {
            ValidationResult::Valid
        } else {
            ValidationResult::Invalid
        }
    }
}

/// Возвращает валидатор по имени.
pub fn get_validator(name: &str) -> Option<Arc<dyn Validator>> {
    match name {
        "luhn" => Some(Arc::new(LuhnValidator)),
        "inn" => Some(Arc::new(InnValidator)),
        "snils" => Some(Arc::new(SnilsValidator)),
        "date" => Some(Arc::new(DateValidator)),
        "passport_series" => Some(Arc::new(PassportSeriesValidator)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_known() {
        assert!(luhn_valid("4532015112830366"));
        assert!(!luhn_valid("4532015112830367"));
    }

    #[test]
    fn inn_known() {
        // Примеры валидных ИНН
        assert!(inn10_valid("7707083893"));
        assert!(inn12_valid("500100732259"));
        assert!(!inn10_valid("7707083894"));
    }

    #[test]
    fn snils_known() {
        assert!(snils_valid("11223344595"));
        assert!(!snils_valid("11223344596"));
    }

    #[test]
    fn date_known() {
        assert!(parse_date("05.03.1985").is_some());
        assert!(parse_date("1985-03-05").is_some());
        assert!(parse_date("31.02.2020").is_none());
    }
}