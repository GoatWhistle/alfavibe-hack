//! Фильтры «это ПД или нет» (relevance).

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::traits::RelevanceFilter;
use crate::service::detect::context::window;

/// Фильтр публичных лиц (Пушкин и т.п.).
pub struct PublicPersonFilter {
    pub persons: Vec<Vec<String>>,
}

impl RelevanceFilter for PublicPersonFilter {
    fn id(&self) -> &str {
        "public_persons"
    }
    fn keep(&self, doc: &Document<'_>, cand: &Candidate, all: &[Candidate]) -> bool {
        if cand.pd_type.as_str() != PdType::FIO {
            return true;
        }
        let orig = doc.original_slice(cand.span).to_lowercase();
        let is_person = self.persons.iter().any(|forms| {
            forms.iter().any(|f| {
                let f = f.to_lowercase();
                // Совпадение только если orig содержит полную форму персоны
                // (не наоборот — иначе клиент «Александр» будет принят за Пушкина).
                orig.contains(&f)
            })
        });
        if !is_person {
            return true;
        }
        // В окне ±80 есть персональные маркеры?
        let window = window(doc, cand.span.start.saturating_sub(80), cand.span.end + 80);
        let markers = ["клиент", "паспорт", "телефон", "проживает", "счет", "карта"]
            .iter()
            .any(|w| window.contains(w));
        let other_pd = all.iter().any(|c| {
            c.span != cand.span && c.score >= 0.8 && c.pd_type.as_str() != PdType::FIO
        });
        if markers || other_pd {
            return true;
        }
        // Контекст «поэт/писатель/улица/памятник...»
        let neg = ["поэт", "писатель", "композитор", "президент", "министр", "художник", "ученый", "улица", "проспект", "памятник", "музей", "имени", "им."]
            .iter()
            .any(|w| window.contains(w));
        !neg
    }
}

/// Фильтр адресов/телефонов банка.
pub struct BankAllowlistFilter {
    pub offices: Vec<String>,
    pub phones: Vec<String>,
    /// Адреса отделений, разобранные на слова один раз.
    office_tokens: Vec<Vec<String>>,
    /// Цифры телефонов банка, посчитанные один раз.
    phone_digits: Vec<String>,
}

impl BankAllowlistFilter {
    pub fn new(offices: Vec<String>, phones: Vec<String>) -> Self {
        let office_tokens = offices
            .iter()
            .map(|o| normalize_for_compare(o).split_whitespace().map(str::to_string).collect())
            .filter(|t: &Vec<String>| !t.is_empty())
            .collect();
        let phone_digits = phones
            .iter()
            .map(|p| p.chars().filter(|c| c.is_ascii_digit()).collect())
            .collect();
        Self {
            offices,
            phones,
            office_tokens,
            phone_digits,
        }
    }
}

impl RelevanceFilter for BankAllowlistFilter {
    fn id(&self) -> &str {
        "bank_allowlist"
    }
    fn keep(&self, doc: &Document<'_>, cand: &Candidate, _all: &[Candidate]) -> bool {
        let orig = doc.original_slice(cand.span);

        // Адрес отделения может быть длиннее найденного компонента («ул. Тверская»
        // против «москва ул тверская д 1»), поэтому сверяемся с окрестностью,
        // а не только с самим кандидатом. Сравниваем последовательности слов, а не
        // подстроки: иначе «д 1» из справочника совпадёт с «д 12» в тексте.
        let around = normalize_for_compare(&window_original(doc, cand, 60, 60));
        let tokens: Vec<&str> = around.split_whitespace().collect();
        if self
            .office_tokens
            .iter()
            .any(|office| contains_token_sequence(&tokens, office))
        {
            return false;
        }

        // Рядом сказано, что это отделение/офис банка — значит, не ПД клиента.
        if matches!(
            cand.pd_type.as_str(),
            PdType::ADDRESS
                | PdType::ADDR_CITY
                | PdType::ADDR_STREET
                | PdType::ADDR_HOUSE
                | PdType::ADDR_FLAT
                | PdType::ADDR_REGION
                | PdType::ADDR_INDEX
                | PdType::PHONE
        ) && ["отделение банка", "офис банка", "филиал банка", "горячей линии", "горячая линия"]
            .iter()
            .any(|w| around.contains(w))
        {
            return false;
        }
        if cand.pd_type.as_str() == PdType::PHONE {
            let digits: String = orig.chars().filter(|c| c.is_ascii_digit()).collect();
            if self
                .phone_digits
                .iter()
                .any(|pd| !pd.is_empty() && digits.contains(pd.as_str()))
            {
                return false;
            }
        }
        true
    }
}

/// Встречается ли последовательность слов `needle` подряд в `haystack`.
fn contains_token_sequence(haystack: &[&str], needle: &[String]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(a, b)| *a == b.as_str()))
}

/// Окрестность кандидата в исходном тексте.
fn window_original(doc: &Document<'_>, cand: &Candidate, left: usize, right: usize) -> String {
    let text = doc.original;
    let mut lo = cand.span.start.saturating_sub(left);
    let mut hi = (cand.span.end + right).min(text.len());
    while lo > 0 && !text.is_char_boundary(lo) {
        lo -= 1;
    }
    while hi < text.len() && !text.is_char_boundary(hi) {
        hi += 1;
    }
    text[lo..hi].to_string()
}

/// Приводит адрес к форме, в которой записан справочник отделений:
/// нижний регистр, без пунктуации, одиночные пробелы.
fn normalize_for_compare(s: &str) -> String {
    let stripped: String = s
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect();
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Фильтр негативного контекста чисел (заказ/договор/сумма).
pub struct NegativeNumberContext;

impl RelevanceFilter for NegativeNumberContext {
    fn id(&self) -> &str {
        "negative_number_context"
    }
    fn keep(&self, doc: &Document<'_>, cand: &Candidate, _all: &[Candidate]) -> bool {
        // Только для числовых типов без контрольной суммы.
        let is_numeric = matches!(
            cand.pd_type.as_str(),
            PdType::PASSPORT | PdType::PHONE | PdType::INN | PdType::ORG_INN
        );
        if !is_numeric {
            return true;
        }
        if cand.signals.contains(SignalFlags::CHECKSUM_OK) {
            return true;
        }
        let window = window(doc, cand.span.start.saturating_sub(60), cand.span.start);
        let neg = ["заказ", "договор", "счет-фактура", "артикул", "инвойс", "номер заявки", "тикет", "сумма", "руб"]
            .iter()
            .any(|w| window.contains(w));
        !neg
    }
}

/// Фильтр контекста организации (ФИО внутри названия ООО).
pub struct OrgContextFilter;

impl RelevanceFilter for OrgContextFilter {
    fn id(&self) -> &str {
        "org_context"
    }
    fn keep(&self, doc: &Document<'_>, cand: &Candidate, _all: &[Candidate]) -> bool {
        if cand.pd_type.as_str() != PdType::FIO {
            return true;
        }
        let window = window(doc, cand.span.start.saturating_sub(40), cand.span.end + 40);
        let org = ["ооо", "зао", "ао", "пао", "ип", "оао"]
            .iter()
            .any(|w| window.contains(w));
        !org
    }
}