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
}

impl RelevanceFilter for BankAllowlistFilter {
    fn id(&self) -> &str {
        "bank_allowlist"
    }
    fn keep(&self, doc: &Document<'_>, cand: &Candidate, _all: &[Candidate]) -> bool {
        let orig = doc.original_slice(cand.span);
        let norm_orig = normalize_for_compare(orig);
        if self.offices.iter().any(|o| norm_orig.contains(&normalize_for_compare(o))) {
            return false;
        }
        if cand.pd_type.as_str() == PdType::PHONE {
            let digits: String = orig.chars().filter(|c| c.is_ascii_digit()).collect();
            if self.phones.iter().any(|p| {
                let pd: String = p.chars().filter(|c| c.is_ascii_digit()).collect();
                !pd.is_empty() && digits.contains(&pd)
            }) {
                return false;
            }
        }
        true
    }
}

fn normalize_for_compare(s: &str) -> String {
    s.to_lowercase()
        .replace("ул.", "улица")
        .replace("г.", "город")
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect()
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