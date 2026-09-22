//! Демаскирование: поиск плейсхолдеров/токенов и замена.

use std::collections::HashMap;

use regex::Regex;

/// Соответствие «маска → оригинал» для сессии.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Mapping {
    pub entries: Vec<MappingEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MappingEntry {
    pub key: String,
    pub pd_type: String,
    pub original: String,
    /// Частично замаскированная форма (для partial-маскеров).
    #[serde(default)]
    pub masked: Option<String>,
}

impl Mapping {
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::domain::errors::VaultError> {
        bincode::serialize(self)
            .map_err(|e| crate::domain::errors::VaultError::Serialization(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::domain::errors::VaultError> {
        bincode::deserialize(bytes)
            .map_err(|e| crate::domain::errors::VaultError::Serialization(e.to_string()))
    }
}

/// Результат демаскирования.
pub struct DemaskResult {
    pub text: String,
    pub restored: usize,
    pub unresolved: usize,
}

/// Демаскирует текст, заменяя плейсхолдеры на оригиналы.
pub fn demask(text: &str, mapping: &Mapping) -> DemaskResult {
    let mut by_key: HashMap<&str, &str> = HashMap::new();
    let mut by_masked: Vec<(&str, &str)> = Vec::new();
    for e in &mapping.entries {
        by_key.insert(e.key.as_str(), e.original.as_str());
        if let Some(m) = &e.masked {
            by_masked.push((m.as_str(), e.original.as_str()));
        }
    }

    // Толерантный поиск плейсхолдеров.
    let re = Regex::new(r"(?:[\[\(\{<]\s*)?([A-ZА-Я]+(?:_[A-ZА-Я]+)*)[ _-]?(\d+)(?:\s*[\]\)\}>])?").unwrap();
    let mut restored = 0;
    let mut unresolved = 0;
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for caps in re.captures_iter(text) {
        let m = caps.get(0).unwrap();
        let label = caps.get(1).unwrap().as_str();
        let num = caps.get(2).unwrap().as_str();
        let key = format!("{label}_{num}");
        if let Some(orig) = by_key.get(key.as_str()) {
            out.push_str(&text[last..m.start()]);
            out.push_str(orig);
            restored += 1;
        } else {
            out.push_str(&text[last..m.end()]);
            unresolved += 1;
        }
        last = m.end();
    }
    out.push_str(&text[last..]);

    // Поиск по частично замаскированным значениям.
    for (masked, orig) in by_masked {
        if masked.is_empty() {
            continue;
        }
        let mut search_from = 0;
        while let Some(pos) = out[search_from..].find(masked) {
            let abs = search_from + pos;
            out.replace_range(abs..abs + masked.len(), orig);
            restored += 1;
            search_from = abs + orig.len();
        }
    }

    DemaskResult {
        text: out,
        restored,
        unresolved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demask_restores() {
        let mapping = Mapping {
            entries: vec![MappingEntry {
                key: "ФИО_1".into(),
                pd_type: "FIO".into(),
                original: "Иванов Иван Иванович".into(),
                masked: None,
            }],
        };
        let res = demask("Клиент [ФИО_1] живёт", &mapping);
        assert_eq!(res.text, "Клиент Иванов Иван Иванович живёт");
        assert_eq!(res.restored, 1);
        assert_eq!(res.unresolved, 0);
    }

    #[test]
    fn demask_tolerant() {
        let mapping = Mapping {
            entries: vec![MappingEntry {
                key: "ФИО_1".into(),
                pd_type: "FIO".into(),
                original: "Иванов".into(),
                masked: None,
            }],
        };
        // LLM исказил скобки
        let res = demask("Клиент ФИО_1", &mapping);
        assert_eq!(res.text, "Клиент Иванов");
    }
}