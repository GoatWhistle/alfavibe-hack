//! Тип ПД — строковый идентификатор, расширяемый конфигом.

use std::sync::Arc;

/// Тип персональных данных. Открытый строковый идентификатор: новые типы
/// добавляются конфигом без переделки кода.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PdType(pub Arc<str>);

impl serde::Serialize for PdType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for PdType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(PdType(Arc::from(s)))
    }
}

impl PdType {
    pub const FIO: &'static str = "FIO";
    pub const BIRTH_DATE: &'static str = "BIRTH_DATE";
    pub const BIRTH_PLACE: &'static str = "BIRTH_PLACE";
    pub const PASSPORT: &'static str = "PASSPORT";
    pub const CITIZENSHIP: &'static str = "CITIZENSHIP";
    pub const PASSPORT_ISSUER: &'static str = "PASSPORT_ISSUER";
    pub const DIVISION_CODE: &'static str = "DIVISION_CODE";
    pub const PASSPORT_ISSUE_DATE: &'static str = "PASSPORT_ISSUE_DATE";
    pub const DRIVER_LICENSE: &'static str = "DRIVER_LICENSE";
    pub const ADDRESS: &'static str = "ADDRESS";
    pub const ADDR_COUNTRY: &'static str = "ADDR_COUNTRY";
    pub const ADDR_INDEX: &'static str = "ADDR_INDEX";
    pub const ADDR_REGION: &'static str = "ADDR_REGION";
    pub const ADDR_CITY: &'static str = "ADDR_CITY";
    pub const ADDR_STREET: &'static str = "ADDR_STREET";
    pub const ADDR_HOUSE: &'static str = "ADDR_HOUSE";
    pub const ADDR_FLAT: &'static str = "ADDR_FLAT";
    pub const EMAIL: &'static str = "EMAIL";
    pub const PHONE: &'static str = "PHONE";
    pub const INN: &'static str = "INN";
    pub const CARD_NUMBER: &'static str = "CARD_NUMBER";
    pub const CVV: &'static str = "CVV";
    pub const PIN: &'static str = "PIN";
    pub const CARD_HOLDER: &'static str = "CARD_HOLDER";
    pub const SNILS: &'static str = "SNILS";
    pub const FOREIGN_PASSPORT: &'static str = "FOREIGN_PASSPORT";
    pub const OMS_POLICY: &'static str = "OMS_POLICY";
    pub const BIRTH_CERT: &'static str = "BIRTH_CERT";
    pub const MILITARY_ID: &'static str = "MILITARY_ID";
    pub const DATE: &'static str = "DATE";
    pub const ORG_INN: &'static str = "ORG_INN";
    pub const UNCLASSIFIED_ID: &'static str = "UNCLASSIFIED_ID";

    pub fn new(s: impl Into<Arc<str>>) -> Self {
        PdType(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for PdType {
    fn from(s: &str) -> Self {
        PdType(Arc::from(s))
    }
}

impl From<String> for PdType {
    fn from(s: String) -> Self {
        PdType(Arc::from(s))
    }
}

impl std::fmt::Display for PdType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for PdType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}