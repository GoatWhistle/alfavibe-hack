//! Кандидаты, сущности, записи маскирования.

use bitflags::bitflags;

use super::document::Span;
use super::pd_type::PdType;
use super::sensitive::Sensitive;

/// Источник кандидата.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DetectorSource {
    Regex { id: String },
    Checksum { id: String },
    Ner { model: String },
    Dictionary { id: String },
    Custom { id: String },
}

impl DetectorSource {
    pub fn kind(&self) -> &'static str {
        match self {
            DetectorSource::Regex { .. } => "regex",
            DetectorSource::Checksum { .. } => "checksum",
            DetectorSource::Ner { .. } => "ner",
            DetectorSource::Dictionary { .. } => "dictionary",
            DetectorSource::Custom { .. } => "custom",
        }
    }
}

bitflags! {
    /// Сигналы, накопленные при детекции.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SignalFlags: u32 {
        const CHECKSUM_OK = 1 << 0;
        const CONTEXT_POS = 1 << 1;
        const CONTEXT_NEG = 1 << 2;
        const DICT_HIT = 1 << 3;
        const CAPITALIZED_ORIGINAL = 1 << 4;
        const VALIDATED = 1 << 5;
    }
}

/// Кандидат на ПД до разрешения конфликтов.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub pd_type: PdType,
    pub span: Span,
    pub score: f32,
    pub source: DetectorSource,
    pub components: Vec<Candidate>,
    pub signals: SignalFlags,
}

impl Candidate {
    pub fn new(pd_type: PdType, span: Span, score: f32, source: DetectorSource) -> Self {
        Candidate {
            pd_type,
            span,
            score,
            source,
            components: Vec::new(),
            signals: SignalFlags::empty(),
        }
    }
}

/// Сущность ПД после разрешения конфликтов.
#[derive(Clone, Debug)]
pub struct Entity {
    pub pd_type: PdType,
    pub span: Span,
    pub score: f32,
    pub source: DetectorSource,
    pub components: Vec<Entity>,
    pub canonical: Sensitive<String>,
}

/// Запись о маскировании одного значения.
#[derive(Clone, Debug)]
pub struct MaskRecord {
    pub masked_span: Span,
    pub original_span: Span,
    pub pd_type: PdType,
    pub key: Option<String>,
}

/// Состояние маскирования в рамках сессии (нумерация плейсхолдеров, консистентность).
#[derive(Default)]
pub struct MaskState {
    /// Счётчик номеров по типу (для разных значений).
    pub counters: std::collections::HashMap<PdType, u32>,
    /// canonical → уже назначенный номер (для повторов одного значения).
    pub assigned: std::collections::HashMap<(PdType, String), u32>,
}

impl MaskState {
    /// Возвращает номер плейсхолдера для значения. Одно и то же значение (по canonical)
    /// в рамках сессии получает один и тот же номер; разные значения — разные номера.
    pub fn next_number(&mut self, pd_type: &PdType, canonical: &str) -> u32 {
        let key = (pd_type.clone(), canonical.to_string());
        if let Some(n) = self.assigned.get(&key) {
            return *n;
        }
        let n = self.counters.entry(pd_type.clone()).or_insert(0);
        *n += 1;
        self.assigned.insert(key, *n);
        *n
    }
}