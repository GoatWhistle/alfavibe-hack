//! Все абстракции (трейты) доменного слоя.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;

use super::document::{Document, Span};
use super::entity::{Candidate, Entity, MaskState};
use super::errors::{NerError, UpstreamError, VaultError};
use super::pd_type::PdType;

/// Контекст детекции: переиспользуемые результаты префильтра.
#[derive(Default)]
pub struct DetectCtx {
    /// Позиции ключевых слов контекста (нормализованные байты).
    pub keyword_hits: Vec<(usize, usize)>,
    /// Какие детекторы имеют шанс (по RegexSet-префильтру).
    pub active_detectors: Vec<usize>,
}

/// Результат валидации формата/контрольной суммы.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Invalid,
    NotApplicable,
}

/// Нормализатор текста.
pub trait Normalizer: Send + Sync {
    fn normalize<'a>(&self, text: &'a str) -> Document<'a>;
}

/// Детерминированный детектор одного или нескольких типов.
pub trait Detector: Send + Sync {
    fn id(&self) -> &str;
    fn types(&self) -> &[PdType];
    fn detect(&self, doc: &Document<'_>, ctx: &DetectCtx, out: &mut Vec<Candidate>);
}

/// Проверка формата/контрольной суммы.
pub trait Validator: Send + Sync {
    fn id(&self) -> &str;
    fn validate(&self, raw: &str) -> ValidationResult;
}

/// Контекстный скоринг.
pub trait ContextScorer: Send + Sync {
    fn score(&self, doc: &Document<'_>, cand: &mut Candidate);
}

/// NER-движок.
#[async_trait]
pub trait NerEngine: Send + Sync {
    fn name(&self) -> &str;
    async fn recognize(
        &self,
        text: &str,
        windows: &[Span],
        deadline: Instant,
    ) -> Result<Vec<Candidate>, NerError>;
    async fn health(&self) -> bool;
}

/// Фильтр «это ПД или нет».
pub trait RelevanceFilter: Send + Sync {
    fn id(&self) -> &str;
    fn keep(&self, doc: &Document<'_>, cand: &Candidate, all: &[Candidate]) -> bool;
}

/// Разрешение пересечений и слияние.
pub trait Resolver: Send + Sync {
    fn resolve(&self, cands: Vec<Candidate>, policy: &EffectivePolicy) -> Vec<Entity>;
}

/// Правила совместного появления типов.
pub trait CombinationRule: Send + Sync {
    fn apply(&self, entities: &mut Vec<Entity>, policy: &EffectivePolicy);
}

/// Вид маскирования.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MaskKind {
    Placeholder,
    Redact,
    Partial,
    Token,
    Synthetic,
    Hash,
}

/// Результат маскирования одного значения.
pub struct MaskOutput {
    pub replacement: String,
    pub key: Option<String>,
}

/// Стратегия маскирования одного значения.
pub trait Masker: Send + Sync {
    fn kind(&self) -> MaskKind;
    fn mask(&self, entity: &Entity, original: &str, state: &mut MaskState) -> MaskOutput;
    fn reversible(&self) -> bool;
}

/// Идентификатор сессии.
pub type SessionId = String;

/// Зашифрованное соответствие «маска → оригинал».
#[derive(Clone)]
pub struct EncryptedMapping {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Идентификатор upstream.
pub type UpstreamId = String;

/// Хранилище соответствий.
#[async_trait]
pub trait Vault: Send + Sync {
    async fn put(
        &self,
        session: &str,
        mapping: EncryptedMapping,
        ttl: Duration,
    ) -> Result<(), VaultError>;
    async fn get(&self, session: &str) -> Result<Option<EncryptedMapping>, VaultError>;
    async fn delete(&self, session: &str) -> Result<(), VaultError>;
    async fn health(&self) -> bool;
}

/// Исходящий клиент к LLM.
#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn send(
        &self,
        upstream: &UpstreamId,
        req: http::Request<http_body_util::Full<Bytes>>,
        deadline: Instant,
    ) -> Result<http::Response<Bytes>, UpstreamError>;
}

/// Подсчёт токенов.
pub trait TokenCounter: Send + Sync {
    fn count(&self, text: &str) -> usize;
}

/// Эффективная политика для запроса (предвычисленная).
#[derive(Clone, Debug, Default)]
pub struct EffectivePolicy {
    pub action: PolicyAction,
    pub types: Vec<PdType>,
    pub demask: bool,
    pub ambiguous_ids: AmbiguousIdsMode,
    pub placeholder_format: String,
    pub labels: std::collections::HashMap<PdType, String>,
    pub thresholds: std::collections::HashMap<PdType, f32>,
    pub priorities: std::collections::HashMap<PdType, i32>,
    pub mask_kinds: std::collections::HashMap<PdType, MaskKind>,
    pub address_mode: AddressMode,
    pub ner_enabled: bool,
    pub ner_types: Vec<PdType>,
    pub ner_on_failure: NerOnFailure,
    /// OPS-04: лимит окон NER (из конфига).
    pub max_windows_per_request: usize,
    /// OPS-04: триггерные слова NER (из конфига).
    pub trigger_words: Vec<String>,
    pub filters: Vec<String>,
    pub combination: CombinationConfig,
    pub json_paths: Vec<String>,
    pub response_json_paths: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PolicyAction {
    #[default]
    Mask,
    Bypass,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AmbiguousIdsMode {
    #[default]
    Skip,
    Mask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AddressMode {
    #[default]
    Whole,
    Components,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum NerOnFailure {
    #[default]
    Degrade,
    Fail,
}

#[derive(Clone, Debug, Default)]
pub struct CombinationConfig {
    pub rules: std::collections::HashMap<PdType, CombinationRuleConfig>,
    pub min_distinct_types: usize,
    pub always_mask: Vec<PdType>,
}

#[derive(Clone, Debug)]
pub struct CombinationRuleConfig {
    pub requires_any: Vec<PdType>,
    pub requires_all: Vec<PdType>,
    pub scope: CombinationScope,
    pub window_chars: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CombinationScope {
    #[default]
    Document,
    Window,
}