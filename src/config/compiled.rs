//! CompiledConfig: предвычисленные регулярки, автоматы, словари, политики.

use std::collections::HashMap;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};

use crate::domain::pd_type::PdType;
use crate::domain::traits::EffectivePolicy;

use super::model::Config;

/// Скомпилированный конфиг. Неизменяемый, разделяется через ArcSwap.
pub struct CompiledConfig {
    pub version: u64,
    pub raw: Config,
    /// Регулярки детекторов по типу.
    pub detector_regexes: HashMap<PdType, Regex>,
    /// value_group для конфиг-детекторов.
    pub detector_value_groups: HashMap<PdType, String>,
    /// base_score для конфиг-детекторов.
    pub detector_base_scores: HashMap<PdType, f32>,
    /// Контекстные слова для конфиг-детекторов.
    pub detector_context: HashMap<PdType, (Vec<String>, Vec<String>)>,
    /// Общий AhoCorasick по всем контекстным словам (для префильтра).
    pub context_ac: Option<AhoCorasick>,
    /// PERF-11: RegexSet по всем паттернам конфиг-детекторов (для префильтра).
    pub prefilter_regex_set: Option<RegexSet>,
    /// Словари.
    pub first_names: Vec<String>,
    pub public_persons: Vec<Vec<String>>,
    pub bank_offices: Vec<String>,
    pub bank_phones: Vec<String>,
    pub countries: Vec<String>,
    pub cities: Vec<String>,
    pub issuing_authorities: Vec<String>,
    /// Кэш эффективных политик.
    pub policies: HashMap<(String, Option<String>), Arc<EffectivePolicy>>,
    /// Метки типов.
    pub labels: HashMap<PdType, String>,
    /// Приоритеты типов.
    pub priorities: HashMap<PdType, i32>,
    /// Пороги типов.
    pub thresholds: HashMap<PdType, f32>,
    /// Мастер-ключ (base64 строка из env/file).
    pub master_key_b64: String,
    /// SHA-256 admin-токена (резолвнутый).
    pub admin_token_sha256: String,
    /// SHA-256 ключей систем.
    pub system_keys: HashMap<String, String>,
    /// SHA-256 ключей систем как сырые 32 байта (PERF-06).
    pub system_key_bytes: HashMap<String, [u8; 32]>,
    /// Включённость систем.
    pub system_enabled: HashMap<String, bool>,
    /// Профиль системы.
    pub system_profile: HashMap<String, String>,
    /// demask системы.
    pub system_demask: HashMap<String, bool>,
    /// rate limit систем.
    pub system_rate_limit: HashMap<String, u64>,
    /// overrides систем.
    pub system_overrides: HashMap<String, super::model::ProfileConfig>,
    /// route_overrides систем.
    pub system_route_overrides: HashMap<String, HashMap<String, super::model::RouteOverrideConfig>>,
    /// Профили.
    pub profiles: HashMap<String, super::model::ProfileConfig>,
    /// defaults.
    pub defaults: super::model::DefaultsConfig,
    /// upstreams.
    pub upstreams: HashMap<String, super::model::UpstreamConfig>,
    /// routes.
    pub routes: Vec<super::model::RouteConfig>,
    /// placeholder format по умолчанию.
    pub placeholder_format: String,
    /// default action.
    pub default_action: String,
}

impl CompiledConfig {
    pub fn label(&self, t: &PdType) -> String {
        self.labels
            .get(t)
            .cloned()
            .unwrap_or_else(|| t.as_str().to_string())
    }

    pub fn priority(&self, t: &PdType) -> i32 {
        self.priorities.get(t).copied().unwrap_or(50)
    }

    pub fn threshold(&self, t: &PdType) -> f32 {
        self.thresholds.get(t).copied().unwrap_or(0.6)
    }
}