//! serde-модель конфигурации (раздел 11.2).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::domain::pd_type::PdType;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub vault: VaultConfig,
    #[serde(default)]
    pub ner: NerConfig,
    #[serde(default)]
    pub resources: ResourcesConfig,
    #[serde(default)]
    pub pd_types: HashMap<PdType, PdTypeConfig>,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub systems: HashMap<String, SystemConfig>,
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_max_inflight")]
    pub max_inflight: usize,
    #[serde(default = "default_heavy_threshold")]
    pub heavy_text_threshold_bytes: usize,
}

fn default_listen() -> String {
    "0.0.0.0:8080".into()
}
fn default_admin_listen() -> String {
    "127.0.0.1:9090".into()
}
fn default_max_body() -> usize {
    2_000_000
}
fn default_timeout_ms() -> u64 {
    950
}
fn default_max_inflight() -> usize {
    4096
}
fn default_heavy_threshold() -> usize {
    65536
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            admin_listen: default_admin_listen(),
            max_body_bytes: default_max_body(),
            request_timeout_ms: default_timeout_ms(),
            max_inflight: default_max_inflight(),
            heavy_text_threshold_bytes: default_heavy_threshold(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default)]
    pub master_key: String,
    #[serde(default)]
    pub admin_token_sha256: String,
    #[serde(default = "default_auth_header")]
    pub auth_header: String,
    #[serde(default = "default_system_id_header")]
    pub system_id_header: String,
    /// Система, от имени которой обслуживаются запросы без заголовков
    /// аутентификации. Нужна для контракта Приложения A: проверяющая система
    /// шлёт POST /process без учётных данных. Пусто — анонимный доступ закрыт.
    #[serde(default)]
    pub default_system_id: String,
}

fn default_auth_header() -> String {
    "X-System-Key".into()
}
fn default_system_id_header() -> String {
    "X-System-Id".into()
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            master_key: String::new(),
            admin_token_sha256: String::new(),
            auth_header: default_auth_header(),
            system_id_header: default_system_id_header(),
            default_system_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default = "default_true")]
    pub log_entity_offsets: bool,
}

fn default_level() -> String {
    "info".into()
}
fn default_format() -> String {
    "json".into()
}
fn default_true() -> bool {
    true
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
            format: default_format(),
            log_entity_offsets: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    #[serde(default = "default_vault_mode")]
    pub mode: String,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
    #[serde(default = "default_max_entries")]
    pub max_entries: u64,
    #[serde(default)]
    pub redis_url: String,
    #[serde(default)]
    pub delete_after_demask: bool,
}

fn default_vault_mode() -> String {
    "memory".into()
}
fn default_ttl() -> u64 {
    900
}
fn default_max_entries() -> u64 {
    1_000_000
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            mode: default_vault_mode(),
            ttl_seconds: default_ttl(),
            max_entries: default_max_entries(),
            redis_url: String::new(),
            delete_after_demask: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NerConfig {
    #[serde(default = "default_ner_engine")]
    pub engine: String,
    #[serde(default)]
    pub onnx: NerOnnxConfig,
    #[serde(default)]
    pub http: NerHttpConfig,
    #[serde(default = "default_ner_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_windows")]
    pub max_windows_per_request: usize,
    #[serde(default)]
    pub trigger_words: Vec<String>,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
}

fn default_ner_engine() -> String {
    "disabled".into()
}
fn default_ner_timeout() -> u64 {
    400
}
fn default_max_windows() -> usize {
    64
}

impl Default for NerConfig {
    fn default() -> Self {
        Self {
            engine: default_ner_engine(),
            onnx: NerOnnxConfig::default(),
            http: NerHttpConfig::default(),
            timeout_ms: default_ner_timeout(),
            max_windows_per_request: default_max_windows(),
            trigger_words: Vec::new(),
            circuit_breaker: CircuitBreakerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NerOnnxConfig {
    #[serde(default)]
    pub model_path: String,
    #[serde(default)]
    pub tokenizer_path: String,
    #[serde(default = "default_workers")]
    pub workers: usize,
    #[serde(default = "default_max_batch")]
    pub max_batch: usize,
    #[serde(default = "default_batch_wait")]
    pub batch_wait_ms: u64,
}

fn default_workers() -> usize {
    4
}
fn default_max_batch() -> usize {
    16
}
fn default_batch_wait() -> u64 {
    5
}

impl Default for NerOnnxConfig {
    fn default() -> Self {
        Self {
            model_path: String::new(),
            tokenizer_path: String::new(),
            workers: default_workers(),
            max_batch: default_max_batch(),
            batch_wait_ms: default_batch_wait(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NerHttpConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_ner_http_timeout")]
    pub timeout_ms: u64,
}

fn default_ner_http_timeout() -> u64 {
    300
}

impl Default for NerHttpConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout_ms: default_ner_http_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_failure_ratio")]
    pub failure_ratio: f64,
    #[serde(default = "default_window")]
    pub window: usize,
    #[serde(default = "default_open_seconds")]
    pub open_seconds: u64,
}

fn default_failure_ratio() -> f64 {
    0.5
}
fn default_window() -> usize {
    20
}
fn default_open_seconds() -> u64 {
    10
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_ratio: default_failure_ratio(),
            window: default_window(),
            open_seconds: default_open_seconds(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub struct ResourcesConfig {
    #[serde(default)]
    pub first_names: String,
    #[serde(default)]
    pub public_persons: String,
    #[serde(default)]
    pub bank_offices: String,
    #[serde(default)]
    pub bank_phones: String,
    #[serde(default)]
    pub countries: String,
    #[serde(default)]
    pub cities: String,
    #[serde(default)]
    pub issuing_authorities: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdTypeConfig {
    pub label: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default = "default_threshold")]
    pub threshold: f32,
    #[serde(default)]
    pub detector: Option<DetectorConfig>,
}

fn default_priority() -> i32 {
    50
}
fn default_threshold() -> f32 {
    0.6
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorConfig {
    pub regex: String,
    #[serde(default)]
    pub value_group: String,
    #[serde(default = "default_validator")]
    pub validator: String,
    #[serde(default = "default_base_score")]
    pub base_score: f32,
    #[serde(default)]
    pub context_pos: Vec<String>,
    #[serde(default)]
    pub context_neg: Vec<String>,
    #[serde(default)]
    pub window: WindowConfig,
}

fn default_validator() -> String {
    "none".into()
}
fn default_base_score() -> f32 {
    0.8
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowConfig {
    #[serde(default = "default_window_left")]
    pub left: usize,
    #[serde(default = "default_window_right")]
    pub right: usize,
}

fn default_window_left() -> usize {
    60
}
fn default_window_right() -> usize {
    20
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            left: default_window_left(),
            right: default_window_right(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    #[serde(default)]
    pub types: HashMap<PdType, TypeMaskConfig>,
    #[serde(default)]
    pub ner: ProfileNerConfig,
    #[serde(default)]
    pub filters: Vec<String>,
    #[serde(default)]
    pub combination: CombinationConfig,
    #[serde(default)]
    pub ambiguous_ids: Option<String>,
    #[serde(default)]
    pub demask: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeMaskConfig {
    #[serde(default)]
    pub mask: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub keep_last: Option<usize>,
    #[serde(default)]
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(Default)]
pub struct ProfileNerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub types: Vec<PdType>,
    #[serde(default)]
    pub on_failure: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CombinationRuleConfig {
    #[serde(default)]
    pub requires_any: Vec<PdType>,
    #[serde(default)]
    pub requires_all: Vec<PdType>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub window_chars: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultsConfig {
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub placeholder: PlaceholderConfig,
    #[serde(default)]
    pub action: String,
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            profile: String::new(),
            placeholder: PlaceholderConfig::default(),
            action: "mask".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlaceholderConfig {
    #[serde(default = "default_placeholder_format")]
    pub format: String,
}

fn default_placeholder_format() -> String {
    "[{label}_{n}]".into()
}

impl Default for PlaceholderConfig {
    fn default() -> Self {
        Self {
            format: default_placeholder_format(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub key_sha256: String,
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub demask: bool,
    #[serde(default)]
    pub rate_limit_rps: Option<u64>,
    #[serde(default)]
    pub overrides: Option<ProfileConfig>,
    #[serde(default)]
    pub route_overrides: HashMap<String, RouteOverrideConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOverrideConfig {
    #[serde(default)]
    pub types: HashMap<PdType, TypeMaskConfig>,
    #[serde(default)]
    pub combination: Option<CombinationConfig>,
    #[serde(default)]
    pub demask: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub url: String,
    #[serde(default)]
    pub auth_header: String,
    #[serde(default)]
    pub auth_value: String,
    #[serde(default = "default_upstream_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub pass_headers: Vec<String>,
}

fn default_upstream_timeout() -> u64 {
    60000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub id: String,
    pub r#match: RouteMatch,
    #[serde(default)]
    pub upstream: String,
    #[serde(default)]
    pub request: RouteRequestConfig,
    #[serde(default)]
    pub response: RouteResponseConfig,
    #[serde(default)]
    pub stream: String,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub systems: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteMatch {
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub path_prefix: String,
    #[serde(default)]
    pub header: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RouteRequestConfig {
    #[serde(default)]
    pub json_paths: Vec<String>,
    #[serde(default)]
    pub profile_override: Option<String>,
    #[serde(default)]
    pub types_override: HashMap<PdType, TypeMaskConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RouteResponseConfig {
    #[serde(default)]
    pub demask: bool,
    #[serde(default)]
    pub json_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CombinationConfig {
    #[serde(default)]
    pub rules: HashMap<PdType, Option<CombinationRuleConfig>>,
    #[serde(default)]
    pub min_distinct_types: usize,
    #[serde(default)]
    pub always_mask: Vec<PdType>,
}