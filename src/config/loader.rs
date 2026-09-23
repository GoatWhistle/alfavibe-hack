//! Загрузка, валидация и компиляция конфига.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, MatchKind};
use regex::{Regex, RegexSet};
use thiserror::Error;

use crate::domain::pd_type::PdType;
use crate::domain::traits::{
    AddressMode, AmbiguousIdsMode, CombinationConfig, CombinationRuleConfig, CombinationScope,
    EffectivePolicy, MaskKind, NerOnFailure, PolicyAction,
};

use super::compiled::CompiledConfig;
use super::model::{Config, ProfileConfig, TypeMaskConfig};

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config parse error: {0}")]
    Parse(String),
    #[error("config validation error at {path}: {msg}")]
    Validation { path: String, msg: String },
    #[error("resource load error: {0}")]
    Resource(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Загружает конфиг из YAML-строки и компилирует.
pub fn load_from_str(yaml: &str, base_dir: &Path) -> Result<CompiledConfig, ConfigError> {
    let cfg: Config = serde_yaml::from_str(yaml)
        .map_err(|e| ConfigError::Parse(format!("{e}")))?;
    compile(cfg, base_dir)
}

/// Загружает конфиг из файла.
pub fn load_from_file(path: &Path) -> Result<CompiledConfig, ConfigError> {
    let yaml = std::fs::read_to_string(path)?;
    // base_dir — корень проекта (родитель каталога конфига), чтобы пути
    // `config/resources/...` в конфиге резолвились относительно корня.
    let base_dir = path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    load_from_str(&yaml, &base_dir)
}

fn compile(cfg: Config, base_dir: &Path) -> Result<CompiledConfig, ConfigError> {
    validate(&cfg)?;

    // Компиляция регулярок детекторов.
    let mut detector_regexes = HashMap::new();
    let mut detector_value_groups = HashMap::new();
    let mut detector_base_scores = HashMap::new();
    let mut detector_context: HashMap<PdType, (Vec<String>, Vec<String>)> = HashMap::new();

    for (t, tc) in &cfg.pd_types {
        if let Some(d) = &tc.detector {
            let re = Regex::new(&d.regex)
                .map_err(|e| ConfigError::Validation {
                    path: format!("pd_types.{}.detector.regex", t),
                    msg: format!("invalid regex: {e}"),
                })?;
            if d.value_group.is_empty() {
                return Err(ConfigError::Validation {
                    path: format!("pd_types.{}.detector", t),
                    msg: "value_group is required".into(),
                });
            }
            detector_regexes.insert(t.clone(), re);
            detector_value_groups.insert(t.clone(), d.value_group.clone());
            detector_base_scores.insert(t.clone(), d.base_score);
            detector_context.insert(t.clone(), (d.context_pos.clone(), d.context_neg.clone()));
        }
    }

    // Общий AhoCorasick по контекстным словам.
    let mut all_context_words: Vec<String> = Vec::new();
    for (pos, neg) in detector_context.values() {
        all_context_words.extend(pos.iter().cloned());
        all_context_words.extend(neg.iter().cloned());
    }
    let context_ac = if all_context_words.is_empty() {
        None
    } else {
        Some(
            AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&all_context_words)
                .map_err(|e| ConfigError::Validation {
                    path: "context".into(),
                    msg: format!("aho-corasick build: {e}"),
                })?,
        )
    };

    // PERF-11: RegexSet по всем паттернам конфиг-детекторов.
    let prefilter_regex_set = if detector_regexes.is_empty() {
        None
    } else {
        let mut patterns: Vec<&str> = Vec::new();
        for re in detector_regexes.values() {
            patterns.push(re.as_str());
        }
        Some(
            RegexSet::new(patterns).map_err(|e| ConfigError::Validation {
                path: "pd_types.*.detector.regex".into(),
                msg: format!("regex set build: {e}"),
            })?,
        )
    };

    // Загрузка ресурсов.
    let first_names = load_lines(&cfg.resources.first_names, base_dir)?;
    let public_persons = load_pipe_lines(&cfg.resources.public_persons, base_dir)?;
    let bank_offices = load_lines(&cfg.resources.bank_offices, base_dir)?;
    let bank_phones = load_lines(&cfg.resources.bank_phones, base_dir)?;
    let countries = load_lines(&cfg.resources.countries, base_dir)?;
    let cities = load_lines(&cfg.resources.cities, base_dir)?;
    let issuing_authorities = load_lines(&cfg.resources.issuing_authorities, base_dir)?;

    // Метки, приоритеты, пороги.
    let mut labels = HashMap::new();
    let mut priorities = HashMap::new();
    let mut thresholds = HashMap::new();
    for (t, tc) in &cfg.pd_types {
        labels.insert(t.clone(), tc.label.clone());
        priorities.insert(t.clone(), tc.priority);
        thresholds.insert(t.clone(), tc.threshold);
    }

    let master_key_b64 = resolve_secret(&cfg.security.master_key)?;
    let admin_token_sha256 = resolve_secret(&cfg.security.admin_token_sha256)?;

    let mut system_keys = HashMap::new();
    let mut system_key_bytes = HashMap::new();
    let mut system_enabled = HashMap::new();
    let mut system_profile = HashMap::new();
    let mut system_demask = HashMap::new();
    let mut system_rate_limit = HashMap::new();
    let mut system_overrides = HashMap::new();
    let mut system_route_overrides = HashMap::new();
    for (id, sc) in &cfg.systems {
        let key_hex = resolve_secret(&sc.key_sha256)?;
        system_keys.insert(id.clone(), key_hex.clone());
        // PERF-06: декодируем hex в 32 сырых байта один раз.
        if let Some(bytes) = decode_hex32(&key_hex) {
            system_key_bytes.insert(id.clone(), bytes);
        }
        system_enabled.insert(id.clone(), sc.enabled);
        system_profile.insert(id.clone(), sc.profile.clone());
        system_demask.insert(id.clone(), sc.demask);
        if let Some(rl) = sc.rate_limit_rps {
            system_rate_limit.insert(id.clone(), rl);
        }
        if let Some(o) = &sc.overrides {
            system_overrides.insert(id.clone(), o.clone());
        }
        system_route_overrides.insert(id.clone(), sc.route_overrides.clone());
    }

    let placeholder_format = cfg.defaults.placeholder.format.clone();
    let default_action = cfg.defaults.action.clone();

    let mut compiled = CompiledConfig {
        version: 1,
        raw: cfg.clone(),
        detector_regexes,
        detector_value_groups,
        detector_base_scores,
        detector_context,
        context_ac,
        prefilter_regex_set,
        first_names,
        public_persons,
        bank_offices,
        bank_phones,
        countries,
        cities,
        issuing_authorities,
        policies: HashMap::new(),
        labels,
        priorities,
        thresholds,
        master_key_b64,
        admin_token_sha256,
        system_keys,
        system_key_bytes,
        system_enabled,
        system_profile,
        system_demask,
        system_rate_limit,
        system_overrides,
        system_route_overrides,
        profiles: cfg.profiles.clone(),
        defaults: cfg.defaults.clone(),
        upstreams: cfg.upstreams.clone(),
        routes: cfg.routes.clone(),
        placeholder_format,
        default_action,
    };

    // PERF-05: предвычисляем эффективные политики для всех (система × маршрут).
    let mut policies: HashMap<(String, Option<String>), Arc<EffectivePolicy>> = HashMap::new();
    for system_id in compiled.system_enabled.keys() {
        // Без маршрута.
        if let Ok(p) = resolve_policy(&compiled, system_id, None) {
            policies.insert((system_id.clone(), None), p);
        }
        // С каждым маршрутом.
        for route in &compiled.routes {
            if let Ok(p) = resolve_policy(&compiled, system_id, Some(&route.id)) {
                policies.insert((system_id.clone(), Some(route.id.clone())), p);
            }
        }
    }
    compiled.policies = policies;

    Ok(compiled)
}

fn validate(cfg: &Config) -> Result<(), ConfigError> {
    // Типы в профилях объявлены в pd_types.
    for (pname, p) in &cfg.profiles {
        for t in p.types.keys() {
            if !cfg.pd_types.contains_key(t) {
                return Err(ConfigError::Validation {
                    path: format!("profiles.{}.types.{}", pname, t),
                    msg: "type not declared in pd_types".into(),
                });
            }
        }
    }
    // profile ссылается на существующий.
    for (sid, sc) in &cfg.systems {
        if !sc.profile.is_empty() && !cfg.profiles.contains_key(&sc.profile) {
            return Err(ConfigError::Validation {
                path: format!("systems.{}.profile", sid),
                msg: format!("unknown profile '{}'", sc.profile),
            });
        }
    }
    if !cfg.defaults.profile.is_empty() && !cfg.profiles.contains_key(&cfg.defaults.profile) {
        return Err(ConfigError::Validation {
            path: "defaults.profile".into(),
            msg: format!("unknown profile '{}'", cfg.defaults.profile),
        });
    }
    // upstream ссылается на существующий.
    for r in &cfg.routes {
        if !r.upstream.is_empty() && !cfg.upstreams.contains_key(&r.upstream) {
            return Err(ConfigError::Validation {
                path: format!("routes.{}.upstream", r.id),
                msg: format!("unknown upstream '{}'", r.upstream),
            });
        }
    }
    // Нет двух одинаковых match без различающего условия.
    for (i, a) in cfg.routes.iter().enumerate() {
        for b in cfg.routes.iter().skip(i + 1) {
            if a.r#match.method == b.r#match.method
                && a.r#match.path == b.r#match.path
                && a.r#match.path_prefix == b.r#match.path_prefix
                && a.r#match.header == b.r#match.header
            {
                return Err(ConfigError::Validation {
                    path: format!("routes[{}] vs routes[{}]", i, i + 1),
                    msg: "duplicate route match without distinguishing condition".into(),
                });
            }
        }
    }
    Ok(())
}

fn load_lines(path: &str, base_dir: &Path) -> Result<Vec<String>, ConfigError> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let full = resolve_path(path, base_dir);
    let content = std::fs::read_to_string(&full)
        .map_err(|e| ConfigError::Resource(format!("{}: {e}", full.display())))?;
    Ok(content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

fn load_pipe_lines(path: &str, base_dir: &Path) -> Result<Vec<Vec<String>>, ConfigError> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let full = resolve_path(path, base_dir);
    let content = std::fs::read_to_string(&full)
        .map_err(|e| ConfigError::Resource(format!("{}: {e}", full.display())))?;
    Ok(content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split('|').map(|s| s.trim().to_string()).collect())
        .collect())
}

fn resolve_path(path: &str, base_dir: &Path) -> std::path::PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

/// Разрешает ссылку `env:VAR` или `file:/path` или возвращает как есть.
pub fn resolve_secret(s: &str) -> Result<String, ConfigError> {
    if let Some(var) = s.strip_prefix("env:") {
        std::env::var(var)
            .map_err(|_| ConfigError::Validation {
                path: "secret".into(),
                msg: format!("env var {var} not set"),
            })
    } else if let Some(path) = s.strip_prefix("file:") {
        std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .map_err(|e| ConfigError::Validation {
                path: "secret".into(),
                msg: format!("cannot read secret file {path}: {e}"),
            })
    } else {
        Ok(s.to_string())
    }
}

/// Декодирует hex-строку в 32 байта (для ключей систем). Возвращает None при неверной длине.
fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// PolicyResolver: (system, route) → EffectivePolicy.
pub fn resolve_policy(
    cfg: &CompiledConfig,
    system_id: &str,
    route_id: Option<&str>,
) -> Result<Arc<EffectivePolicy>, PolicyError> {
    let enabled = cfg.system_enabled.get(system_id).copied().unwrap_or(false);
    if !cfg.system_enabled.contains_key(system_id) {
        return Err(PolicyError::UnknownSystem);
    }
    if !enabled {
        return Err(PolicyError::SystemDisabled);
    }

    // Проверка route.systems.
    if let Some(rid) = route_id {
        if let Some(route) = cfg.routes.iter().find(|r| r.id == rid) {
            if !route.systems.is_empty() && !route.systems.iter().any(|s| s == system_id) {
                return Err(PolicyError::RouteForbidden);
            }
        }
    }

    // Выбор профиля.
    let route_profile_override = route_id
        .and_then(|rid| cfg.routes.iter().find(|r| r.id == rid))
        .and_then(|r| r.request.profile_override.clone());
    let sys_profile = cfg.system_profile.get(system_id).cloned().unwrap_or_default();
    let base_profile = route_profile_override
        .or(if sys_profile.is_empty() { None } else { Some(sys_profile) })
        .or_else(|| if cfg.defaults.profile.is_empty() { None } else { Some(cfg.defaults.profile.clone()) })
        .unwrap_or_default();

    let mut p = cfg
        .profiles
        .get(&base_profile)
        .cloned()
        .unwrap_or_default();

    // deep_merge(sys.overrides)
    if let Some(ov) = cfg.system_overrides.get(system_id) {
        deep_merge_profile(&mut p, ov);
    }

    // deep_merge(route.types_override)
    if let Some(rid) = route_id {
        if let Some(route) = cfg.routes.iter().find(|r| r.id == rid) {
            for (t, tm) in &route.request.types_override {
                p.types.insert(t.clone(), tm.clone());
            }
        }
    }

    // deep_merge(sys.route_overrides[route.id])
    if let Some(rid) = route_id {
        if let Some(ro) = cfg.system_route_overrides.get(system_id).and_then(|m| m.get(rid)) {
            for (t, tm) in &ro.types {
                p.types.insert(t.clone(), tm.clone());
            }
            if let Some(c) = &ro.combination {
                p.combination = c.clone();
            }
            if let Some(d) = ro.demask {
                p.demask = Some(d);
            }
        }
    }

    // demask = route.response.demask && sys.demask && p.demask
    let route_demask = route_id
        .and_then(|rid| cfg.routes.iter().find(|r| r.id == rid))
        .map(|r| r.response.demask)
        .unwrap_or(true);
    let sys_demask = cfg.system_demask.get(system_id).copied().unwrap_or(false);
    let p_demask = p.demask.unwrap_or(true);
    let demask = route_demask && sys_demask && p_demask;

    // action
    let route_action = route_id
        .and_then(|rid| cfg.routes.iter().find(|r| r.id == rid))
        .and_then(|r| r.action.clone());
    let action = route_action.unwrap_or_else(|| cfg.default_action.clone());

    let ep = build_effective(cfg, p, demask, &action);
    Ok(Arc::new(ep))
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("unknown system")]
    UnknownSystem,
    #[error("system disabled")]
    SystemDisabled,
    #[error("route forbidden for system")]
    RouteForbidden,
}

fn deep_merge_profile(base: &mut ProfileConfig, ov: &ProfileConfig) {
    for (t, tm) in &ov.types {
        if tm.disabled == Some(true) {
            base.types.remove(t);
        } else {
            base.types.insert(t.clone(), tm.clone());
        }
    }
    if ov.ner.enabled {
        base.ner.enabled = true;
    }
    if !ov.ner.types.is_empty() {
        base.ner.types = ov.ner.types.clone();
    }
    if let Some(of) = &ov.ner.on_failure {
        base.ner.on_failure = Some(of.clone());
    }
    if !ov.filters.is_empty() {
        base.filters = ov.filters.clone();
    }
    if ov.combination.min_distinct_types != 0 {
        base.combination.min_distinct_types = ov.combination.min_distinct_types;
    }
    if !ov.combination.always_mask.is_empty() {
        base.combination.always_mask = ov.combination.always_mask.clone();
    }
    for (t, r) in &ov.combination.rules {
        if r.is_none() {
            base.combination.rules.remove(t);
        } else {
            base.combination.rules.insert(t.clone(), r.clone());
        }
    }
    if let Some(a) = &ov.ambiguous_ids {
        base.ambiguous_ids = Some(a.clone());
    }
    if let Some(d) = ov.demask {
        base.demask = Some(d);
    }
}

fn build_effective(
    cfg: &CompiledConfig,
    p: ProfileConfig,
    demask: bool,
    action: &str,
) -> EffectivePolicy {
    let mut ep = EffectivePolicy {
        action: match action {
            "bypass" => PolicyAction::Bypass,
            "block" => PolicyAction::Block,
            _ => PolicyAction::Mask,
        },
        demask,
        placeholder_format: cfg.placeholder_format.clone(),
        labels: cfg.labels.clone(),
        thresholds: cfg.thresholds.clone(),
        priorities: cfg.priorities.clone(),
        ner_enabled: p.ner.enabled,
        ner_types: p.ner.types.clone(),
        ner_on_failure: match p.ner.on_failure.as_deref() {
            Some("fail") => NerOnFailure::Fail,
            _ => NerOnFailure::Degrade,
        },
        max_windows_per_request: cfg.raw.ner.max_windows_per_request,
        trigger_words: cfg.raw.ner.trigger_words.clone(),
        filters: p.filters.clone(),
        ambiguous_ids: match p.ambiguous_ids.as_deref() {
            Some("mask") => AmbiguousIdsMode::Mask,
            _ => AmbiguousIdsMode::Skip,
        },
        combination: CombinationConfig {
            rules: p
                .combination
                .rules
                .iter()
                .filter_map(|(t, r)| {
                    let r = r.as_ref()?;
                    Some((
                        t.clone(),
                        CombinationRuleConfig {
                            requires_any: r.requires_any.clone(),
                            requires_all: r.requires_all.clone(),
                            scope: match r.scope.as_deref() {
                                Some("window") => CombinationScope::Window,
                                _ => CombinationScope::Document,
                            },
                            window_chars: r.window_chars,
                        },
                    ))
                })
                .collect(),
            min_distinct_types: p.combination.min_distinct_types,
            always_mask: p.combination.always_mask.clone(),
        },
        ..Default::default()
    };

    for (t, tm) in &p.types {
        if tm.disabled == Some(true) {
            continue;
        }
        ep.types.push(t.clone());
        let kind = match tm.mask.as_deref() {
            Some("redact") => MaskKind::Redact,
            Some("partial") => MaskKind::Partial,
            Some("token") => MaskKind::Token,
            Some("synthetic") => MaskKind::Synthetic,
            Some("hash") => MaskKind::Hash,
            _ => MaskKind::Placeholder,
        };
        ep.mask_kinds.insert(t.clone(), kind);
        if let Some(mode) = &tm.mode {
            if mode == "components" {
                ep.address_mode = AddressMode::Components;
            }
        }
    }

    enable_address_components(&mut ep);
    ep
}

/// В режиме components ADDRESS разворачивается в ADDR_*, поэтому компоненты
/// должны попасть в список разрешённых типов: иначе конвейер отбросит их
/// вместе со всеми типами, которых нет в профиле.
pub fn enable_address_components(ep: &mut EffectivePolicy) {
    if ep.address_mode != AddressMode::Components {
        return;
    }
    let address = PdType::new(PdType::ADDRESS);
    if !ep.types.contains(&address) {
        return;
    }
    let kind = ep
        .mask_kinds
        .get(&address)
        .copied()
        .unwrap_or(MaskKind::Placeholder);
    for name in [
        PdType::ADDR_COUNTRY,
        PdType::ADDR_INDEX,
        PdType::ADDR_REGION,
        PdType::ADDR_CITY,
        PdType::ADDR_STREET,
        PdType::ADDR_HOUSE,
        PdType::ADDR_FLAT,
    ] {
        let t = PdType::new(name);
        if !ep.types.contains(&t) {
            ep.types.push(t.clone());
        }
        ep.mask_kinds.entry(t).or_insert(kind);
    }
}

/// Применяет deep_merge к EffectivePolicy (для route.types_override уже сделано на уровне ProfileConfig).
pub fn merge_type_mask(ep: &mut EffectivePolicy, t: &PdType, tm: &TypeMaskConfig) {
    if tm.disabled == Some(true) {
        ep.types.retain(|x| x != t);
        ep.mask_kinds.remove(t);
        return;
    }
    if !ep.types.contains(t) {
        ep.types.push(t.clone());
    }
    if let Some(mask) = &tm.mask {
        let kind = match mask.as_str() {
            "redact" => MaskKind::Redact,
            "partial" => MaskKind::Partial,
            "token" => MaskKind::Token,
            "synthetic" => MaskKind::Synthetic,
            "hash" => MaskKind::Hash,
            _ => MaskKind::Placeholder,
        };
        ep.mask_kinds.insert(t.clone(), kind);
    }
    if let Some(mode) = &tm.mode {
        if mode == "components" {
            ep.address_mode = AddressMode::Components;
            enable_address_components(ep);
        }
    }
}