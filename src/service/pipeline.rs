//! Конвейер обработки: маскирование и демаскирование.

use std::sync::Arc;
use std::time::Instant;

use crate::domain::document::Document;
use crate::domain::entity::{Candidate, Entity, MaskRecord, MaskState};
use crate::domain::pd_type::PdType;
use crate::domain::traits::{
    AddressMode, CombinationRule, ContextScorer, DetectCtx, Detector, EffectivePolicy, Masker,
    MaskKind, NerEngine, RelevanceFilter, Resolver, Validator,
};

use super::demask::{demask, Mapping};
use super::resolve::canonical_from_original;

/// Результат маскирования одной строки.
pub struct MaskLineResult {
    pub text: String,
    pub entities: Vec<MaskedEntityInfo>,
    pub records: Vec<MaskRecord>,
    pub degraded: bool,
    pub ner_failed: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MaskedEntityInfo {
    pub pd_type: String,
    pub start: usize,
    pub end: usize,
    pub masked_start: usize,
    pub masked_end: usize,
    pub replacement: String,
    pub score: f32,
    pub source: String,
}

/// Контекст конвейера: все компоненты.
pub struct PipelineCtx {
    pub detectors: Vec<Arc<dyn Detector>>,
    pub validators: Vec<Arc<dyn Validator>>,
    pub context_scorers: Vec<Arc<dyn ContextScorer>>,
    pub ner: Option<Arc<dyn NerEngine>>,
    pub filters: Vec<Arc<dyn RelevanceFilter>>,
    pub resolver: Arc<dyn Resolver>,
    pub combination: Arc<dyn CombinationRule>,
    pub maskers_by_kind: std::collections::HashMap<MaskKind, Arc<dyn Masker>>,
    pub default_masker: Arc<dyn Masker>,
    /// PERF-11: RegexSet по паттернам конфиг-детекторов (для префильтра).
    pub prefilter_regex_set: Option<regex::RegexSet>,
}

/// Маскирует одну строку.
pub async fn mask_line(
    ctx: &PipelineCtx,
    policy: &EffectivePolicy,
    original: &str,
    state: &mut MaskState,
    deadline: Instant,
) -> MaskLineResult {
    // PERF-12: ранний выход для текста без признаков ПД.
    if !has_pd_signal(original) {
        return MaskLineResult {
            text: original.to_string(),
            entities: Vec::new(),
            records: Vec::new(),
            degraded: false,
            ner_failed: false,
        };
    }

    let doc = Document::new(original);
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut degraded = false;

    // Stage A — детерминированные детекторы.
    // PERF-11: префильтр — RegexSet по паттернам конфиг-детекторов.
    let mut detect_ctx = DetectCtx::default();
    if let Some(regex_set) = &ctx.prefilter_regex_set {
        let matches = regex_set.matches(&doc.norm);
        // Индексы конфиг-детекторов (id == "config_regex"), чьи паттерны сматчились.
        for (i, d) in ctx.detectors.iter().enumerate() {
            if d.id() == "config_regex" && matches.matched_any() {
                detect_ctx.active_detectors.push(i);
            }
        }
    }
    for (i, d) in ctx.detectors.iter().enumerate() {
        // PERF-22: проверка дедлайна между стадиями.
        if Instant::now() >= deadline {
            degraded = true;
            break;
        }
        // Только типы из политики (но ORG_INN участвует в разрешении).
        let relevant = d
            .types()
            .iter()
            .any(|t| policy.types.contains(t) || t.as_str() == PdType::ORG_INN);
        if !relevant {
            continue;
        }
        // PERF-11: пропускаем конфиг-детекторы, чьи паттерны не сматчились.
        if d.id() == "config_regex" && !detect_ctx.active_detectors.contains(&i) {
            continue;
        }
        d.detect(&doc, &detect_ctx, &mut candidates);
    }

    // Валидаторы уже применены внутри детекторов (score/отбрасывание).

    // Stage B — NER.
    let mut ner_failed = false;
    if policy.ner_enabled {
        if let Some(ner) = &ctx.ner {
            if Instant::now() < deadline {
                // Окна: предложения с сигналами.
                let windows = select_ner_windows(&doc, policy);
                if !windows.is_empty() {
                    let text = doc.original.to_string();
                    let wins = windows.clone();
                    match ner.recognize(&text, &wins, deadline).await {
                        Ok(mut ner_cands) => {
                            candidates.append(&mut ner_cands);
                        }
                        Err(_) => {
                            degraded = true;
                            ner_failed = true;
                        }
                    }
                }
            }
        }
    }

    // Relevance-фильтры (только те, что указаны в политике).
    // PERF-09: фильтрам передаётся срез исходных кандидатов, без клонирования всего вектора.
    let active_filters: Vec<&Arc<dyn RelevanceFilter>> = if policy.filters.is_empty() {
        ctx.filters.iter().collect()
    } else {
        ctx.filters
            .iter()
            .filter(|f| policy.filters.iter().any(|id| id == f.id()))
            .collect()
    };
    let all_candidates = std::mem::take(&mut candidates);
    candidates = all_candidates
        .iter()
        .filter(|c| active_filters.iter().all(|f| f.keep(&doc, c, &all_candidates)))
        .cloned()
        .collect();

    // PERF-22: дедлайн перед resolver.
    if Instant::now() >= deadline {
        degraded = true;
    }

    // Resolver.
    let mut entities = ctx.resolver.resolve(candidates, policy);

    // Combination rules.
    ctx.combination.apply(&mut entities, policy);

    // Если address_mode == Components, разворачиваем ADDRESS в его компоненты.
    if policy.address_mode == AddressMode::Components {
        let mut expanded: Vec<Entity> = Vec::new();
        for e in entities.drain(..) {
            if e.pd_type.as_str() == PdType::ADDRESS && !e.components.is_empty() {
                for comp in e.components {
                    expanded.push(comp);
                }
            } else {
                expanded.push(e);
            }
        }
        entities = expanded;
    }

    // Профиль решает, что маскировать: детектор может породить тип, которого в
    // профиле нет (ORG_INN и DATE участвуют в разрешении конфликтов, но сами по
    // себе не маскируются), поэтому лишнее отбрасываем перед маскированием.
    entities.retain(|e| policy.types.contains(&e.pd_type));

    // Вычислить canonical для каждой сущности.
    for e in entities.iter_mut() {
        let orig = doc.original_slice(e.span);
        let canon = canonical_from_original(orig, &e.pd_type);
        e.canonical = crate::domain::sensitive::Sensitive::new(canon);
    }

    // Маскирование одним проходом.
    let mut text = String::with_capacity(original.len());
    let mut cursor = 0usize;
    let mut records = Vec::new();
    let mut masked_entities = Vec::new();

    entities.sort_by_key(|e| e.span.start);
    for e in &entities {
        if e.span.start < cursor {
            continue;
        }
        let orig = doc.original_slice(e.span);
        let kind = policy
            .mask_kinds
            .get(&e.pd_type)
            .copied()
            .unwrap_or(MaskKind::Placeholder);
        let masker = ctx
            .maskers_by_kind
            .get(&kind)
            .unwrap_or(&ctx.default_masker);
        let out = masker.mask(e, orig, state);

        text.push_str(&original[cursor..e.span.start]);
        let masked_start = text.len();
        text.push_str(&out.replacement);
        let masked_end = text.len();
        cursor = e.span.end;

        if let Some(key) = &out.key {
            records.push(MaskRecord {
                masked_span: crate::domain::document::Span::new(masked_start, masked_end),
                original_span: e.span,
                pd_type: e.pd_type.clone(),
                key: Some(key.clone()),
            });
        }

        masked_entities.push(MaskedEntityInfo {
            pd_type: e.pd_type.as_str().to_string(),
            start: e.span.start,
            end: e.span.end,
            masked_start,
            masked_end,
            replacement: out.replacement,
            score: e.score,
            source: e.source.kind().to_string(),
        });
    }
    text.push_str(&original[cursor..]);

    // DET-06: самопроверка — прогоняем детекторы по уже маскированному тексту.
    // Любая находка инкрементирует метрику утечки.
    self_check(ctx, policy, &text);

    MaskLineResult {
        text,
        entities: masked_entities,
        records,
        degraded,
        ner_failed,
    }
}

/// PERF-12: быстрая проверка наличия признаков ПД в тексте.
/// Если нет цифр, '@', заглавных букв и контекстных слов — ПД нет.
fn has_pd_signal(text: &str) -> bool {
    let mut has_digit = false;
    let mut has_at = false;
    let mut has_upper = false;
    for c in text.chars() {
        if c.is_ascii_digit() {
            has_digit = true;
        } else if c == '@' {
            has_at = true;
        } else if c.is_uppercase() {
            has_upper = true;
        }
        if has_digit && has_at && has_upper {
            return true;
        }
    }
    // Контекстные слова (регистронезависимо).
    if has_upper {
        let lower = text.to_lowercase();
        const TRIGGERS: &[&str] = &[
            "паспорт", "серия", "телефон", "клиент", "гражданин", "инн", "снилс", "карта",
            "пин", "cvv", "email", "адрес", "проживает", "родился", "родилась", "выдан",
            "водительск", "держатель", "фио", "дата рождения",
        ];
        if TRIGGERS.iter().any(|w| lower.contains(w)) {
            return true;
        }
    }
    has_digit || has_at || has_upper
}

/// DET-06: повторный прогон детекторов по маскированному тексту.
fn self_check(ctx: &PipelineCtx, policy: &EffectivePolicy, masked: &str) {
    let doc = Document::new(masked);
    let detect_ctx = DetectCtx::default();
    let mut leaks: Vec<Candidate> = Vec::new();
    for d in &ctx.detectors {
        let relevant = d
            .types()
            .iter()
            .any(|t| policy.types.contains(t) || t.as_str() == PdType::ORG_INN);
        if !relevant {
            continue;
        }
        d.detect(&doc, &detect_ctx, &mut leaks);
    }
    for c in leaks {
        crate::infra::metrics::inc_leak_detected(c.pd_type.as_str());
    }
}

/// Выбирает окна для NER (gated NER): только предложения с сигналами.
fn select_ner_windows(
    doc: &Document<'_>,
    policy: &EffectivePolicy,
) -> Vec<crate::domain::document::Span> {
    let mut windows = Vec::new();
    let norm = &doc.norm;
    let mut start = 0usize;
    let mut sentences: Vec<(usize, usize)> = Vec::new();
    for (i, ch) in norm.char_indices() {
        if matches!(ch, '.' | '!' | '?' | '\n') {
            let end = i + ch.len_utf8();
            if end > start {
                sentences.push((start, end));
            }
            start = end;
        }
    }
    if start < norm.len() {
        sentences.push((start, norm.len()));
    }

    // Фильтр по сигналам.
    for (s, e) in sentences {
        let sentence = &norm[s..e];
        let has_signal = has_ner_signal(doc, sentence, s);
        if has_signal {
            windows.push(crate::domain::document::Span::new(s, e));
        }
    }

    // Ограничение по max_windows (OPS-04: из конфига).
    let max_windows = if policy.max_windows_per_request > 0 {
        policy.max_windows_per_request
    } else {
        policy.ner_types.len().max(1) * 64
    };
    if windows.len() > max_windows {
        windows.truncate(max_windows);
    }
    windows
}

/// Проверяет, есть ли в предложении сигнал для NER.
fn has_ner_signal(doc: &Document<'_>, sentence: &str, norm_start: usize) -> bool {
    // Слово с заглавной в оригинале (не в начале предложения).
    let orig = doc.original_slice(doc.to_original(norm_start, norm_start + sentence.len()));
    let words: Vec<&str> = orig.split_whitespace().collect();
    for (i, w) in words.iter().enumerate() {
        if i > 0 && w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            return true;
        }
    }
    // Контекстные слова.
    let trigger = ["клиент", "зовут", "проживает", "уроженец", "гражданин", "заявитель", "родился", "родилась"];
    if trigger.iter().any(|w| sentence.contains(w)) {
        return true;
    }
    false
}

/// Демаскирует строку.
pub fn demask_line(text: &str, mapping: &Mapping) -> super::demask::DemaskResult {
    demask(text, mapping)
}