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
}

/// Маскирует одну строку.
pub async fn mask_line(
    ctx: &PipelineCtx,
    policy: &EffectivePolicy,
    original: &str,
    state: &mut MaskState,
    deadline: Instant,
) -> MaskLineResult {
    let doc = Document::new(original);
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut degraded = false;

    // Stage A — детерминированные детекторы.
    let detect_ctx = DetectCtx::default();
    for d in &ctx.detectors {
        // Только типы из политики (но ORG_INN участвует в разрешении).
        let relevant = d
            .types()
            .iter()
            .any(|t| policy.types.contains(t) || t.as_str() == PdType::ORG_INN);
        if !relevant {
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
    let all_candidates = candidates.clone();
    let active_filters: Vec<&Arc<dyn RelevanceFilter>> = if policy.filters.is_empty() {
        ctx.filters.iter().collect()
    } else {
        ctx.filters
            .iter()
            .filter(|f| policy.filters.iter().any(|id| id == f.id()))
            .collect()
    };
    candidates.retain(|c| {
        active_filters
            .iter()
            .all(|f| f.keep(&doc, c, &all_candidates))
    });

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

    MaskLineResult {
        text,
        entities: masked_entities,
        records,
        degraded,
        ner_failed,
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

    // Ограничение по max_windows.
    if windows.len() > policy.ner_types.len().max(1) * 64 {
        windows.truncate(64);
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