//! Разрешение пересечений и приоритетов.

use crate::domain::entity::{Candidate, Entity, SignalFlags};
use crate::domain::pd_type::PdType;
use crate::domain::sensitive::Sensitive;
use crate::domain::traits::{EffectivePolicy, Resolver};

/// Стандартный резолвер.
pub struct DefaultResolver;

impl Resolver for DefaultResolver {
    fn resolve(&self, cands: Vec<Candidate>, policy: &EffectivePolicy) -> Vec<Entity> {
        // 1. Отбросить кандидатов со score < порог типа.
        let mut cands: Vec<Candidate> = cands
            .into_iter()
            .filter(|c| {
                let threshold = policy.thresholds.get(&c.pd_type).copied().unwrap_or(0.6);
                c.score >= threshold
            })
            .collect();

        // 2. Сортировка по start.
        cands.sort_by(|a, b| a.span.start.cmp(&b.span.start));

        // 3. Разрешение пересечений (PERF-17: свип по отсортированным кандидатам).
        //    Кандидаты отсортированы по start; выбранные не пересекаются, поэтому
        //    новый кандидат может пересекаться только с последним выбранным.
        let mut selected: Vec<Candidate> = Vec::new();
        for cand in cands {
            if let Some(last) = selected.last_mut() {
                if last.span.overlaps(&cand.span) {
                    // Составная сущность поглощает компоненты.
                    if last.pd_type.as_str() == PdType::ADDRESS
                        && cand.components.iter().any(|c| c.span.overlaps(&last.span))
                    {
                        continue;
                    }
                    if a_wins(&cand, last, policy) {
                        *last = cand;
                    }
                    continue;
                }
            }
            selected.push(cand);
        }

        // 4. Преобразование в Entity.
        selected
            .into_iter()
            .map(|c| to_entity(c, policy))
            .collect()
    }
}

/// Возвращает true, если a выигрывает у b.
fn a_wins(a: &Candidate, b: &Candidate, policy: &EffectivePolicy) -> bool {
    let a_checksum = a.signals.contains(SignalFlags::CHECKSUM_OK);
    let b_checksum = b.signals.contains(SignalFlags::CHECKSUM_OK);
    if a_checksum != b_checksum {
        return a_checksum;
    }
    let a_prio = policy.priorities.get(&a.pd_type).copied().unwrap_or(50);
    let b_prio = policy.priorities.get(&b.pd_type).copied().unwrap_or(50);
    if a_prio != b_prio {
        return a_prio > b_prio;
    }
    if (a.score - b.score).abs() > f32::EPSILON {
        return a.score > b.score;
    }
    a.span.len() > b.span.len()
}

fn to_entity(c: Candidate, policy: &EffectivePolicy) -> Entity {
    let canonical = canonicalize(&c, policy);
    Entity {
        pd_type: c.pd_type,
        span: c.span,
        score: c.score,
        source: c.source,
        components: c.components.into_iter().map(|cc| to_entity(cc, policy)).collect(),
        canonical: Sensitive::new(canonical),
    }
}

/// Каноническая форма (заполняется в pipeline с доступом к original).
pub fn canonicalize(_c: &Candidate, _policy: &EffectivePolicy) -> String {
    String::new()
}

/// Вычисляет canonical из original-среза.
pub fn canonical_from_original(original: &str, pd_type: &PdType) -> String {
    match pd_type.as_str() {
        PdType::CARD_NUMBER | PdType::INN | PdType::ORG_INN | PdType::SNILS | PdType::PHONE => {
            original.chars().filter(|c| c.is_ascii_digit()).collect()
        }
        PdType::FIO | PdType::CARD_HOLDER => {
            original.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
        }
        _ => original.to_lowercase(),
    }
}