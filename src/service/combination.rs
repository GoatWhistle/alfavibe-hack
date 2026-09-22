//! Правила совместного появления типов.

use crate::domain::entity::Entity;
use crate::domain::traits::{CombinationRule, CombinationScope, EffectivePolicy};

/// Стандартное правило совместного появления.
pub struct DefaultCombinationRule;

impl CombinationRule for DefaultCombinationRule {
    fn apply(&self, entities: &mut Vec<Entity>, policy: &EffectivePolicy) {
        // Собрать множество типов документа.
        let doc_types: std::collections::HashSet<String> =
            entities.iter().map(|e| e.pd_type.as_str().to_string()).collect();

        // min_distinct_types
        if policy.combination.min_distinct_types > 0 {
            let distinct = doc_types.len();
            if distinct < policy.combination.min_distinct_types {
                entities.retain(|e| {
                    policy
                        .combination
                        .always_mask
                        .iter()
                        .any(|t| t.as_str() == e.pd_type.as_str())
                });
                return;
            }
        }

        // Правила по типам.
        let snapshot = entities.clone();
        let kept: Vec<Entity> = entities
            .drain(..)
            .filter(|e| {
                let Some(rule) = policy.combination.rules.get(&e.pd_type) else {
                    return true;
                };
                let satisfied = match rule.scope {
                    CombinationScope::Document => {
                        let any_ok = rule.requires_any.is_empty()
                            || rule
                                .requires_any
                                .iter()
                                .any(|t| doc_types.contains(t.as_str()));
                        let all_ok = rule
                            .requires_all
                            .iter()
                            .all(|t| doc_types.contains(t.as_str()));
                        any_ok && all_ok
                    }
                    CombinationScope::Window => {
                        let any_ok = rule.requires_any.is_empty()
                            || rule.requires_any.iter().any(|t| {
                                snapshot.iter().any(|other| {
                                    other.pd_type.as_str() == t.as_str()
                                        && window_overlap(e, other, rule.window_chars)
                                })
                            });
                        let all_ok = rule.requires_all.iter().all(|t| {
                            snapshot.iter().any(|other| {
                                other.pd_type.as_str() == t.as_str()
                                    && window_overlap(e, other, rule.window_chars)
                            })
                        });
                        any_ok && all_ok
                    }
                };
                satisfied
            })
            .collect();
        *entities = kept;
    }
}

fn window_overlap(a: &Entity, b: &Entity, window_chars: usize) -> bool {
    let a_start = a.span.start;
    let b_start = b.span.start;
    a_start.abs_diff(b_start) <= window_chars
}