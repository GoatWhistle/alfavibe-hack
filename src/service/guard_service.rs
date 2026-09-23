//! GuardService — фасад: mask(), demask(), process_proxy().

use std::sync::Arc;
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::domain::entity::MaskState;
use crate::domain::errors::VaultError;
use crate::domain::traits::{EffectivePolicy, LlmClient, Vault};

use super::demask::Mapping;
use super::pipeline::{demask_line, mask_line, PipelineCtx};

/// Результат маскирования.
pub struct MaskResult {
    pub text: String,
    pub session_id: String,
    pub entities: Vec<super::pipeline::MaskedEntityInfo>,
    pub degraded: bool,
    pub mask_context: Option<String>,
    pub mapping: Mapping,
}

/// Чем закончилась обработка по контракту Приложения A.
pub enum TzOutcome {
    /// Прямой шаг: payload_id встретился впервые, текст замаскирован.
    Masked(MaskResult),
    /// Обратный шаг: вернули исходную строку.
    Restored { text: String, restored: usize },
    /// Ретрай прямого шага с тем же payload_id — отвечаем тем же результатом.
    Repeated(String),
}

impl TzOutcome {
    pub fn text(&self) -> &str {
        match self {
            TzOutcome::Masked(m) => &m.text,
            TzOutcome::Restored { text, .. } => text,
            TzOutcome::Repeated(text) => text,
        }
    }

    pub fn step(&self) -> &'static str {
        match self {
            TzOutcome::Masked(_) => "mask",
            TzOutcome::Restored { .. } => "demask",
            TzOutcome::Repeated(_) => "mask_retry",
        }
    }
}

/// Результат демаскирования.
pub struct DemaskResult {
    pub text: String,
    pub restored: usize,
    pub unresolved: usize,
    pub degraded: bool,
}

/// Фасад сервиса.
pub struct GuardService {
    pub pipeline: Arc<PipelineCtx>,
    pub vault: Arc<dyn Vault>,
    pub llm: Option<Arc<dyn LlmClient>>,
    pub master_key: crate::infra::crypto::MasterKey,
    pub vault_mode: String,
    pub ttl: Duration,
    pub delete_after_demask: bool,
    /// PERF-20: тексты длиннее этого порога обрабатываются вне реактора.
    pub heavy_text_threshold_bytes: usize,
}

impl GuardService {
    /// Маскирует текст.
    pub async fn mask(
        &self,
        policy: &EffectivePolicy,
        system_id: &str,
        text: &str,
        session_id: Option<&str>,
        deadline: Instant,
        dry_run: bool,
    ) -> Result<MaskResult, VaultError> {
        let session = session_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::now_v7().to_string());

        let mut state = MaskState::default();
        // PERF-20: тяжёлые тексты обрабатываются вне реактора (spawn_blocking).
        let result = if text.len() > self.heavy_text_threshold_bytes {
            let pipeline = self.pipeline.clone();
            let policy = policy.clone();
            let text = text.to_string();
            tokio::task::spawn_blocking(move || {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(async {
                    let mut state = MaskState::default();
                    mask_line(&pipeline, &policy, &text, &mut state, deadline).await
                })
            })
            .await
            .map_err(|e| VaultError::Unavailable(format!("heavy task panicked: {e}")))?
        } else {
            mask_line(&self.pipeline, policy, text, &mut state, deadline).await
        };

        // FEAT-05: dry_run — возвращаем перечень того, что было бы замаскировано,
        // без изменения текста и без записи маппинга.
        if dry_run {
            return Ok(MaskResult {
                text: text.to_string(),
                session_id: session,
                entities: result.entities,
                degraded: result.degraded,
                mask_context: None,
                mapping: Mapping::default(),
            });
        }

        // Если NER недоступен и политика требует fail — возвращаем ошибку.
        if result.ner_failed && policy.ner_on_failure == crate::domain::traits::NerOnFailure::Fail {
            return Err(VaultError::Unavailable("NER unavailable and policy requires fail".into()));
        }

        // Собрать mapping.
        let mut entries = Vec::new();
        for r in &result.records {
            let orig = &text[r.original_span.start..r.original_span.end];
            let masked = if r.masked_span.start < r.masked_span.end {
                Some(result.text[r.masked_span.start..r.masked_span.end].to_string())
            } else {
                None
            };
            entries.push(super::demask::MappingEntry {
                key: r.key.clone().unwrap_or_default(),
                pd_type: r.pd_type.as_str().to_string(),
                original: orig.to_string(),
                masked,
            });
        }
        let mapping = Mapping {
            entries,
            original: text.to_string(),
            masked: result.text.clone(),
        };

        // Сессию заводим всегда, когда разрешено демаскирование, даже если ПД не
        // нашлось: обратный шаг приходит на каждый payload_id и должен получить
        // 200 с исходной строкой, а не session_not_found.
        let needs_vault = policy.demask;
        let mut mask_context = None;
        if needs_vault {
            let bytes = mapping.to_bytes()?;
            let enc = crate::infra::crypto::encrypt_mapping(
                &self.master_key,
                &session,
                system_id,
                &bytes,
            )?;
            if self.vault_mode == "stateless" {
                // Сохраняем nonce || ciphertext (nonce 12 байт).
                let mut payload = Vec::with_capacity(enc.nonce.len() + enc.ciphertext.len());
                payload.extend_from_slice(&enc.nonce);
                payload.extend_from_slice(&enc.ciphertext);
                mask_context = Some(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    payload,
                ));
            } else {
                self.vault.put(&session, enc, self.ttl).await?;
            }
        }

        Ok(MaskResult {
            text: result.text,
            session_id: session,
            entities: result.entities,
            degraded: result.degraded,
            mask_context,
            mapping,
        })
    }

    /// Обработка по контракту Приложения A: единый вход, направление
    /// определяется тем, знаком ли уже `payload_id`.
    ///
    /// Первый запрос с новым id — маскирование, соответствие запоминается.
    /// Повторный запрос с тем же id — либо ретрай прямого шага (пришёл тот же
    /// исходный текст, отвечаем тем же результатом — эндпоинт идемпотентен),
    /// либо обратный шаг (пришла наша маска, возвращаем исходную строку).
    pub async fn process_tz(
        &self,
        policy: &EffectivePolicy,
        system_id: &str,
        payload_id: &str,
        payload: &str,
        deadline: Instant,
    ) -> Result<TzOutcome, VaultError> {
        // Систему без демаскирования обслуживаем как «всегда прямой шаг»:
        // соответствие не хранится, маска детерминирована, ретраи безопасны.
        if policy.demask {
            if let Some(mapping) = self.lookup_mapping(system_id, payload_id).await {
                if payload == mapping.original {
                    return Ok(TzOutcome::Repeated(mapping.masked));
                }
                if payload == mapping.masked {
                    let restored = mapping.entries.len();
                    return Ok(TzOutcome::Restored {
                        text: mapping.original,
                        restored,
                    });
                }
                // Текст между шагами изменился (например, его переписала LLM) —
                // восстанавливаем по плейсхолдерам, а не по точному совпадению.
                let res = demask_line(payload, &mapping);
                return Ok(TzOutcome::Restored {
                    text: res.text,
                    restored: res.restored,
                });
            }
        }

        let result = self
            .mask(policy, system_id, payload, Some(payload_id), deadline, false)
            .await?;
        Ok(TzOutcome::Masked(result))
    }

    /// Достаёт и расшифровывает соответствие по ключу сессии.
    /// Недоступность vault — не ошибка запроса: деградируем до маскирования.
    async fn lookup_mapping(&self, system_id: &str, session: &str) -> Option<Mapping> {
        if self.vault_mode == "stateless" {
            return None;
        }
        let enc = match self.vault.get(session).await {
            Ok(Some(enc)) => enc,
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(error = %e, "vault lookup failed, degrading to mask");
                crate::infra::metrics::inc_degraded("vault_lookup");
                return None;
            }
        };
        let plain =
            crate::infra::crypto::decrypt_mapping(&self.master_key, session, system_id, &enc)
                .ok()?;
        Mapping::from_bytes(&plain).ok()
    }

    /// Демаскирует текст.
    pub async fn demask(
        &self,
        policy: &EffectivePolicy,
        system_id: &str,
        text: &str,
        session_id: &str,
        mask_context: Option<&str>,
        deadline: Instant,
    ) -> Result<DemaskResult, VaultError> {
        let _ = deadline;
        // Демаскирование разрешено только если политика это допускает.
        if !policy.demask {
            return Err(VaultError::Unavailable("demask disabled for this system".into()));
        }
        let mapping = if self.vault_mode == "stateless" {
            let ct = mask_context.ok_or_else(|| {
                VaultError::Unavailable("mask_context required for stateless vault".into())
            })?;
            let ct_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                ct,
            )
            .map_err(|e| VaultError::Crypto(format!("bad mask_context: {e}")))?;
            // Разделяем nonce (12 байт) и ciphertext.
            if ct_bytes.len() < 12 {
                return Err(VaultError::Crypto("mask_context too short".into()));
            }
            let nonce = ct_bytes[..12].to_vec();
            let ciphertext = ct_bytes[12..].to_vec();
            let enc = crate::domain::traits::EncryptedMapping {
                nonce,
                ciphertext,
            };
            let plain = crate::infra::crypto::decrypt_mapping(
                &self.master_key,
                session_id,
                system_id,
                &enc,
            )?;
            Mapping::from_bytes(&plain)?
        } else {
            let enc = self
                .vault
                .get(session_id)
                .await?
                .ok_or_else(|| VaultError::Unavailable("session not found".into()))?;
            let plain = crate::infra::crypto::decrypt_mapping(
                &self.master_key,
                session_id,
                system_id,
                &enc,
            )?;
            Mapping::from_bytes(&plain)?
        };

        let res = demask_line(text, &mapping);

        if self.delete_after_demask && self.vault_mode != "stateless" {
            let _ = self.vault.delete(session_id).await;
        }

        Ok(DemaskResult {
            text: res.text,
            restored: res.restored,
            unresolved: res.unresolved,
            degraded: false,
        })
    }
}