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
    ) -> Result<MaskResult, VaultError> {
        let session = session_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::now_v7().to_string());

        let mut state = MaskState::default();
        let result = mask_line(&self.pipeline, policy, text, &mut state, deadline).await;

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
        let mapping = Mapping { entries };

        // Сохранить в vault, если есть обратимые маски и demask.
        let needs_vault = policy.demask && !mapping.entries.is_empty();
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