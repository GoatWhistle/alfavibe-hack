//! Vault в памяти (moka с TTL).

use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;

use crate::domain::errors::VaultError;
use crate::domain::traits::{EncryptedMapping, Vault};

/// In-memory vault.
pub struct MemoryVault {
    cache: Cache<String, EncryptedMapping>,
}

impl MemoryVault {
    pub fn new(ttl: Duration, max_entries: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(ttl)
            .max_capacity(max_entries)
            .build();
        Self { cache }
    }
}

#[async_trait]
impl Vault for MemoryVault {
    async fn put(
        &self,
        session: &str,
        mapping: EncryptedMapping,
        ttl: Duration,
    ) -> Result<(), VaultError> {
        let _ = ttl;
        self.cache.insert(session.to_string(), mapping).await;
        Ok(())
    }

    async fn get(&self, session: &str) -> Result<Option<EncryptedMapping>, VaultError> {
        Ok(self.cache.get(session).await)
    }

    async fn delete(&self, session: &str) -> Result<(), VaultError> {
        self.cache.invalidate(session).await;
        Ok(())
    }

    async fn health(&self) -> bool {
        true
    }
}