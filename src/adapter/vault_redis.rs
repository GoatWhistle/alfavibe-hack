//! Vault на Redis. Требует feature `redis` и crate `fred`.

use std::time::Duration;

use async_trait::async_trait;

use crate::domain::errors::VaultError;
use crate::domain::traits::{EncryptedMapping, Vault};

/// Redis vault (заглушка; полная реализация требует fred).
pub struct RedisVault;

impl RedisVault {
    pub fn new(_url: &str) -> anyhow::Result<Self> {
        anyhow::bail!("redis vault requires fred crate; add it to Cargo.toml under feature redis")
    }
}

#[async_trait]
impl Vault for RedisVault {
    async fn put(
        &self,
        _session: &str,
        _mapping: EncryptedMapping,
        _ttl: Duration,
    ) -> Result<(), VaultError> {
        Err(VaultError::Unavailable("redis not built".into()))
    }
    async fn get(&self, _session: &str) -> Result<Option<EncryptedMapping>, VaultError> {
        Err(VaultError::Unavailable("redis not built".into()))
    }
    async fn delete(&self, _session: &str) -> Result<(), VaultError> {
        Err(VaultError::Unavailable("redis not built".into()))
    }
    async fn health(&self) -> bool {
        false
    }
}