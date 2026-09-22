//! PolicyResolver: (system, route) → EffectivePolicy.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::config::compiled::CompiledConfig;
use crate::config::loader::{resolve_policy, PolicyError};
use crate::domain::traits::EffectivePolicy;

/// Обёртка над resolve_policy с кэшированием и горячей перезагрузкой конфига.
pub struct PolicyResolver {
    pub cfg: ArcSwap<CompiledConfig>,
}

impl PolicyResolver {
    pub fn new(cfg: Arc<CompiledConfig>) -> Self {
        Self {
            cfg: ArcSwap::from(cfg),
        }
    }

    /// Обновляет конфиг (горячая перезагрузка).
    pub fn swap(&self, cfg: Arc<CompiledConfig>) {
        self.cfg.store(cfg);
    }

    pub fn resolve(
        &self,
        system_id: &str,
        route_id: Option<&str>,
    ) -> Result<Arc<EffectivePolicy>, PolicyError> {
        let cfg = self.cfg.load_full();
        resolve_policy(&cfg, system_id, route_id)
    }
}