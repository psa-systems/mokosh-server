//! [`OidcProvider`]: the central handle holding repositories, key set,
//! clock, and engine config.
//!
//! Endpoint logic lives in `authorize`, `token`, `userinfo`, `logout`.
//! They take `&OidcProvider` so dependencies are explicit and tests can
//! construct one with in-memory fakes.

use std::sync::Arc;

use mokosh_auth_core::{
    AuditLogger, AuthCodeRepository, Clock, EntitlementRepository, OAuthClientRepository,
    OpSessionRepository, RefreshTokenRepository, UserRepository,
};
use mokosh_auth_crypto::OidcKeySet;

use crate::config::EngineConfig;

#[derive(Clone)]
pub struct OidcProvider {
    pub cfg: EngineConfig,
    pub keys: Arc<OidcKeySet>,
    pub users: Arc<dyn UserRepository>,
    pub clients: Arc<dyn OAuthClientRepository>,
    pub sessions: Arc<dyn OpSessionRepository>,
    pub codes: Arc<dyn AuthCodeRepository>,
    pub refresh: Arc<dyn RefreshTokenRepository>,
    pub entitlements: Arc<dyn EntitlementRepository>,
    pub audit: Arc<dyn AuditLogger>,
    pub clock: Arc<dyn Clock>,
}

impl OidcProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: EngineConfig,
        keys: Arc<OidcKeySet>,
        users: Arc<dyn UserRepository>,
        clients: Arc<dyn OAuthClientRepository>,
        sessions: Arc<dyn OpSessionRepository>,
        codes: Arc<dyn AuthCodeRepository>,
        refresh: Arc<dyn RefreshTokenRepository>,
        entitlements: Arc<dyn EntitlementRepository>,
        audit: Arc<dyn AuditLogger>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            cfg,
            keys,
            users,
            clients,
            sessions,
            codes,
            refresh,
            entitlements,
            audit,
            clock,
        }
    }
}
