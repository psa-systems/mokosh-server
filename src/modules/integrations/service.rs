//! `IntegrationsService`: the one writer of `integrations` (PMS-1310).
//!
//! Three rules live here and nowhere else, because each is a way the subsystem
//! could quietly become untrue.
//!
//! **A tenant may only delegate what the provider supports.** The registry
//! declares the supported set per provider and [`Self::resolve_capabilities`]
//! rejects anything outside it, so `enabled_capabilities` is a subset by
//! construction rather than by whoever wrote the last request. Rejected rather
//! than filtered: an operator who ticks a box and is silently given a row
//! without it has been told the delegation happened.
//!
//! **A provider whose connection lives elsewhere is read-only here.** Stripe
//! and PayPal are still `payment_gateway_configs`, Google is still
//! `contact_sync_connections` (see [`super::registry`]), so `connect`,
//! `disconnect` and a capability change are refused for them and no row is ever
//! written. That is what keeps one fact in one place while PMS-1312 and
//! PMS-1315 are outstanding.
//!
//! **A credential never touches the row.** [`Self::connect`] hands it to the
//! [`SecretProvider`] under [`SecretKey::integration`] and drops it; nothing
//! here reads it back, serves it or logs it. `disconnect` deletes it, which is
//! what makes keying the secret by provider rather than by row id safe: there
//! is no stale secret still resolving at an address a reconnect would reuse.
//!
//! Reads and writes go through [`Database::begin_with_tenant`], so the
//! `tenant_isolation` policy on the table confines them and a missing GUC
//! yields zero rows rather than another tenant's (PMS-285). Every statement
//! ALSO filters on `tenant_id` explicitly, the `PortalRoleService` posture: a
//! superuser bypasses RLS however forced the policy is, and the integration
//! harness's default `boot` hands the service exactly such a pool, so leaning
//! on the policy alone would mean the isolation is untested where it is most
//! likely to be got wrong. `tests/integrations.rs` boots through `boot_rls` so
//! the policy is exercised too.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::secrets::{SecretKey, SecretProvider};
use crate::utils::error::{AppError, AppResult};

use super::models::*;
use super::registry::{self, ConnectionHome, ProviderDescriptor};

/// What `audit_log.entity_type` calls a change here.
const AUDIT_ENTITY: &str = "integrations";

#[derive(Clone)]
pub struct IntegrationsService {
    db: Database,
    secrets: Arc<dyn SecretProvider>,
}

impl IntegrationsService {
    pub fn new(db: Database, secrets: Arc<dyn SecretProvider>) -> Self {
        Self { db, secrets }
    }

    /// Every provider, each with what it supports and what this tenant has
    /// handed it.
    ///
    /// The registry drives the list and the rows fill it in, not the other way
    /// round: the page's job is to show what COULD be connected, so a provider
    /// with no row appears as `not_connected` rather than being absent.
    pub async fn list(&self, tenant_id: TenantId) -> AppResult<Vec<IntegrationResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<IntegrationRow> =
            sqlx::query_as(&format!("{ROW_SELECT} WHERE tenant_id = $1"))
                .bind(*tenant_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        tx.commit().await?;

        Ok(registry::REGISTRY
            .iter()
            .map(|descriptor| {
                let row = rows
                    .iter()
                    .find(|row| row.provider == descriptor.provider.as_str());
                compose(descriptor, row)
            })
            .collect())
    }

    /// One provider. Answers for a provider with no row too, for the same
    /// reason the list does.
    pub async fn get(
        &self,
        tenant_id: TenantId,
        provider: IntegrationProvider,
    ) -> AppResult<IntegrationResponse> {
        let descriptor = registry::descriptor(provider);
        let row = self.read_row(tenant_id, provider).await?;
        Ok(compose(descriptor, row.as_ref()))
    }

    /// Change what this tenant delegates, and the non-secret settings.
    ///
    /// Refused for a provider managed elsewhere, and refused when there is no
    /// row: capabilities are what an installation was trusted with, so setting
    /// them on something that was never connected would mint a row that claims
    /// a delegation nothing can act on. Connect first.
    pub async fn update(
        &self,
        tenant_id: TenantId,
        provider: IntegrationProvider,
        request: UpdateIntegrationRequest,
        ctx: &AuditCtx,
    ) -> AppResult<IntegrationResponse> {
        let descriptor = registry::descriptor(provider);
        assert_managed_here(descriptor)?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let existing: Option<IntegrationRow> = sqlx::query_as(&format!(
            "{ROW_SELECT} WHERE tenant_id = $1 AND provider = $2 FOR UPDATE"
        ))
        .bind(*tenant_id)
        .bind(provider.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let Some(existing) = existing else {
            return Err(AppError::NotFound(format!(
                "{} is not connected, so there is nothing to configure",
                descriptor.display_name
            )));
        };

        let capabilities = match request.capabilities {
            Some(requested) => resolve_capabilities(descriptor, &requested)?,
            None => existing.enabled_capabilities.clone(),
        };
        let config = match request.config {
            Some(config) => assert_config_object(config)?,
            None => existing.config.clone(),
        };
        let poll_interval_minutes = match request.poll_interval_minutes {
            Some(value) => assert_poll_interval(descriptor, value)?,
            None => existing.poll_interval_minutes,
        };

        let updated: IntegrationRow = sqlx::query_as(&format!(
            "UPDATE integrations \
             SET enabled_capabilities = $3, config = $4, poll_interval_minutes = $5, \
                 updated_at = NOW() \
             WHERE tenant_id = $1 AND provider = $2 \
             RETURNING {ROW_COLUMNS}"
        ))
        .bind(*tenant_id)
        .bind(provider.as_str())
        .bind(&capabilities)
        .bind(&config)
        .bind(poll_interval_minutes)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Update,
            AUDIT_ENTITY,
            Some(updated.id),
            Some(audit_snapshot(&existing)),
            Some(audit_snapshot(&updated)),
        )
        .await?;
        tx.commit().await?;

        Ok(compose(descriptor, Some(&updated)))
    }

    /// Store the credential and mark the integration connected.
    ///
    /// The row is upserted, because `integrations` is UNIQUE on
    /// `(tenant_id, provider)` and reconnecting is the ordinary case: a tenant
    /// whose grant was revoked reconnects the same installation rather than
    /// acquiring a second one.
    ///
    /// The secret is written BEFORE the row, and the row's commit is what makes
    /// the integration connected. The other order would let a committed
    /// `connected` row exist with no credential behind it, which reads as a
    /// working integration and fails on first use; this order can leave a
    /// secret with no row, which the next connect overwrites and
    /// [`Self::disconnect`] deletes by address whether a row is there or not.
    pub async fn connect(
        &self,
        tenant_id: TenantId,
        provider: IntegrationProvider,
        request: ConnectIntegrationRequest,
        ctx: &AuditCtx,
    ) -> AppResult<IntegrationResponse> {
        let descriptor = registry::descriptor(provider);
        assert_managed_here(descriptor)?;

        // Omitted means every capability the provider supports: an operator who
        // connects an integration and is asked nothing else expects it to work.
        // An explicit empty list means connected and delegated nothing, which
        // is a state worth being able to express.
        let capabilities = match request.capabilities {
            Some(requested) => resolve_capabilities(descriptor, &requested)?,
            None => descriptor
                .supported_capabilities
                .iter()
                .map(|capability| capability.as_str().to_string())
                .collect(),
        };
        let config = match request.config {
            Some(config) => assert_config_object(config)?,
            None => json!({}),
        };
        let poll_interval_minutes =
            assert_poll_interval(descriptor, request.poll_interval_minutes)?;

        self.secrets
            .put(
                &SecretKey::integration(*tenant_id, provider.as_str()),
                &request.credential,
            )
            .await?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: IntegrationRow = sqlx::query_as(&format!(
            "INSERT INTO integrations \
                 (tenant_id, provider, status, config, enabled_capabilities, \
                  poll_interval_minutes, connected_by_user_id, connected_at) \
             VALUES ($1, $2, 'connected', $3, $4, $5, $6, NOW()) \
             ON CONFLICT (tenant_id, provider) DO UPDATE \
             SET status = 'connected', \
                 config = EXCLUDED.config, \
                 enabled_capabilities = EXCLUDED.enabled_capabilities, \
                 poll_interval_minutes = EXCLUDED.poll_interval_minutes, \
                 connected_by_user_id = EXCLUDED.connected_by_user_id, \
                 connected_at = NOW(), \
                 disconnected_at = NULL, \
                 last_error = NULL, \
                 updated_at = NOW() \
             RETURNING {ROW_COLUMNS}"
        ))
        .bind(*tenant_id)
        .bind(provider.as_str())
        .bind(&config)
        .bind(&capabilities)
        .bind(poll_interval_minutes)
        .bind(ctx.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Create,
            AUDIT_ENTITY,
            Some(row.id),
            None,
            Some(audit_snapshot(&row)),
        )
        .await?;
        tx.commit().await?;

        Ok(compose(descriptor, Some(&row)))
    }

    /// Mark the integration disconnected and delete its credential.
    ///
    /// The ROW IS KEPT, the `contact_sync_connections.disconnected_at` choice:
    /// the capability set the tenant chose is worth keeping so reconnecting does
    /// not start from an empty page, and the audit trail has to keep naming who
    /// connected it.
    ///
    /// The row commits BEFORE the secret is deleted, the opposite of
    /// [`Self::connect`] and for the same reason: the state that must never
    /// exist is a `connected` row with no credential, so the credential is
    /// written first and removed last. A deleted secret with a stale
    /// `connected` row would be an integration that looks fine and fails on
    /// first use.
    pub async fn disconnect(
        &self,
        tenant_id: TenantId,
        provider: IntegrationProvider,
        ctx: &AuditCtx,
    ) -> AppResult<IntegrationResponse> {
        let descriptor = registry::descriptor(provider);
        assert_managed_here(descriptor)?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let existing: Option<IntegrationRow> = sqlx::query_as(&format!(
            "{ROW_SELECT} WHERE tenant_id = $1 AND provider = $2 FOR UPDATE"
        ))
        .bind(*tenant_id)
        .bind(provider.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let Some(existing) = existing else {
            return Err(AppError::NotFound(format!(
                "{} is not connected",
                descriptor.display_name
            )));
        };

        let row: IntegrationRow = sqlx::query_as(&format!(
            "UPDATE integrations \
             SET status = 'disconnected', disconnected_at = NOW(), last_error = NULL, \
                 updated_at = NOW() \
             WHERE tenant_id = $1 AND provider = $2 \
             RETURNING {ROW_COLUMNS}"
        ))
        .bind(*tenant_id)
        .bind(provider.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            AuditAction::Delete,
            AUDIT_ENTITY,
            Some(row.id),
            Some(audit_snapshot(&existing)),
            Some(audit_snapshot(&row)),
        )
        .await?;
        tx.commit().await?;

        self.secrets
            .delete(&SecretKey::integration(*tenant_id, provider.as_str()))
            .await?;

        Ok(compose(descriptor, Some(&row)))
    }

    async fn read_row(
        &self,
        tenant_id: TenantId,
        provider: IntegrationProvider,
    ) -> AppResult<Option<IntegrationRow>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<IntegrationRow> = sqlx::query_as(&format!(
            "{ROW_SELECT} WHERE tenant_id = $1 AND provider = $2"
        ))
        .bind(*tenant_id)
        .bind(provider.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        tx.commit().await?;
        Ok(row)
    }
}

/// The column list every read and every `RETURNING` shares, so a column added
/// to [`IntegrationRow`] cannot be served by one path and not another (the
/// `PRODUCT_COLUMNS` arrangement from PMS-1002).
const ROW_COLUMNS: &str = "id, provider, status, config, enabled_capabilities, \
                           poll_interval_minutes, connected_at, disconnected_at, last_error";

const ROW_SELECT: &str = "SELECT id, provider, status, config, enabled_capabilities, \
                          poll_interval_minutes, connected_at, disconnected_at, last_error \
                          FROM integrations";

/// The registry's half and the tenant's half, joined.
fn compose(descriptor: &ProviderDescriptor, row: Option<&IntegrationRow>) -> IntegrationResponse {
    let mut response = IntegrationResponse::not_installed(descriptor);
    let Some(row) = row else {
        return response;
    };
    // A status the enum does not know means the CHECK constraint and the enum
    // have drifted, which is a deployment running a schema this build does not
    // understand. Reading it as `error` is the honest answer: something is
    // wrong with this integration and an operator should look.
    response.status = IntegrationStatus::from_str(&row.status).unwrap_or(IntegrationStatus::Error);
    response.enabled_capabilities = row.enabled_capabilities.clone();
    response.config = row.config.clone();
    response.poll_interval_minutes = row.poll_interval_minutes;
    response.connected_at = row.connected_at;
    response.disconnected_at = row.disconnected_at;
    response.last_error = row.last_error.clone();
    response
}

/// Refuse a provider whose connection is owned by another subsystem, naming
/// where it is configured and the issue that moves it.
///
/// A 409 rather than a 404: the provider exists and is listed, and what is
/// wrong is that this is the wrong surface for it.
fn assert_managed_here(descriptor: &ProviderDescriptor) -> AppResult<()> {
    match descriptor.connection_home {
        ConnectionHome::Integrations => Ok(()),
        ConnectionHome::Elsewhere {
            table,
            configured_at,
            issue,
        } => Err(AppError::Conflict(format!(
            "{} is configured under {configured_at} and not as an integration, so its \
             connection stays in {table} until {issue} moves it. Changing it here would \
             give one connection two places to live.",
            descriptor.display_name
        ))),
    }
}

/// The subset rule: every requested capability has to be one the provider
/// supports, and nothing may be asked for twice.
///
/// Returns the stored spelling in the registry's own order, so two requests
/// naming the same set produce the same row and a diff in the audit log means a
/// real change.
fn resolve_capabilities(
    descriptor: &ProviderDescriptor,
    requested: &[String],
) -> AppResult<Vec<String>> {
    let mut chosen = Vec::with_capacity(requested.len());
    for raw in requested {
        let Some(capability) = Capability::from_str(raw) else {
            return Err(AppError::BadRequest(format!(
                "{raw:?} is not a capability. The capabilities are: {}",
                Capability::ALL
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        };
        if !descriptor.supports(capability) {
            return Err(AppError::BadRequest(format!(
                "{} does not provide {}. It provides: {}",
                descriptor.display_name,
                capability.as_str(),
                descriptor
                    .supported_capabilities
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        if chosen.contains(&capability) {
            return Err(AppError::BadRequest(format!(
                "{} is named more than once",
                capability.as_str()
            )));
        }
        chosen.push(capability);
    }
    Ok(descriptor
        .supported_capabilities
        .iter()
        .filter(|capability| chosen.contains(capability))
        .map(|capability| capability.as_str().to_string())
        .collect())
}

/// `config` holds per-provider settings, so it has to be a JSON object: an
/// array or a scalar there would be a shape no provider can read, stored
/// without complaint.
fn assert_config_object(config: Value) -> AppResult<Value> {
    if config.is_object() {
        Ok(config)
    } else {
        Err(AppError::BadRequest(
            "config must be a JSON object of settings".to_string(),
        ))
    }
}

/// A poll interval is only meaningful for a provider that polls, and only above
/// the floor the column enforces. Checked here so the refusal names the
/// provider and the floor rather than surfacing a constraint violation.
fn assert_poll_interval(
    descriptor: &ProviderDescriptor,
    requested: Option<i32>,
) -> AppResult<Option<i32>> {
    let Some(minutes) = requested else {
        return Ok(None);
    };
    let Some(polling) = descriptor.polling else {
        return Err(AppError::BadRequest(format!(
            "{} is not polled, so it has no poll interval",
            descriptor.display_name
        )));
    };
    if minutes < polling.min_minutes {
        return Err(AppError::BadRequest(format!(
            "a poll interval of {minutes} minutes is below the {} minute floor",
            polling.min_minutes
        )));
    }
    Ok(Some(minutes))
}

/// What the audit row records. Deliberately only the fields a change can move,
/// and deliberately never the credential, which is not on the row to begin
/// with.
fn audit_snapshot(row: &IntegrationRow) -> Value {
    json!({
        "provider": row.provider,
        "status": row.status,
        "enabled_capabilities": row.enabled_capabilities,
        "config": row.config,
        "poll_interval_minutes": row.poll_interval_minutes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mokosh_types::integrations::IntegrationProvider;

    fn xero() -> &'static ProviderDescriptor {
        registry::descriptor(IntegrationProvider::Xero)
    }

    /// The rule the whole subsystem exists for: a tenant cannot hand a provider
    /// something the provider does not do. Rejected and not filtered, so an
    /// operator is never told a delegation happened that did not.
    #[test]
    fn a_capability_the_provider_does_not_support_is_rejected() {
        let error = resolve_capabilities(xero(), &["payments".to_string()])
            .expect_err("Xero does not take payments");
        let message = error.to_string();
        assert!(message.contains("Xero"), "{message}");
        assert!(message.contains("payments"), "{message}");
        assert!(
            message.contains("invoicing"),
            "the refusal says what it DOES provide: {message}"
        );
    }

    #[test]
    fn a_supported_subset_is_accepted_and_stored_in_registry_order() {
        let chosen = resolve_capabilities(
            xero(),
            &["bills_and_expenses".to_string(), "invoicing".to_string()],
        )
        .expect("both are supported");
        assert_eq!(
            chosen,
            vec!["invoicing".to_string(), "bills_and_expenses".to_string()],
            "the stored order is the registry's, so the same set is the same row"
        );
    }

    /// An empty set is connected-and-delegated-nothing, which is how a
    /// delegation is suspended without discarding the credential.
    #[test]
    fn an_empty_capability_set_is_accepted() {
        assert_eq!(
            resolve_capabilities(xero(), &[]).expect("empty is legal"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_capability_nobody_has_heard_of_is_rejected() {
        let error =
            resolve_capabilities(xero(), &["telepathy".to_string()]).expect_err("not a capability");
        assert!(error.to_string().contains("telepathy"), "{error}");
    }

    /// A duplicate would store one entry and report success for two, which
    /// makes the request and the row disagree about what was asked.
    #[test]
    fn the_same_capability_twice_is_rejected() {
        let error =
            resolve_capabilities(xero(), &["invoicing".to_string(), "invoicing".to_string()])
                .expect_err("duplicated");
        assert!(error.to_string().contains("more than once"), "{error}");
    }

    /// The guard that keeps one connection in one place while PMS-1312 and
    /// PMS-1315 are outstanding.
    #[test]
    fn a_provider_managed_elsewhere_is_refused_and_says_where() {
        let error = assert_managed_here(registry::descriptor(IntegrationProvider::Stripe))
            .expect_err("Stripe is still payment_gateway_configs");
        let message = error.to_string();
        assert!(message.contains("Payment gateways"), "{message}");
        assert!(message.contains("payment_gateway_configs"), "{message}");
        assert!(
            message.contains("PMS-1312"),
            "the refusal names the issue that moves it: {message}"
        );

        assert_managed_here(xero()).expect("Xero is managed here");
    }

    /// A poll interval on a provider nothing polls is a setting that would be
    /// stored and never read.
    #[test]
    fn a_poll_interval_is_refused_for_a_provider_that_does_not_poll() {
        let stripe = registry::descriptor(IntegrationProvider::Stripe);
        let error = assert_poll_interval(stripe, Some(30)).expect_err("Stripe is not polled");
        assert!(error.to_string().contains("not polled"), "{error}");
        assert_eq!(
            assert_poll_interval(stripe, None).expect("no interval is fine"),
            None
        );
    }

    /// The floor is the one the column enforces, so a value the service accepts
    /// can never be a constraint violation.
    #[test]
    fn a_poll_interval_below_the_floor_is_refused_before_the_database_sees_it() {
        let error = assert_poll_interval(xero(), Some(1)).expect_err("below the floor");
        assert!(error.to_string().contains("floor"), "{error}");
        assert_eq!(
            assert_poll_interval(xero(), Some(registry::MIN_POLL_INTERVAL_MINUTES))
                .expect("the floor itself is legal"),
            Some(registry::MIN_POLL_INTERVAL_MINUTES)
        );
    }

    #[test]
    fn config_has_to_be_an_object() {
        assert!(assert_config_object(json!({"realm": "abc"})).is_ok());
        assert!(assert_config_object(json!([1, 2])).is_err());
        assert!(assert_config_object(json!("abc")).is_err());
    }
}
