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
//! **A provider whose connection lives elsewhere is read-only here.** Google is
//! still `contact_sync_connections` (see [`super::registry`]), so `connect`,
//! `disconnect` and a capability change are refused for it and no row is ever
//! written. That is what keeps one fact in one place while PMS-1315 is
//! outstanding. Stripe and PayPal came over under PMS-1312 and are writable here
//! now, with one difference covered below.
//!
//! **A credential never touches the row.** For a provider whose
//! [`CredentialHome`] is the integrations surface, [`Self::connect`] hands it to
//! the [`SecretProvider`] under [`SecretKey::integration`] and drops it; nothing
//! here reads it back, serves it or logs it. `disconnect` deletes it, which is
//! what makes keying the secret by provider rather than by row id safe: there is
//! no stale secret still resolving at an address a reconnect would reuse.
//!
//! **A payment gateway's credential is entered on the payments surface.** Stripe
//! needs a secret key, a webhook signing secret, a test-mode flag and a
//! validation pass that parses the blob into its own shape, and
//! `PUT /api/v1/payment-gateways` is where all of that already happens.
//! So `connect` for such a provider takes no credential, refuses one that is
//! sent, and refuses when the gateway has not been configured yet; `disconnect`
//! leaves the stored credential where it is. The status itself goes through
//! [`connection::set_payment_connection`], which is the single writer shared with
//! that surface.
//!
//! Reads and writes go through [`Database::begin_with_tenant`], so the
//! `tenant_isolation` policy on the table confines them and a missing GUC
//! yields zero rows rather than another tenant's (PMS-285). Every statement
//! ALSO filters on `tenant_id` explicitly, the `PortalRoleService` posture: a
//! superuser bypasses RLS however forced the policy is, and the integration
//! harness's default `boot` hands the service exactly such a pool, so leaning
//! on the policy alone would mean the isolation is untested where it is most
//! likely to be got wrong. `tests/suites/integrations.rs` boots through `boot_rls` so
//! the policy is exercised too.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::db::Database;
use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::secrets::{SecretKey, SecretProvider};
use crate::utils::error::{AppError, AppResult};

use super::connection;
use super::models::*;
use super::registry::{self, ConnectionHome, CredentialHome, ProviderDescriptor};

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

        // MAPPS-1122: every provider is listed, payment providers included.
        // Changing one is still confined to its own surface
        // (`is_writable_on_integrations_page`); what the panel does here is
        // say what exists and what state it is in.
        let contact_sync = self.contact_sync_states(tenant_id).await?;
        Ok(registry::REGISTRY
            .iter()
            .map(|descriptor| {
                let row = rows
                    .iter()
                    .find(|row| row.provider == descriptor.provider.as_str());
                compose(
                    descriptor,
                    row,
                    contact_sync.get(descriptor.provider.as_str()),
                )
            })
            .collect())
    }

    /// The contact-sync connections this tenant holds, by provider
    /// discriminator (MAPPS-1122).
    ///
    /// One query for the whole page rather than one per provider: three of the
    /// six registry entries are contact-sync sources, and a per-provider read
    /// would be the N+1 the registry's own `company_name` ticket exists to
    /// avoid.
    ///
    /// Read through `begin_with_tenant` like everything else here, so the
    /// policy confines it (PMS-285), and projected to the four fields the
    /// panel renders rather than taking the module's row type across the
    /// boundary.
    async fn contact_sync_states(
        &self,
        tenant_id: TenantId,
    ) -> AppResult<std::collections::HashMap<String, ContactSyncState>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows: Vec<ContactSyncRow> = sqlx::query_as(
            "SELECT provider, is_active, sync_status, last_error, created_at, disconnected_at \
                 FROM contact_sync_connections WHERE tenant_id = $1",
        )
        .bind(*tenant_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        tx.commit().await?;

        let mut states = std::collections::HashMap::new();
        for row in rows {
            // The registry's providers only. `contact_sync_connections` also
            // holds a `vcard` row per tenant since PMS-1290, which is an
            // uploaded file rather than an integration: it has no registry
            // entry, nothing on this page looks it up, and it has no
            // tenant-wide switch to read.
            if IntegrationProvider::from_str(&row.provider).is_none() {
                continue;
            }
            let enabled = crate::modules::contact_sync::switch::contacts_enabled(
                &self.db,
                tenant_id,
                &row.provider,
            )
            .await?;
            let status = contact_sync_status(row.is_active, &row.sync_status, row.disconnected_at);
            states.insert(
                row.provider,
                ContactSyncState {
                    status,
                    enabled,
                    // Only when the state IS the error: a stale message from a
                    // sync that later succeeded would read as a live failure.
                    last_error: match status {
                        IntegrationStatus::Error => row.last_error,
                        _ => None,
                    },
                    connected_at: Some(row.created_at),
                    disconnected_at: row.disconnected_at,
                },
            );
        }
        Ok(states)
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
        let contact_sync = self.contact_sync_states(tenant_id).await?;
        Ok(compose(
            descriptor,
            row.as_ref(),
            contact_sync.get(provider.as_str()),
        ))
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
        // MAPPS-1121: a capability change is the same claim `connect` makes,
        // in smaller print. `disconnect` is deliberately NOT gated: a tenant
        // who connected one of these before this landed has a row and a stored
        // credential, and the way to be rid of both is the button that removes
        // them.
        assert_built(descriptor)?;

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

        Ok(compose(descriptor, Some(&updated), None))
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
        assert_built(descriptor)?;

        if descriptor.credential_home != CredentialHome::Integration {
            return self
                .connect_with_credential_elsewhere(tenant_id, provider, request, ctx)
                .await;
        }

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

        // Required for this credential home, and refused for the other one, so
        // the field being optional on the wire does not make it optional here.
        let Some(credential) = request.credential.as_deref() else {
            return Err(AppError::BadRequest(format!(
                "{} is connected by storing its credential, so one has to be supplied",
                descriptor.display_name
            )));
        };

        self.secrets
            .put(
                &SecretKey::integration(*tenant_id, provider.as_str()),
                credential,
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

        Ok(compose(descriptor, Some(&row), None))
    }

    /// Connect a provider whose credential is entered on another surface
    /// (PMS-1312).
    ///
    /// Today that is Stripe and PayPal, whose key, webhook signing secret,
    /// test-mode flag and per-provider display and partial-payment settings are
    /// entered under `PUT /api/v1/payment-gateways`. What is left for
    /// this surface is the two things it owns: whether the tenant is connected,
    /// and what they have delegated.
    ///
    /// Three refusals, each for a state that would otherwise read as working:
    ///
    /// - a credential in the request, because it would be written to
    ///   `SecretKind::Integration` while the payment path reads
    ///   `SecretKind::PaymentGateway`, so the operator would have typed a key
    ///   into a field nothing reads;
    /// - no gateway row, because there is nothing to connect and the honest
    ///   answer names the surface that creates one;
    /// - a gateway row with no credential anywhere, because a `connected` row
    ///   with no credential behind it is exactly the state this subsystem's
    ///   write ordering exists to prevent.
    async fn connect_with_credential_elsewhere(
        &self,
        tenant_id: TenantId,
        provider: IntegrationProvider,
        request: ConnectIntegrationRequest,
        ctx: &AuditCtx,
    ) -> AppResult<IntegrationResponse> {
        let descriptor = registry::descriptor(provider);

        if descriptor.credential_home != CredentialHome::PaymentGateway {
            // Unreachable while Google is the only `ContactSync` entry and its
            // connection home is still elsewhere, so `assert_managed_here`
            // refuses first. Stated rather than silently falling through,
            // because PMS-1315 flipping that entry without writing this arm
            // would otherwise connect a contact sync with no token.
            return Err(AppError::BadRequest(format!(
                "{} cannot be connected here yet: its credential is keyed by the connection \
                 it belongs to, which this surface does not create.",
                descriptor.display_name
            )));
        }

        if request.credential.is_some() {
            return Err(AppError::BadRequest(format!(
                "{} takes its credentials under Settings > Payment gateways, not here. \
                 Connecting here only records that the tenant is using it.",
                descriptor.display_name
            )));
        }

        let capabilities = match request.capabilities {
            Some(requested) => Some(resolve_capabilities(descriptor, &requested)?),
            None => None,
        };
        let config = match request.config {
            Some(config) => Some(assert_config_object(config)?),
            None => None,
        };
        let poll_interval_minutes =
            assert_poll_interval(descriptor, request.poll_interval_minutes)?;

        let mut tx = self.db.begin_with_tenant(tenant_id).await?;

        // Both halves of "is there a credential" in one read: the pre-PMS-968
        // ciphertext still on the row, and whether the row says its credential
        // moved to the secret provider.
        let gateway: Option<(bool,)> = sqlx::query_as(
            "SELECT config_encrypted IS NOT NULL FROM payment_gateway_configs \
             WHERE tenant_id = $1 AND provider = $2",
        )
        .bind(*tenant_id)
        .bind(provider.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let Some((ciphertext_on_row,)) = gateway else {
            return Err(AppError::BadRequest(format!(
                "{} has no configuration yet. Add its credentials under \
                 Settings > Payment gateways first, then connect it here.",
                descriptor.display_name
            )));
        };

        if !ciphertext_on_row {
            let stored = self
                .secrets
                .get(&SecretKey::payment_gateway(*tenant_id, provider.as_str()))
                .await?;
            if stored.is_none() {
                return Err(AppError::BadRequest(format!(
                    "{}'s configuration holds no credential, so connecting it would record a \
                     gateway that cannot charge. Re-enter it under Settings > Payment gateways.",
                    descriptor.display_name
                )));
            }
        }

        let existing = read_row_in_tx(&mut tx, tenant_id, provider).await?;

        connection::set_payment_connection(
            &mut tx,
            tenant_id,
            provider.as_str(),
            true,
            ctx.user_id,
        )
        .await?;

        // Only when the request said something: `set_payment_connection` seeds
        // `{payments}` on a row it creates and leaves an existing row's set
        // alone, so an omitted list means "what this tenant already delegated"
        // rather than the provider's whole supported set. Connecting must not
        // silently widen a delegation.
        if capabilities.is_some() || config.is_some() || poll_interval_minutes.is_some() {
            sqlx::query(
                "UPDATE integrations \
                 SET enabled_capabilities = COALESCE($3, enabled_capabilities), \
                     config = COALESCE($4, config), \
                     poll_interval_minutes = COALESCE($5, poll_interval_minutes), \
                     updated_at = NOW() \
                 WHERE tenant_id = $1 AND provider = $2",
            )
            .bind(*tenant_id)
            .bind(provider.as_str())
            .bind(capabilities.as_ref())
            .bind(config.as_ref())
            .bind(poll_interval_minutes)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        let row = read_row_in_tx(&mut tx, tenant_id, provider)
            .await?
            .ok_or_else(|| {
                AppError::Database("the integration row vanished inside its own write".to_string())
            })?;

        audit_write(
            &mut *tx,
            tenant_id,
            ctx,
            if existing.is_some() {
                AuditAction::Update
            } else {
                AuditAction::Create
            },
            AUDIT_ENTITY,
            Some(row.id),
            existing.as_ref().map(audit_snapshot),
            Some(audit_snapshot(&row)),
        )
        .await?;
        tx.commit().await?;

        Ok(compose(descriptor, Some(&row), None))
    }

    /// Mark the integration disconnected, and delete its credential when this
    /// surface is the one that stored it.
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
    ///
    /// PMS-1312: for a provider whose [`CredentialHome`] is the payments
    /// surface the credential is left alone, because it is not this surface's to
    /// delete and an MSP switching payments off for a month should not have to
    /// find their Stripe keys again. `DELETE /api/v1/payment-gateways/{provider}`
    /// is what removes it, and it is also what removes the gateway row, so the
    /// two cannot end up half gone.
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

        // One writer per home: a payment provider's status is written only by
        // `connection::set_payment_connection`, which the payments surface shares,
        // so switching a gateway off here and switching it off there cannot leave
        // two different answers (and the retired `is_active` mirror is written in
        // both cases).
        let row: IntegrationRow = if descriptor.credential_home == CredentialHome::PaymentGateway {
            connection::set_payment_connection(&mut tx, tenant_id, provider.as_str(), false, None)
                .await?;
            read_row_in_tx(&mut tx, tenant_id, provider)
                .await?
                .ok_or_else(|| {
                    AppError::Database(
                        "the integration row vanished inside its own write".to_string(),
                    )
                })?
        } else {
            sqlx::query_as(&format!(
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
            .map_err(|e| AppError::Database(e.to_string()))?
        };

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

        if descriptor.credential_home == CredentialHome::Integration {
            self.secrets
                .delete(&SecretKey::integration(*tenant_id, provider.as_str()))
                .await?;
        }

        Ok(compose(descriptor, Some(&row), None))
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

/// One integration row, read inside a transaction the caller already holds.
///
/// The method form ([`IntegrationsService::read_row`]) opens its own transaction,
/// which is wrong for a write path: the `before` snapshot and the write have to
/// see the same state, and PMS-1312's payment connect needs both plus the row it
/// produced.
async fn read_row_in_tx(
    conn: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    provider: IntegrationProvider,
) -> AppResult<Option<IntegrationRow>> {
    sqlx::query_as(&format!(
        "{ROW_SELECT} WHERE tenant_id = $1 AND provider = $2"
    ))
    .bind(*tenant_id)
    .bind(provider.as_str())
    .fetch_optional(conn)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// The registry's half and the tenant's half, joined.
fn compose(
    descriptor: &ProviderDescriptor,
    row: Option<&IntegrationRow>,
    contact_sync: Option<&ContactSyncState>,
) -> IntegrationResponse {
    let mut response = IntegrationResponse::not_installed(descriptor);
    // MAPPS-1122: a provider whose connection lives in another subsystem has
    // its status THERE, and this read it from the `integrations` row anyway.
    // There is no row for Google, so a tenant with Google Contacts connected
    // and syncing read "Not connected" on a page whose whole job is to say
    // what is connected. The owning subsystem answers for it.
    if let Some(state) = contact_sync {
        response.status = state.status;
        response.last_error = state.last_error.clone();
        response.connected_at = state.connected_at;
        response.disconnected_at = state.disconnected_at;
        // MAPPS-1131: and the DELEGATION from there too. MAPPS-1122 moved the
        // status and stopped, so a tenant actively syncing Google Contacts was
        // listed as connected with nothing delegated to it: these providers
        // have no `integrations` row at all (`ConnectionHome::Elsewhere`, so
        // two tables cannot disagree about one fact), which left
        // `enabled_capabilities` permanently empty.
        //
        // Delegated means both halves: a live connection AND the tenant-wide
        // switch. A disconnected connection is handing nothing over, and
        // neither is a live one whose switch is off - `assert_enabled` refuses
        // a sync on the switch alone. `Error` counts as live: the account is
        // linked and the last attempt to read it failed, which is a failing
        // delegation, not an absent one.
        if state.enabled
            && matches!(
                state.status,
                IntegrationStatus::Connected | IntegrationStatus::Error
            )
        {
            response.enabled_capabilities = descriptor
                .supported_capabilities
                .iter()
                .map(|capability| capability.as_str().to_string())
                .collect();
        }
        return response;
    }
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

/// A contact-sync connection's state, as one of the four statuses this
/// surface speaks (MAPPS-1122).
///
/// `reconnect_required` is an error and not a disconnection: the row is still
/// there and the tenant still wants the integration, which is why contact sync
/// gives it its own outcome rather than folding it into `failed` (PSA-70 J).
/// `throttled` is the provider asking us to wait and must not read as broken.
fn contact_sync_status(
    is_active: bool,
    sync_status: &str,
    disconnected_at: Option<chrono::DateTime<chrono::Utc>>,
) -> IntegrationStatus {
    if disconnected_at.is_some() || !is_active {
        return IntegrationStatus::Disconnected;
    }
    match sync_status {
        "failed" | "reconnect_required" => IntegrationStatus::Error,
        _ => IntegrationStatus::Connected,
    }
}

/// The columns [`IntegrationsService::contact_sync_states`] reads.
///
/// A named row type rather than the tuple this was: six columns is past where
/// a tuple reads (clippy's `type_complexity` says so, and CI is `-D warnings`),
/// and the positional destructuring was one swapped pair away from reporting
/// `is_active` as the status.
#[derive(sqlx::FromRow)]
struct ContactSyncRow {
    provider: String,
    is_active: bool,
    sync_status: String,
    last_error: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    disconnected_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One contact-sync connection, reduced to what the panel renders
/// (MAPPS-1122).
///
/// A projection rather than the module's own row type: this is a read across a
/// subsystem boundary, and taking the whole row would make every column of
/// `contact_sync_connections` part of what integrations depends on.
struct ContactSyncState {
    status: IntegrationStatus,
    /// Whether the tenant-wide switch for this provider is on (MAPPS-1131).
    ///
    /// A second fact from a second table, and both are needed to answer what is
    /// delegated: the connection says the account is linked, and the switch
    /// says whether anything is allowed to read it. `assert_enabled` refuses a
    /// sync request on the switch alone, so a tenant with a live connection and
    /// the switch off has handed nothing over.
    enabled: bool,
    last_error: Option<String>,
    connected_at: Option<chrono::DateTime<chrono::Utc>>,
    disconnected_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Refuse a provider whose connection is owned by another subsystem, naming
/// where it is configured instead.
///
/// A 409 rather than a 404: the provider exists and is listed, and what is
/// wrong is that this is the wrong surface for it.
fn assert_managed_here(descriptor: &ProviderDescriptor) -> AppResult<()> {
    match descriptor.connection_home {
        ConnectionHome::Integrations => Ok(()),
        ConnectionHome::Elsewhere {
            table,
            configured_at,
        } => Err(AppError::Conflict(format!(
            "{} is configured under {configured_at} and not as an integration, so its \
             connection stays in {table}. Changing it here would give one connection two \
             places to live.",
            descriptor.display_name
        ))),
    }
}

/// Refuse a provider this build has nothing behind (MAPPS-1121).
///
/// A 409 rather than a 400, the `assert_managed_here` reading: the request is
/// well formed and the provider is really listed, and what is wrong is that
/// there is nothing here to connect it to. Checked before the credential is
/// read, so nothing is ever written to the secret provider for a provider that
/// cannot use it, and before the row, so the table never claims a delegation
/// nothing can act on.
///
/// The message does not carry `tracked_by`: it reaches a tenant's screen, and
/// an MSP admin has no use for our issue keys.
fn assert_built(descriptor: &ProviderDescriptor) -> AppResult<()> {
    if descriptor.build.is_built() {
        return Ok(());
    }
    Err(AppError::Conflict(format!(
        "{} is listed so the capabilities it would take can be named, but this build has \
         nothing behind it yet: there is no client to hand a credential to and nothing reads \
         what it would be delegated. Connecting it would report a delegation that cannot \
         happen.",
        descriptor.display_name
    )))
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
                "`{raw}` is not a capability. The capabilities are: {}",
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
            "integrations.config must be a JSON object of settings".to_string(),
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
            "A poll interval of {minutes} minutes is below the {} minute floor for {}.",
            polling.min_minutes, descriptor.display_name
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

    /// MAPPS-1121: a provider with nothing behind it is refused before any
    /// credential is read.
    ///
    /// The refusal is the whole fix. Before it, `connect` stored whatever
    /// string was typed into the page's Credential field under
    /// `SecretKey::integration`, wrote `status = 'connected'`, and returned
    /// 200 for a provider with no client, no capability reader and no poll
    /// job. A tenant was told a delegation had happened that nothing could
    /// act on, which is worse than the button failing.
    #[test]
    fn a_planned_provider_is_refused_and_a_built_one_is_not() {
        // MAPPS-1153 flipped the last two planned entries, so the refusal
        // is exercised against a descriptor built for it rather than
        // against whichever provider happened to be unfinished. The rule
        // outlives the providers that prompted it, and a test naming Xero
        // would have been deleted with the flip rather than kept.
        let planned = ProviderDescriptor {
            build: registry::ProviderBuild::Planned {
                tracked_by: "MAPPS-1099",
            },
            ..*registry::descriptor(IntegrationProvider::Xero)
        };
        let error = assert_built(&planned).expect_err("planned, so refused");
        let message = format!("{error}");
        assert!(
            message.contains(planned.display_name),
            "the refusal names the provider: {message}"
        );
        assert!(
            !message.contains("MAPPS-"),
            "an MSP admin reading their own settings has no use for our issue keys: {message}"
        );
        for provider in [IntegrationProvider::Quickbooks, IntegrationProvider::Xero] {
            assert!(
                assert_built(registry::descriptor(provider)).is_ok(),
                "{provider:?} has a client, a consent flow and a settings page now"
            );
        }
        for provider in [
            IntegrationProvider::Stripe,
            IntegrationProvider::Paypal,
            IntegrationProvider::Google,
            IntegrationProvider::Microsoft,
        ] {
            assert_built(registry::descriptor(provider)).expect("built, so not refused here");
        }
    }

    /// Microsoft 365 is refused on this surface for the OTHER reason, and the
    /// distinction matters to whoever reads the message.
    ///
    /// Its client shipped (MAPPS-1101); what is true is that the connection is
    /// the Entra consent round trip in `contact_sync`, so this is the wrong
    /// surface rather than an absent provider. `assert_managed_here` is what
    /// says so, and it names where the connection does live.
    #[test]
    fn microsoft_is_refused_as_managed_elsewhere_not_as_unbuilt() {
        let descriptor = registry::descriptor(IntegrationProvider::Microsoft);
        let error = assert_managed_here(descriptor).expect_err("its connection lives elsewhere");
        let message = format!("{error}");
        assert!(
            message.contains("contact_sync_connections"),
            "names where the connection lives: {message}"
        );
        assert!(
            !message.contains("nothing behind it"),
            "it is built; saying otherwise sends an admin to wait for work that is done: \
             {message}"
        );
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

    /// The guard that keeps one connection in one place while PMS-1315 is
    /// outstanding.
    ///
    /// Google, because PMS-1312 brought the payment providers over. The guard is
    /// exercised against whichever provider is still outside rather than deleted
    /// with the last one that was: the message is what an operator gets back, and
    /// it is the only thing that tells them where to go instead.
    /// PMS-1447: what the response SAYS about a provider's credential is what
    /// `connect` actually does about it, for every provider in the registry.
    ///
    /// The two could drift trivially: `credential_elsewhere` is composed in
    /// `models.rs` and the behaviour is branched in `connect` above, and the
    /// only thing holding them together is that both read
    /// `descriptor.credential_home`. This walks the registry and asserts the
    /// pair agrees, so adding a provider with the wrong home fails here rather
    /// than shipping a page that renders a credential field for a provider that
    /// refuses one.
    ///
    /// A pure test: it reads the registry and the composed response, and never
    /// calls `connect`, which needs a pool. What it pins is the AGREEMENT, and
    /// the behaviour either side of it is covered where it happens.
    #[test]
    fn the_credential_home_the_response_reports_is_the_one_connect_enforces() {
        for descriptor in registry::REGISTRY {
            let response = IntegrationResponse::not_installed(descriptor);
            let takes_credential_here = descriptor.credential_home == CredentialHome::Integration;
            assert_eq!(
                response.credential_elsewhere.is_none(),
                takes_credential_here,
                "{}: the response says credential_elsewhere {:?} while connect {} a credential \
                 here",
                descriptor.display_name,
                response.credential_elsewhere.as_ref().map(|c| &c.kind),
                if takes_credential_here {
                    "takes"
                } else {
                    "refuses"
                },
            );
            if let Some(elsewhere) = &response.credential_elsewhere {
                assert_eq!(elsewhere.kind, descriptor.credential_home.as_str());
                assert!(
                    elsewhere.entered_at.starts_with("Settings > "),
                    "{}: entered_at has to name a settings screen so a page can point at it, \
                     got {:?}",
                    descriptor.display_name,
                    elsewhere.entered_at,
                );
            }
        }
    }

    /// The two payment providers report the payments surface and Google reports
    /// the contact-sync one, which is the distinction a boolean would have lost.
    ///
    /// Named providers rather than a loop, because these three are the reason
    /// the field carries a surface at all: an admin sent to the wrong screen is
    /// no better off than one sent to none.
    #[test]
    fn each_credential_home_names_its_own_surface() {
        for (provider, expected) in [
            (IntegrationProvider::Stripe, "Payment Gateways"),
            (IntegrationProvider::Paypal, "Payment Gateways"),
            (IntegrationProvider::Google, "Google Contacts"),
            // MAPPS-1153: and the ones that made the per-home label a lie.
            // `ContactSync` answered "Settings > Google Contacts" for all
            // three contact sources, so iCloud's card named Google's page;
            // `InvoiceIssuer` has no such string at all, because nothing is
            // entered and the two providers have different pages. The label
            // comes from each provider's own setup surface now.
            (IntegrationProvider::Icloud, "iCloud Contacts"),
            (IntegrationProvider::Microsoft, "Microsoft 365 Contacts"),
            (IntegrationProvider::Xero, "Xero"),
            (IntegrationProvider::Quickbooks, "QuickBooks"),
        ] {
            let response = IntegrationResponse::not_installed(registry::descriptor(provider));
            let elsewhere = response
                .credential_elsewhere
                .expect("this provider's credential is entered on another surface");
            assert!(
                elsewhere.entered_at.contains(expected),
                "{provider:?} points at {:?}, expected it to name {expected}",
                elsewhere.entered_at
            );
        }
        // And one that takes its credential here, so the absence is asserted
        // rather than assumed from the loop above. No provider in the
        // registry does since MAPPS-1153, so it is a descriptor built for
        // the case: the rule is about the home, not about who holds it.
        let arrives_here = registry::ProviderDescriptor {
            credential_home: registry::CredentialHome::Integration,
            ..*registry::descriptor(IntegrationProvider::Quickbooks)
        };
        assert!(
            IntegrationResponse::not_installed(&arrives_here)
                .credential_elsewhere
                .is_none(),
            "a credential that arrives in the connect request names no other surface"
        );
    }

    #[test]
    fn a_provider_managed_elsewhere_is_refused_and_says_where() {
        let error = assert_managed_here(registry::descriptor(IntegrationProvider::Google))
            .expect_err("Google is still contact_sync_connections");
        let message = error.to_string();
        assert!(message.contains("Contact sync"), "{message}");
        assert!(message.contains("contact_sync_connections"), "{message}");
        assert!(
            message.contains("Changing it here"),
            "the refusal says why this surface is not the place: {message}"
        );
        assert!(
            !message.contains("PMS-"),
            "and names no issue, because the connection stays where it is (PMS-1315): {message}"
        );

        assert_managed_here(xero()).expect("Xero is managed here");
        assert_managed_here(registry::descriptor(IntegrationProvider::Stripe))
            .expect("PMS-1312 moved Stripe's connection here");
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
