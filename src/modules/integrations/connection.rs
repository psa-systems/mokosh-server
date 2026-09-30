//! PMS-1312: the one writer of whether a payment provider is connected, and the
//! one definition of what "connected" selects.
//!
//! Before this, `payment_gateway_configs.is_active` was that fact, and
//! `integrations` deliberately held no row for Stripe or PayPal so the two could
//! not disagree ([`super::registry`] carries the reasoning and migration 256 the
//! backfill). `integrations.status` is the fact now, and the reason this module
//! exists rather than the statements living at each call site is that two
//! surfaces legitimately set it: the payments settings page, which is where a
//! gateway's credential and its per-provider settings are entered, and the
//! integrations page, which is where a tenant says what it delegates. One home
//! with two writers is the shape that ends in two answers, so both go through
//! [`set_payment_connection`].
//!
//! # The mirror, and why it is not a second home
//!
//! [`set_payment_connection`] also writes `payment_gateway_configs.is_active`,
//! and nothing in this build reads it: every serving read filters on
//! [`CONNECTED_GATEWAY_JOIN`] instead, and
//! `billing::service::tests::no_serving_read_consults_the_retired_is_active_flag`
//! fails the build if one comes back. It is a one-way mirror kept for exactly
//! one release, for the deployment that rolls back to the previous image: that
//! image reads `is_active` as its only answer, and a gateway silently switched
//! off there is a Pay Now button that stops appearing and, worse, a webhook
//! delivery that resolves nothing while the customer's card has already been
//! charged. `crate::storage::env::ALL` carries the same kind of note for the
//! same kind of reason; the release that drops the column is the one after every
//! deployment has taken migration 256.

use sqlx::PgConnection;

use crate::modules::auth::TenantId;
use crate::utils::error::{AppError, AppResult};

/// What a serving read joins to decide that a gateway is connected.
///
/// The gateway row is `g` and the integration row is `i`, so a caller's `WHERE`
/// clause names `g.tenant_id`. One fragment rather than five copies of the same
/// join: "connected" is a definition, and five copies of a definition is four
/// chances for one of them to keep meaning what it used to.
pub const CONNECTED_GATEWAY_JOIN: &str = "JOIN integrations i \
                                          ON i.tenant_id = g.tenant_id \
                                         AND i.provider = g.provider \
                                         AND i.status = 'connected'";

/// What a read that must list every gateway, connected or not, joins instead.
///
/// A LEFT JOIN because the payments settings page has to show a gateway an MSP
/// saved and never switched on; [`CONNECTED_GATEWAY_JOIN`] would hide it.
pub const GATEWAY_INTEGRATION_LEFT_JOIN: &str = "LEFT JOIN integrations i \
                                                 ON i.tenant_id = g.tenant_id \
                                                AND i.provider = g.provider";

/// The connected flag, derived, for a read that uses
/// [`GATEWAY_INTEGRATION_LEFT_JOIN`].
///
/// `COALESCE` because a gateway with no integration row is not connected: that
/// is every `authorize_net` row (the value is not in `integrations.provider`'s
/// CHECK, and activating it is refused anyway) and any gateway saved before
/// migration 256 ran.
pub const CONNECTED_GATEWAY_FLAG: &str = "COALESCE(i.status = 'connected', FALSE)";

/// Record whether `provider` is connected for `tenant_id`, inside the caller's
/// transaction.
///
/// Upserted, because the integrations row IS the installation: a tenant who
/// switches a gateway off and on again reuses it rather than acquiring a second
/// one, and `integrations` is UNIQUE on `(tenant_id, provider)`.
///
/// Two things are deliberate about what this does NOT touch. It leaves
/// `enabled_capabilities` alone on an existing row, because what a tenant
/// delegates is their answer and switching a gateway off is not a withdrawal of
/// it; a row it creates gets `{payments}` and not the provider's whole supported
/// set, since a gateway exists because somebody wanted to take card payments and
/// enabling `invoicing` on their behalf would claim they had handed their invoice
/// issuing over. And it never writes a credential: that is
/// [`CredentialHome`](super::registry::CredentialHome), and for these two
/// providers it is the payments surface's.
///
/// `connected_at` is stamped on a connect and `disconnected_at` on a
/// disconnect, and neither is cleared by the other, so a row carries both
/// timestamps once it has been through both. That is what `contact_sync`'s
/// lifecycle columns do and it is the more useful pair to read back.
pub async fn set_payment_connection(
    tx: &mut PgConnection,
    tenant_id: TenantId,
    provider: &str,
    connected: bool,
    connected_by_user_id: Option<uuid::Uuid>,
) -> AppResult<()> {
    // Not the same status on both arms, and the difference is the point. A row
    // this call CREATES while not connecting is a gateway whose credentials were
    // saved and never switched on, which is `not_connected`; migration 256 maps
    // the existing rows the same way and says why. A row that already exists and
    // is being switched off is `disconnected`, the deliberate act, and it gets
    // the timestamp that goes with it.
    let insert_status = if connected {
        "connected"
    } else {
        "not_connected"
    };
    let update_status = if connected {
        "connected"
    } else {
        "disconnected"
    };

    sqlx::query(
        "INSERT INTO integrations \
             (tenant_id, provider, status, enabled_capabilities, connected_by_user_id, \
              connected_at, disconnected_at) \
         VALUES ($1, $2, $3, ARRAY['payments']::text[], $5, \
                 CASE WHEN $6 THEN NOW() END, NULL) \
         ON CONFLICT (tenant_id, provider) DO UPDATE \
         SET status = $4, \
             connected_by_user_id = COALESCE(EXCLUDED.connected_by_user_id, \
                                             integrations.connected_by_user_id), \
             connected_at = CASE WHEN $6 THEN NOW() ELSE integrations.connected_at END, \
             disconnected_at = CASE WHEN $6 THEN integrations.disconnected_at ELSE NOW() END, \
             last_error = NULL, \
             updated_at = NOW()",
    )
    .bind(*tenant_id)
    .bind(provider)
    .bind(insert_status)
    .bind(update_status)
    .bind(connected_by_user_id)
    .bind(connected)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // The retired mirror. See the module header: read by nothing, written here
    // so a rolled-back image still serves, dropped one release after 256.
    sqlx::query(
        "UPDATE payment_gateway_configs SET is_active = $3, updated_at = NOW() \
         WHERE tenant_id = $1 AND provider = $2",
    )
    .bind(*tenant_id)
    .bind(provider)
    .bind(connected)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}
