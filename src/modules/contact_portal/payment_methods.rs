//! MAPPS-674: portal-contact saved payment methods.
//!
//! A portal contact can save one or more cards through their payment
//! provider's own hosted page (Stripe SetupIntent today, PayPal Reference
//! Transactions later) and pick which one is their default. The card data
//! itself never touches mokosh - the provider returns a stable
//! `PaymentMethod` id and mokosh stores that plus a small display digest
//! (`brand` + `last4` + `exp_month` + `exp_year`) so the list view needs no
//! per-render API call and the future auto-charge worker (MAPPS-674 A/C
//! follow-up) can name a specific card without touching the provider on
//! every send.
//!
//! Rows live in `contact_payment_methods` (migration 218). The service owns
//! every write path:
//!
//! - [`PaymentMethodsService::start_add`] mints a SetupIntent Checkout
//!   Session on the tenant's active provider, stamps tenant + contact ids
//!   into the session metadata, and returns the hosted-page URL for the SPA
//!   to redirect to. The row does NOT exist yet: it lands when the
//!   provider fires `checkout.session.completed` and the receiver calls
//!   [`PaymentMethodsService::record_from_webhook`].
//! - [`PaymentMethodsService::list`] returns the caller's own rows in a
//!   stable order (default first, then newest).
//! - [`PaymentMethodsService::remove`] detaches the card on the provider
//!   side FIRST and then deletes the row, so a future auto-charge worker
//!   cannot resurface the card the contact told the portal to forget.
//! - [`PaymentMethodsService::set_default`] flips the picked row to
//!   `is_default = TRUE` and clears every other row of the same contact in
//!   one transaction. The partial UNIQUE index on the table enforces at
//!   most one default per contact even under concurrent writes.
//!
//! Scope-checking is belt-and-braces: every method takes a
//! [`TenantId`] and a `contact_id`, both of which appear in the WHERE
//! clause on top of the RLS policy on `contact_payment_methods`.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::auth::TenantId;
use crate::modules::billing::provider::{CheckoutSession, SetupIntentParams};
use crate::modules::billing::BillingService;
use crate::utils::error::{AppError, AppResult};

/// The service. `BillingService` is shared with the billing module because
/// it holds the provider-adapter build path (encrypted credential, HTTP
/// client). Everything else is DB writes on the payment-methods table.
#[derive(Clone)]
pub struct PaymentMethodsService {
    db: Database,
    billing: Arc<BillingService>,
}

impl PaymentMethodsService {
    pub fn new(db: Database, billing: Arc<BillingService>) -> Self {
        Self { db, billing }
    }

    /// Mint a hosted SetupIntent session so the calling contact can save a
    /// card. Returns the checkout URL for the SPA to redirect to.
    ///
    /// `success_url` / `cancel_url` come from the SPA because they are
    /// per-page (contact portal lands back on the Payment Methods page).
    /// `customer_email` is looked up from `contacts` so the setup page
    /// pre-fills; a contact without an email (edge case) sends `None`.
    ///
    /// `requested_provider` names which gateway to save the card on.
    /// `active_provider` refuses to pick between two active providers on its
    /// own (PMS-1235, the same refusal `pay_invoice` gets with no provider
    /// named), so a tenant with both Stripe and PayPal connected could not
    /// add a card at all until a caller could say which one.
    pub async fn start_add(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        requested_provider: Option<&str>,
        success_url: &str,
        cancel_url: &str,
    ) -> AppResult<CheckoutSession> {
        let email = self.contact_email(tenant_id, contact_id).await?;
        let Some(provider) = self
            .billing
            .active_provider(tenant_id, requested_provider)
            .await?
        else {
            return Err(AppError::BadRequest(
                "No active payment provider is configured for this account.".to_string(),
            ));
        };
        let params = SetupIntentParams {
            tenant_id: tenant_id.get(),
            contact_id,
            success_url,
            cancel_url,
            customer_email: email.as_deref(),
        };
        provider.create_setup_intent_session(&params).await
    }

    /// Every card the caller has saved, default first, newest next.
    pub async fn list(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<Vec<PaymentMethodResponse>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query(
            r#"
            SELECT id, provider, brand, last4, exp_month, exp_year, is_default, created_at
              FROM contact_payment_methods
             WHERE tenant_id = $1 AND contact_id = $2
             ORDER BY is_default DESC, created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|r| PaymentMethodResponse {
                id: r.get::<Uuid, _>("id"),
                provider: r.get::<String, _>("provider"),
                brand: r.get::<String, _>("brand"),
                last4: r.get::<String, _>("last4"),
                exp_month: r.get::<i16, _>("exp_month") as u8,
                exp_year: r.get::<i16, _>("exp_year") as u16,
                is_default: r.get::<bool, _>("is_default"),
                created_at: r.get::<DateTime<Utc>, _>("created_at"),
            })
            .collect())
    }

    /// Remove the caller's card. Detaches on the provider side FIRST, then
    /// deletes the row. A missing row is `NotFound` before we touch the
    /// provider so a foreign-card guess costs nothing on the wire.
    pub async fn remove(&self, tenant_id: TenantId, contact_id: Uuid, id: Uuid) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(String, String, bool)> = sqlx::query_as(
            "SELECT provider, provider_pm_id, is_default \
               FROM contact_payment_methods \
              WHERE id = $1 AND tenant_id = $2 AND contact_id = $3 \
              FOR UPDATE",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((provider_id, provider_pm_id, was_default)) = row else {
            tx.commit().await?;
            return Err(AppError::NotFound("Payment method".to_string()));
        };
        // Detach on the provider side BEFORE deleting our row: if the detach
        // fails the row stays so the contact can retry, and a future
        // auto-charge cannot use a card mokosh no longer knows about.
        let Some(provider) = self
            .billing
            .active_provider(tenant_id, Some(&provider_id))
            .await?
        else {
            return Err(AppError::BadRequest(format!(
                "The {provider_id} gateway is no longer active on this account, \
                 so the card cannot be detached. Reconnect the gateway to remove saved cards."
            )));
        };
        provider.detach_payment_method(&provider_pm_id).await?;
        sqlx::query(
            "DELETE FROM contact_payment_methods \
              WHERE id = $1 AND tenant_id = $2 AND contact_id = $3",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(contact_id)
        .execute(&mut *tx)
        .await?;
        // PMS-1235: removing the default left the contact with no default at
        // all, even with other cards still on file, and the future
        // auto-charge worker this table exists for (MAPPS-674) names a
        // specific card by looking here. Newest first, the same order
        // `record_from_webhook` gives the contact's very first card.
        if was_default {
            sqlx::query(
                "UPDATE contact_payment_methods SET is_default = TRUE, updated_at = NOW() \
                  WHERE id = (
                      SELECT id FROM contact_payment_methods \
                       WHERE tenant_id = $1 AND contact_id = $2 \
                       ORDER BY created_at DESC \
                       LIMIT 1 \
                       FOR UPDATE \
                  )",
            )
            .bind(tenant_id)
            .bind(contact_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// PMS-1369: detach every saved card a contact holds, on the provider
    /// side only, before the caller deletes the `contacts` row that
    /// `contact_payment_methods.contact_id ON DELETE CASCADE` would
    /// otherwise remove silently. Mirrors [`Self::remove`]'s contract
    /// exactly (detach first, same "gateway no longer active" refusal) but
    /// does not touch the rows itself: the caller's own `DELETE FROM
    /// contacts` removes them via the cascade once every detach has
    /// succeeded.
    ///
    /// Takes the caller's own transaction rather than opening one, and locks
    /// the rows `FOR UPDATE` in it, so the read and the contact delete that
    /// follows are atomic: a card added between the read and the delete
    /// cannot slip through undetached. A detach failure returns the error
    /// without touching anything; the caller's transaction is left for it to
    /// roll back, leaving the contact and its payment method rows in place.
    pub async fn detach_all_for_contact(
        &self,
        tx: &mut crate::db::TenantTransaction<'_>,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<()> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT provider, provider_pm_id \
               FROM contact_payment_methods \
              WHERE tenant_id = $1 AND contact_id = $2 \
              FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_all(&mut **tx)
        .await?;
        for (provider_id, provider_pm_id) in rows {
            let Some(provider) = self
                .billing
                .active_provider(tenant_id, Some(&provider_id))
                .await?
            else {
                return Err(AppError::BadRequest(format!(
                    "The {provider_id} gateway is no longer active on this account, \
                     so the card cannot be detached. Reconnect the gateway to delete this contact."
                )));
            };
            provider.detach_payment_method(&provider_pm_id).await?;
        }
        Ok(())
    }

    /// Flip the picked row to `is_default = TRUE` and clear every other row
    /// of the same contact in ONE transaction. The partial UNIQUE index on
    /// the table enforces at most one default even under concurrent writes.
    pub async fn set_default(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        id: Uuid,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        // Clear the currently-default row FIRST so the partial UNIQUE index
        // never sees two `is_default = TRUE` rows at once. The order is
        // load-bearing.
        sqlx::query(
            "UPDATE contact_payment_methods \
                SET is_default = FALSE, updated_at = NOW() \
              WHERE tenant_id = $1 AND contact_id = $2 \
                AND is_default = TRUE AND id <> $3",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        let updated = sqlx::query(
            "UPDATE contact_payment_methods \
                SET is_default = TRUE, updated_at = NOW() \
              WHERE id = $1 AND tenant_id = $2 AND contact_id = $3",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(contact_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            tx.rollback().await?;
            return Err(AppError::NotFound("Payment method".to_string()));
        }
        tx.commit().await?;
        Ok(())
    }

    /// Insert a row from a verified provider webhook (`checkout.session.
    /// completed` in `mode: 'setup'`). Idempotent on the provider's own
    /// reference: a redelivery `ON CONFLICT DO NOTHING`s and returns without
    /// touching the row.
    ///
    /// The FIRST card the contact ever saves is set as their default, per
    /// the operator decision on MAPPS-674: nobody wants an extra click on a
    /// page holding one card. Every subsequent card lands as
    /// `is_default = FALSE`.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_from_webhook(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
        provider_id: &str,
        provider_pm_id: &str,
        _provider_customer_id: &str,
        brand: &str,
        last4: &str,
        exp_month: u8,
        exp_year: u16,
    ) -> AppResult<()> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let existing_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM contact_payment_methods \
              WHERE tenant_id = $1 AND contact_id = $2",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .fetch_one(&mut *tx)
        .await?;
        let is_default = existing_count == 0;
        sqlx::query(
            "INSERT INTO contact_payment_methods \
             (tenant_id, contact_id, provider, provider_pm_id, brand, last4, exp_month, exp_year, is_default) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (tenant_id, provider, provider_pm_id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(contact_id)
        .bind(provider_id)
        .bind(provider_pm_id)
        .bind(brand.to_ascii_lowercase())
        .bind(last4)
        .bind(exp_month as i16)
        .bind(exp_year as i16)
        .bind(is_default)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn contact_email(
        &self,
        tenant_id: TenantId,
        contact_id: Uuid,
    ) -> AppResult<Option<String>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT email FROM contacts WHERE id = $1 AND tenant_id = $2")
                .bind(contact_id)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(row.and_then(|(e,)| e))
    }
}

/// One row of `GET /contact/payment-methods`, serialised.
#[derive(Debug, Clone, Serialize)]
pub struct PaymentMethodResponse {
    pub id: Uuid,
    pub provider: String,
    pub brand: String,
    pub last4: String,
    pub exp_month: u8,
    pub exp_year: u16,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
}
