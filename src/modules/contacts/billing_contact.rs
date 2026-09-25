//! PMS-1000: who a document is addressed to, defined once.
//!
//! Two flows send a customer a document they are asked to act on: an invoice
//! (PMS-993) and a quote. Both answer the same two questions - is this contact
//! allowed to be the recipient for this company, and who is the recipient when
//! the caller named nobody - and both got them wrong in their own way. The
//! invoice path bound `billing_contact_id` straight from the request with no
//! check at all, so it could be addressed to another tenant's contact, because
//! an FK check bypasses RLS. The quote path validated the contact but never
//! resolved one, so a quote reached `sent` with nobody to mail and said so only
//! in an `info` log.
//!
//! The answer lives here rather than in either service so the two cannot drift
//! on what "the company's billing contact" means. It reads `contacts` and
//! `companies.default_billing_contact_id`, which is why it sits under
//! `modules/contacts` and not under one of its consumers.

use uuid::Uuid;

use crate::modules::auth::tenant::TenantId;
use crate::utils::error::{AppError, AppResult};

/// Validate that `contact_id` is a contact of `company_id` in this tenant.
///
/// Membership accepts either carrier, because both are live: the legacy
/// `contacts.company_id` scalar (which PMS-806 keeps as the mirror of the
/// primary link) and a `contact_companies` row for a contact who works at
/// several companies.
pub async fn assert_for_company(
    tx: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    company_id: Uuid,
    contact_id: Uuid,
) -> AppResult<()> {
    let found: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM contacts c \
         WHERE c.tenant_id = $1 AND c.id = $3 \
           AND (c.company_id = $2 \
                OR EXISTS(SELECT 1 FROM contact_companies l \
                          WHERE l.tenant_id = $1 AND l.contact_id = c.id \
                            AND l.company_id = $2)))",
    )
    .bind(tenant_id)
    .bind(company_id)
    .bind(contact_id)
    .fetch_one(&mut *tx)
    .await?;
    if !found {
        return Err(AppError::BadRequest(
            "billing_contact_id does not reference a contact of this company".to_string(),
        ));
    }
    Ok(())
}

/// The recipient to record on a document for `company_id`.
///
/// An explicitly named contact is validated against this company and tenant
/// and then used. Otherwise the company's `default_billing_contact_id` is the
/// answer, and `None` means the company has nobody: the caller decides whether
/// that is a refusal (a send) or simply a document that names nobody yet (a
/// draft).
pub async fn resolve(
    tx: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    company_id: Uuid,
    requested: Option<Uuid>,
) -> AppResult<Option<Uuid>> {
    if let Some(contact_id) = requested {
        assert_for_company(tx, tenant_id, company_id, contact_id).await?;
        return Ok(requested);
    }
    let default_contact: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT default_billing_contact_id FROM companies WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_optional(&mut *tx)
    .await?;
    Ok(default_contact.flatten())
}
