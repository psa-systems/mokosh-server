//! PMS-1186: designating a billing contact also lets them see the invoice.
//!
//! Two unrelated things were both called "the billing contact" and nothing
//! kept them in step. `companies.default_billing_contact_id`, and
//! `invoices.billing_contact_id` beside it, decide who RECEIVES the invoice
//! email with its pay link: `resolve_invoice_recipient` reads those two
//! columns and nothing else. A portal role assignment holding
//! `invoices:read` decides who can SEE an invoice after signing in. They are
//! set on different screens and no rule connected them.
//!
//! So the ordinary path failed quietly. The MSP designates Jane as the
//! company's billing contact, sends her an invoice, the mail goes out with a
//! Pay link, and Jane signs in to a portal that shows her nothing, because the
//! access she was granted months ago was for tickets. She cannot pay, and the
//! MSP sees a sent invoice and no sign that its recipient cannot read it.
//!
//! This is not a contact with NO role: `grant_portal_access` refuses an empty
//! role list. It is a contact whose role does not match what the MSP later
//! asked of them.
//!
//! The connection used to exist. The retired `/portal/*` router gated invoices
//! on `default_billing_contact_id` itself (PMS-993), so the two notions were
//! one thing; PMS-1064 retired that router, capabilities became the only gate,
//! and the column quietly kept its other job.

use uuid::Uuid;

use crate::modules::audit::{audit_write, AuditAction, AuditCtx};
use crate::modules::auth::TenantId;
use crate::modules::contact_portal::capabilities::INVOICES_READ;
use crate::utils::error::AppResult;

/// The built-in role a billing contact is given, by the name
/// `seed_builtin_portal_roles` inserts.
const BILLING_CONTACT_ROLE: &str = "Billing Contact";

/// Make sure `contact_id` can read invoices, and say whether that changed
/// anything.
///
/// Runs INSIDE the caller's transaction, so a rolled-back company update or a
/// refused invoice send grants nothing. Three rules, in order:
///
/// 1. A contact who is not a portal user is left alone. A role granted to
///    somebody who cannot sign in changes nothing, and flipping
///    `is_portal_user` here would invite a person to a portal without anyone
///    deciding to - the invitation is the MSP's to make (PMS-1187).
/// 2. A contact whose effective capabilities already include `invoices:read`
///    is left alone, so nothing is added to somebody who can already do the
///    thing, whichever role gave it to them.
/// 3. Otherwise the tenant's built-in `Billing Contact` role is assigned, and
///    an audit row records it against the contact.
///
/// Granting rather than warning is the decision here. The MSP has already said
/// this person handles their invoices; letting them read the invoice they were
/// just emailed makes that decision coherent rather than widening it, and the
/// assignment is audited and shows up in the role editor, so it can be seen
/// and undone.
pub(crate) async fn ensure_can_read_invoices(
    tx: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    contact_id: Uuid,
    ctx: &AuditCtx,
) -> AppResult<bool> {
    let is_portal_user: Option<bool> =
        sqlx::query_scalar("SELECT is_portal_user FROM contacts WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(contact_id)
            .fetch_optional(&mut *tx)
            .await?;
    if is_portal_user != Some(true) {
        return Ok(false);
    }

    // The same union `load_contact_capabilities` computes on every request,
    // asked here for one capability. Read inside the transaction rather than
    // through that helper, which runs on the migrator pool: a grant this
    // transaction is about to make and then roll back must not be visible to
    // the decision, and the reverse - a role assigned moments ago in this same
    // transaction - must be.
    let already: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
           SELECT 1 FROM contact_role_assignments cra \
           INNER JOIN portal_roles pr ON pr.id = cra.role_id \
           WHERE cra.tenant_id = $1 AND cra.contact_id = $2 AND $3 = ANY(pr.capabilities) \
         )",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .bind(INVOICES_READ)
    .fetch_one(&mut *tx)
    .await?;
    if already {
        return Ok(false);
    }

    // The tenant-wide built-in, never a company-scoped role of the same name:
    // a company-scoped one is the MSP's own creation and is not this
    // function's to hand out.
    let role_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM portal_roles \
         WHERE tenant_id = $1 AND company_id IS NULL AND is_builtin = TRUE AND name = $2",
    )
    .bind(tenant_id)
    .bind(BILLING_CONTACT_ROLE)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(role_id) = role_id else {
        // A tenant provisioned before the built-ins were seeded, or one whose
        // admin renamed them. Warned rather than failed: the caller is
        // updating a company or sending an invoice, and neither should be
        // refused over a role that is not there to grant.
        tracing::warn!(
            target: "mokosh_server.contacts",
            %contact_id,
            "no built-in Billing Contact role to grant; the billing contact cannot read invoices"
        );
        return Ok(false);
    };

    sqlx::query(
        "INSERT INTO contact_role_assignments (contact_id, role_id, tenant_id) \
         VALUES ($1, $2, $3) ON CONFLICT (contact_id, role_id) DO NOTHING",
    )
    .bind(contact_id)
    .bind(role_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await?;

    audit_write(
        &mut *tx,
        tenant_id,
        ctx,
        AuditAction::Update,
        "contacts",
        Some(contact_id),
        None,
        Some(serde_json::json!({
            "portal_role_granted": BILLING_CONTACT_ROLE,
            "reason": "designated as a billing contact",
            "role_id": role_id,
        })),
    )
    .await?;
    Ok(true)
}
