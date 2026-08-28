//! mokosh-contact-login prompt 002: portal capability names.
//!
//! Contact roles hold an array of these (as TEXT[] in
//! `portal_roles.capabilities`); the contact session JWT carries the
//! union in its `caps` claim; every gated route + UI element checks
//! membership against the union. `ALL_CAPABILITIES` is the canonical
//! set the MSP admin's role editor exposes as checkboxes (prompt 007)
//! and `PortalRoleService::create_role` validates against - unknown
//! capability strings fail-closed at create-time so the DB never
//! carries garbage that would silently disable a permission check.
//!
//! Naming convention: `<domain>:<action>`. `<domain>` matches the
//! mokosh-workspace tab it gates (tickets, invoices, quotes,
//! contracts, assets, projects, kb, forms, notifications, settings,
//! contacts). `<action>` is `read`, `write`, `comment`, `pay`,
//! `accept`, `submit`, `manage_own`, `invite_sub_user`,
//! `manage_sub_user` - the surface of things a contact can request
//! from the mokosh workspace. Never grants `companies:*` or
//! `contacts:create`: those stay staff-only by construction.
//!
//! PMS-936 (foundation pass): the following five per-tab granular
//! capabilities land in this migration slice as the highest-value
//! subset of the full ~26 proposed catalog. The remaining ~21 caps are
//! deferred to per-tab follow-up tickets and MUST land in NEW
//! migrations rather than editing the seeds already on `main`:
//!
//! Deferred follow-up capabilities (each becomes its own PMS ticket):
//! - `tickets:attach_download` (download attachments on tickets scoped
//!   to the Company)
//! - `tickets:request_service` (submit a service-request form; overlaps
//!   `forms:submit` if the request is form-driven)
//! - `tickets:mark_all_read` (bulk-clear notification badges on tickets)
//! - `invoices:view_payments` (see payment history against invoices)
//! - `invoices:pay_partial` (split pay flow; today `invoices:pay` covers
//!   the full-amount checkout only)
//! - `quotes:comment` (post a public comment on a quote thread)
//! - `quotes:request_revision` (kick a revise cycle back to the MSP)
//! - `contracts:comment` (post a public comment on a contract thread)
//! - `contracts:download_pdf` (download the contract PDF)
//! - `contracts:request_change` (open a change-request ticket linked to
//!   the contract)
//! - `projects:comment` (post a public comment on a project thread)
//! - `projects:approve_milestone` (accept a milestone on behalf of the
//!   Company)
//! - `assets:comment` (post a public comment on an asset)
//! - `assets:download_docs` (download asset-attached documentation)
//! - `kb:comment` (leave feedback on a KB article)
//! - `forms:list_own` (list request forms this contact submitted)
//! - `notifications:manage_own_prefs` (edit per-channel notification
//!   preferences)
//! - `notifications:mark_all_read` (bulk-clear the notification tray)
//! - `settings:manage_own_mfa` (split off from `settings:manage_own` to
//!   let a role edit profile without touching MFA)
//! - `settings:manage_own_sessions` (split off from `settings:manage_own`
//!   to let a role revoke sessions without touching profile)
//! - `contacts:list_sub_users` (read-only view of colleagues at the
//!   same Company; today folded into `contacts:manage_sub_user`)
//!
//! Each of the above stays a follow-up ticket so this pass ships fast
//! and the five foundation caps do not block on the other twenty-one.

/// See tickets in the mokosh workspace scoped to the contact's own Company.
pub const TICKETS_READ: &str = "tickets:read";
/// Open a new ticket. Server sets `created_by_contact_id` on the row.
pub const TICKETS_WRITE: &str = "tickets:write";
/// Post a public comment on an existing ticket. Cannot post internal notes.
pub const TICKETS_COMMENT: &str = "tickets:comment";
/// PMS-936: reopen a resolved or closed ticket so the MSP works on it again.
/// The server clears `closed_at` / `resolved_at`, flips the status back to
/// the tenant's default, and appends a public audit note.
pub const TICKETS_REOPEN: &str = "tickets:reopen";
/// PMS-936: attach a file (JSON base64 body) to an existing ticket the
/// caller's Company owns. Row is stamped with `created_by_contact_id`.
pub const TICKETS_ATTACH_FILE: &str = "tickets:attach_file";
/// PMS-937: correct the title or description on a ticket the calling
/// contact opened themselves. Cannot change status, priority, or
/// assignee (staff owns those); the route silently strips any
/// non-editable field from the body.
pub const TICKETS_EDIT_OWN: &str = "tickets:edit_own";
/// PMS-937: ask the MSP for formal approval on a ticket (approve
/// out-of-scope work, sign off on a resolution). Inserts a
/// `ticket_approvals` row with `requested_by_contact_id` set so the
/// SPA can render the requester as a portal contact rather than an
/// agent.
pub const TICKETS_REQUEST_APPROVAL: &str = "tickets:request_approval";

/// View invoices scoped to the contact's own Company.
pub const INVOICES_READ: &str = "invoices:read";
/// Trigger a payment checkout (Stripe / Paddle) for an outstanding invoice.
pub const INVOICES_PAY: &str = "invoices:pay";
/// PMS-936: download the rendered PDF of an invoice scoped to the
/// caller's Company. Gated separately from `invoices:read` so a
/// role can see invoice totals in the SPA without pulling the PDF.
pub const INVOICES_DOWNLOAD_PDF: &str = "invoices:download_pdf";

/// View quotes scoped to the contact's own Company.
pub const QUOTES_READ: &str = "quotes:read";
/// Accept or decline a quote on behalf of the Company.
pub const QUOTES_ACCEPT: &str = "quotes:accept";
/// PMS-936: download the rendered PDF of a quote scoped to the caller's
/// Company. Same rationale as `invoices:download_pdf`.
pub const QUOTES_DOWNLOAD_PDF: &str = "quotes:download_pdf";

/// View contracts scoped to the contact's own Company.
pub const CONTRACTS_READ: &str = "contracts:read";
/// View assets (CIs) scoped to the contact's own Company.
pub const ASSETS_READ: &str = "assets:read";
/// PMS-936: file a new ticket linked to a specific asset the caller's
/// Company owns. Creates the ticket via the standard ticket-create path
/// with `asset_id` set and `source = 'portal'`.
pub const ASSETS_REPORT_ISSUE: &str = "assets:report_issue";
/// View projects scoped to the contact's own Company.
pub const PROJECTS_READ: &str = "projects:read";
/// Read published Knowledge Base articles visible to the Company.
pub const KB_READ: &str = "kb:read";
/// Submit an MSP-published request form.
pub const FORMS_SUBMIT: &str = "forms:submit";
/// Read notifications addressed to the contact.
pub const NOTIFICATIONS_READ: &str = "notifications:read";
/// Edit own profile + password + MFA + own sessions.
pub const SETTINGS_MANAGE_OWN: &str = "settings:manage_own";
/// MAPPS-618 (mokosh-branding prompt 002): edit the caller's own
/// Company branding overrides (logo, favicon, background, colors,
/// display name, support contact block). Scope-checked server-side:
/// the endpoint derives the target Company from `caller.company_id`,
/// so a holder can only ever paint their own Company. Distinct from
/// [`SETTINGS_MANAGE_OWN`] (personal profile / password / MFA) so a
/// role can be granted profile edit without brand edit, and vice
/// versa. MSP staff never need this cap: the staff plane edits every
/// Company under their tenant via `role.is_admin()`.
pub const SETTINGS_MANAGE_COMPANY_BRANDING: &str = "settings:manage_company_branding";

/// Invite a colleague at the same Company (creates a contact + fires
/// the portal setup email). Contact-plane only; never grants
/// `contacts:create` for cross-Company contacts.
pub const CONTACTS_INVITE_SUB_USER: &str = "contacts:invite_sub_user";
/// Manage (assign roles / resend invites / deactivate) sub-user
/// contacts at the same Company. Cannot grant a capability the caller
/// does not themselves hold (server enforces the subset check in
/// prompt 008).
pub const CONTACTS_MANAGE_SUB_USER: &str = "contacts:manage_sub_user";

/// Canonical list of every capability the server + SPA recognise.
/// `PortalRoleService::create_role` validates that every string in a
/// submitted `capabilities` array appears here (fail-closed on
/// unknowns); the role editor UI (prompt 007) renders one checkbox
/// per entry.
///
/// Order matches the mokosh-workspace sidebar grouping so the checkbox
/// picker's default layout reads naturally.
pub const ALL_CAPABILITIES: &[&str] = &[
    TICKETS_READ,
    TICKETS_WRITE,
    TICKETS_COMMENT,
    TICKETS_REOPEN,
    TICKETS_ATTACH_FILE,
    TICKETS_EDIT_OWN,
    TICKETS_REQUEST_APPROVAL,
    INVOICES_READ,
    INVOICES_PAY,
    INVOICES_DOWNLOAD_PDF,
    QUOTES_READ,
    QUOTES_ACCEPT,
    QUOTES_DOWNLOAD_PDF,
    CONTRACTS_READ,
    ASSETS_READ,
    ASSETS_REPORT_ISSUE,
    PROJECTS_READ,
    KB_READ,
    FORMS_SUBMIT,
    NOTIFICATIONS_READ,
    SETTINGS_MANAGE_OWN,
    SETTINGS_MANAGE_COMPANY_BRANDING,
    CONTACTS_INVITE_SUB_USER,
    CONTACTS_MANAGE_SUB_USER,
];

/// Predicate for validating a role's capability set at write time.
/// Returns `Ok(())` when every entry in `caps` appears in
/// [`ALL_CAPABILITIES`]; returns the first offending value otherwise.
pub fn validate_capabilities(caps: &[String]) -> Result<(), String> {
    for cap in caps {
        if !ALL_CAPABILITIES.iter().any(|k| k == cap) {
            return Err(cap.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_appear_in_all_capabilities() {
        for cap in [
            TICKETS_READ,
            TICKETS_WRITE,
            TICKETS_COMMENT,
            TICKETS_REOPEN,
            TICKETS_ATTACH_FILE,
            TICKETS_EDIT_OWN,
            TICKETS_REQUEST_APPROVAL,
            INVOICES_READ,
            INVOICES_PAY,
            INVOICES_DOWNLOAD_PDF,
            QUOTES_READ,
            QUOTES_ACCEPT,
            QUOTES_DOWNLOAD_PDF,
            CONTRACTS_READ,
            ASSETS_READ,
            ASSETS_REPORT_ISSUE,
            PROJECTS_READ,
            KB_READ,
            FORMS_SUBMIT,
            NOTIFICATIONS_READ,
            SETTINGS_MANAGE_OWN,
            CONTACTS_INVITE_SUB_USER,
            CONTACTS_MANAGE_SUB_USER,
        ] {
            assert!(
                ALL_CAPABILITIES.contains(&cap),
                "capability {cap} is missing from ALL_CAPABILITIES"
            );
        }
    }

    #[test]
    fn validate_accepts_known() {
        let caps = vec![TICKETS_READ.to_string(), INVOICES_PAY.to_string()];
        assert!(validate_capabilities(&caps).is_ok());
    }

    #[test]
    fn validate_rejects_unknown() {
        let caps = vec![TICKETS_READ.to_string(), "billing:full_access".to_string()];
        assert_eq!(
            validate_capabilities(&caps).err().as_deref(),
            Some("billing:full_access")
        );
    }

    #[test]
    fn validate_accepts_empty() {
        assert!(validate_capabilities(&[]).is_ok());
    }

    #[test]
    fn all_capabilities_match_seed_migration() {
        // The migration 142 seed hardcodes the built-in role capability
        // sets as SQL string literals; keep this test as a canary that
        // every capability referenced by the seed also exists in the
        // Rust enum. If someone extends the seed with a new capability
        // string and forgets to add it here, the SPA will not gate on
        // it and this test does not catch that specific mistake - but
        // a mismatch in the other direction (Rust drops one the seed
        // still references) shows up as an unrenderable role in the UI.
        //
        // PMS-936 (migration 150) extends the built-in role capability
        // sets - Billing Contact gains the PDF-download caps; Support
        // Contact gains reopen + attach + report_issue - so those
        // strings ALSO have to appear in `ALL_CAPABILITIES`. Both
        // migrations are pinned by the same canary because migrations
        // are immutable: extending the seed happens in a NEW file, and
        // this test must know about every seed file that ships a cap
        // string.
        let seed_billing_142 = &[
            "invoices:read",
            "invoices:pay",
            "quotes:read",
            "quotes:accept",
            "notifications:read",
            "settings:manage_own",
        ];
        let seed_support_142 = &[
            "tickets:read",
            "tickets:write",
            "tickets:comment",
            "kb:read",
            "notifications:read",
            "settings:manage_own",
        ];
        let seed_readonly_142 = &[
            "tickets:read",
            "invoices:read",
            "quotes:read",
            "contracts:read",
            "assets:read",
            "projects:read",
            "kb:read",
            "notifications:read",
        ];
        // Migration 150 (PMS-936) APPENDs to the two role rows already
        // present. Only the additions are listed here; the base set is
        // still validated above via the 142 arrays.
        let seed_billing_150_add = &["invoices:download_pdf", "quotes:download_pdf"];
        let seed_support_150_add = &[
            "tickets:reopen",
            "tickets:attach_file",
            "assets:report_issue",
        ];
        // Migration 151 (PMS-937) APPENDs the contact-owned ticket edit
        // and contact-initiated approval-request caps to the Support
        // Contact row. Same immutable-migration + append-with-dedupe
        // shape as 150. Read-Only + Billing Contact are unchanged (both
        // caps mutate state and are irrelevant to the billing surface).
        let seed_support_151_add = &["tickets:edit_own", "tickets:request_approval"];
        let all_seeds: &[&[&str]] = &[
            seed_billing_142,
            seed_support_142,
            seed_readonly_142,
            seed_billing_150_add,
            seed_support_150_add,
            seed_support_151_add,
        ];
        for seed in all_seeds {
            for cap in *seed {
                assert!(
                    ALL_CAPABILITIES.iter().any(|k| k == cap),
                    "seed migration references `{cap}` but it is missing from ALL_CAPABILITIES"
                );
            }
        }
    }
}
