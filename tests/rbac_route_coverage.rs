//! Role x route coverage matrix (PMS-350).
//!
//! External review found a technician role could reach Team, Audit Log,
//! Financial reports, Contracts, and Rate Cards. The Invoices page already
//! gated correctly (`RequireFinance`); the sibling surfaces did not. This
//! suite logs in as every role and walks the protected routes, asserting the
//! exact allow / deny matrix so a future feature can't silently re-open a
//! gap.
//!
//! Every blocked route must return `403 FORBIDDEN` (the same `AppError`
//! envelope Invoices returns), never `200`. Allowed roles get a `200`.
//! All modules are enabled for the seeded default tenant (migration
//! `023_seed_data.sql`), so the module-enable gate always passes and the
//! role gate is what these assertions exercise.

mod common;

use reqwest::StatusCode;
use sqlx::PgPool;

/// Every role the PSA defines.
const ALL_ROLES: &[&str] = &[
    "super_admin",
    "admin",
    "manager",
    "technician",
    "dispatcher",
    "sales",
    "finance",
];

/// Finance / billing surfaces: the gate Invoices already enforces
/// (`RequireFinance` == `super_admin | admin | finance`).
const FINANCE_ROLES: &[&str] = &["super_admin", "admin", "finance"];

/// Admin-only surfaces (`RequireAdmin`).
const ADMIN_ROLES: &[&str] = &["super_admin", "admin"];

/// Manager-and-up surfaces (`RequireManager`).
const MANAGER_ROLES: &[&str] = &["super_admin", "admin", "manager"];

/// Seed one active user per role under the default tenant, log each in, and
/// return `(role, bearer_token)` pairs.
async fn tokens_per_role(app: &common::TestApp, pool: &PgPool) -> Vec<(&'static str, String)> {
    let mut out = Vec::with_capacity(ALL_ROLES.len());
    for &role in ALL_ROLES {
        let email = format!("rbac-{role}@example.com");
        let (_id, email, pw) =
            common::seed_user(pool, common::DEFAULT_TENANT_ID, &email, role).await;
        let token = common::login(app, &email, &pw).await;
        out.push((role, token));
    }
    out
}

/// Assert that GET `path` is allowed (200) for `allowed` roles and forbidden
/// (403) for every other role.
async fn assert_matrix(
    app: &common::TestApp,
    tokens: &[(&'static str, String)],
    path: &str,
    allowed: &[&str],
) {
    for (role, token) in tokens {
        let status = app
            .client
            .get(app.url(path))
            .bearer_auth(token)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path} as {role}: {e}"))
            .status();

        if allowed.contains(role) {
            assert_eq!(
                status,
                StatusCode::OK,
                "{role} should be allowed on {path}, got {status}"
            );
        } else {
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{role} should be forbidden on {path}, got {status}"
            );
        }
    }
}

#[sqlx::test]
async fn role_route_coverage_matrix(pool: PgPool) {
    let app = common::boot(pool.clone()).await;
    let tokens = tokens_per_role(&app, &pool).await;

    // Reference surface: Invoices already gated correctly. Every other
    // financial surface must match this exact allow set.
    assert_matrix(&app, &tokens, "/api/v1/invoices", FINANCE_ROLES).await;

    // Contracts + Rate Cards: read must be blocked for non-finance roles
    // (writes were already gated; PMS-350 closes the read side).
    assert_matrix(&app, &tokens, "/api/v1/contracts", FINANCE_ROLES).await;
    assert_matrix(&app, &tokens, "/api/v1/rate-cards", FINANCE_ROLES).await;

    // Quotes (PMS-672): a priced commercial document, so it joins the
    // financial surfaces rather than getting a policy of its own.
    assert_matrix(&app, &tokens, "/api/v1/quotes", FINANCE_ROLES).await;

    // Financial reports: the direct route and the CSV export side-door both
    // enforce the Invoices gate. Covers both the Revenue & A/R report
    // (/reports/billing) and Client Profitability (/reports/clients), which
    // sums invoiced/paid/outstanding from the invoices table (PMS-350).
    assert_matrix(&app, &tokens, "/api/v1/reports/billing", FINANCE_ROLES).await;
    assert_matrix(
        &app,
        &tokens,
        "/api/v1/reports/billing/export?format=csv",
        FINANCE_ROLES,
    )
    .await;
    assert_matrix(&app, &tokens, "/api/v1/reports/clients", FINANCE_ROLES).await;
    assert_matrix(
        &app,
        &tokens,
        "/api/v1/reports/clients/export?format=csv",
        FINANCE_ROLES,
    )
    .await;

    // PMS-962: the six read routes that carried only the module gate, so a
    // technician refused `/api/v1/invoices` two lines up was served
    // `/api/v1/statements`, which holds the same invoice totals plus the whole
    // payment history. Three separate changes each added a route without the
    // role gate (PMS-953 credit notes, PMS-954 statements, PMS-955 products),
    // which is why `billing::routes::finance_gate` now enforces the rule in
    // source rather than leaving it to review. These rows are the behavioural
    // half of that: the guard proves the extractor is present, this proves the
    // extractor does what it is there for.
    let company_id = common::seed_company(&pool).await;
    assert_matrix(
        &app,
        &tokens,
        &format!(
            "/api/v1/statements?company_id={company_id}&period_start=2026-08-01&period_end=2026-08-31"
        ),
        FINANCE_ROLES,
    )
    .await;
    assert_matrix(&app, &tokens, "/api/v1/credit-notes", FINANCE_ROLES).await;
    assert_matrix(&app, &tokens, "/api/v1/products", FINANCE_ROLES).await;
    // The seeded tenant has a default rate and the handler falls back to it, so
    // an allowed role gets a 200 here rather than a 404.
    assert_matrix(
        &app,
        &tokens,
        "/api/v1/tax-rates/lookup?name=No%20Tax",
        FINANCE_ROLES,
    )
    .await;

    // PMS-876: and the PDF format of both, because a new output format is
    // exactly the shape a side-door around a permission takes. The gate sits
    // above the format switch in `export_report` so it cannot be added to one
    // branch and forgotten in the other, and these two rows are what would
    // fail if it ever moved below.
    assert_matrix(
        &app,
        &tokens,
        "/api/v1/reports/billing/export?format=pdf",
        FINANCE_ROLES,
    )
    .await;
    assert_matrix(
        &app,
        &tokens,
        "/api/v1/reports/clients/export?format=pdf",
        FINANCE_ROLES,
    )
    .await;

    // Admin -> Team (invitations / Send invite) and Admin -> Audit Log.
    assert_matrix(&app, &tokens, "/api/v1/invitations", ADMIN_ROLES).await;
    assert_matrix(&app, &tokens, "/api/v1/audit-log", ADMIN_ROLES).await;

    // Admin -> Team (user list) is manager-and-up.
    assert_matrix(&app, &tokens, "/api/v1/auth/users", MANAGER_ROLES).await;
}
