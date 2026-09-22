//! PMS-977: a draft invoice raised against the wrong company can be moved to
//! the right one, the move is audited, and a sent invoice cannot be moved.
//!
//! There is no invoice delete, so before this a draft on the wrong company had
//! no recovery at all. What the move refuses is a draft whose contents belong
//! where they are: billed time, a contract, a payment, or a line naming
//! another company's ticket.

mod common;

use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

struct Fixture {
    app: common::TestApp,
    pool: PgPool,
    token: String,
    admin_id: Uuid,
    acme: Uuid,
    globex: Uuid,
}

impl Fixture {
    async fn new(pool: PgPool) -> Self {
        common::storage_root();
        let (admin_id, email, password) = common::seed_admin(&pool).await;
        let acme = common::seed_company_named(&pool, "Acme Ltd").await;
        let globex = common::seed_company_named(&pool, "Globex Corp").await;
        let app = common::boot_rls(pool.clone()).await;
        let token = common::login(&app, &email, &password).await;
        Self {
            app,
            pool,
            token,
            admin_id,
            acme,
            globex,
        }
    }

    async fn draft(&self, company_id: Uuid, billing_contact_id: Option<Uuid>) -> String {
        let (status, invoice) = self
            .call(
                reqwest::Method::POST,
                "/api/v1/invoices",
                json!({
                    "company_id": company_id,
                    "billing_contact_id": billing_contact_id,
                    "invoice_date": "2026-09-01",
                    "due_date": "2026-09-30",
                    "lines": [{
                        "line_type": "service",
                        "description": "Managed services, September",
                        "quantity": "1",
                        "unit_price": "900.00",
                    }],
                }),
            )
            .await;
        assert!(status.is_success(), "create invoice: {status} {invoice}");
        invoice["id"].as_str().expect("id").to_string()
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Value) -> (StatusCode, Value) {
        let response = self
            .app
            .client
            .request(method, self.app.url(path))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .expect("request");
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn update(&self, invoice_id: &str, body: Value) -> (StatusCode, Value) {
        self.call(
            reqwest::Method::PUT,
            &format!("/api/v1/invoices/{invoice_id}"),
            body,
        )
        .await
    }

    async fn company_changes(&self, invoice_id: &str) -> Vec<(Option<Uuid>, Value, Value)> {
        sqlx::query_as(
            "SELECT user_id, old_values, new_values FROM audit_log \
             WHERE entity_type = 'invoices' AND entity_id = $1 \
               AND new_values->>'event' = 'invoice.company_changed' \
             ORDER BY \"timestamp\"",
        )
        .bind(invoice_id.parse::<Uuid>().unwrap())
        .fetch_all(&self.pool)
        .await
        .expect("audit rows")
    }
}

/// The case the issue was filed for: a draft on the wrong company moves, its
/// old company's contact goes with the old company, and the move is audited
/// with who, both companies, and their names.
#[sqlx::test]
async fn a_draft_moves_to_another_company_and_the_move_is_audited(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let acme_contact = common::seed_billing_contact(&f.pool, f.acme).await;
    let invoice = f.draft(f.acme, Some(acme_contact)).await;

    let (status, moved) = f.update(&invoice, json!({ "company_id": f.globex })).await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["company_id"], json!(f.globex));
    assert_eq!(
        moved["billing_contact_id"],
        Value::Null,
        "Acme's contact is not Globex's person"
    );
    assert_eq!(moved["status"], "draft");

    let rows = f.company_changes(&invoice).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (actor, old, new) = &rows[0];
    assert_eq!(*actor, Some(f.admin_id));
    assert_eq!(old["company_id"], json!(f.acme));
    assert_eq!(old["company_name"], "Acme Ltd");
    assert_eq!(new["company_id"], json!(f.globex));
    assert_eq!(new["company_name"], "Globex Corp");
}

/// Naming one of the new company's contacts in the same request keeps it;
/// naming one of the old company's is refused against the new company.
#[sqlx::test]
async fn the_billing_contact_follows_the_new_company(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let acme_contact = common::seed_billing_contact(&f.pool, f.acme).await;
    let globex_contact = common::seed_billing_contact(&f.pool, f.globex).await;
    let invoice = f.draft(f.acme, Some(acme_contact)).await;

    let (status, _) = f
        .update(
            &invoice,
            json!({ "company_id": f.globex, "billing_contact_id": acme_contact }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "Acme's contact on Globex");

    let (status, moved) = f
        .update(
            &invoice,
            json!({ "company_id": f.globex, "billing_contact_id": globex_contact }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["billing_contact_id"], json!(globex_contact));
}

/// Once sent, the customer holds it: the company is locked, and the refusal
/// says what to do instead.
#[sqlx::test]
async fn a_sent_invoice_cannot_move(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let invoice = f.draft(f.acme, None).await;
    let (status, sent) = f
        .update(&invoice, json!({ "status": "sent", "skip_email": true }))
        .await;
    assert_eq!(status, StatusCode::OK, "{sent}");

    let (status, body) = f.update(&invoice, json!({ "company_id": f.globex })).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("credit note"), "{body}");
    assert!(f.company_changes(&invoice).await.is_empty());
    let company: Uuid = sqlx::query_scalar("SELECT company_id FROM invoices WHERE id = $1")
        .bind(invoice.parse::<Uuid>().unwrap())
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(company, f.acme);
}

/// PMS-1367: the same check on the paths that CREATE, where the hole was
/// found. An FK check bypasses RLS, so another tenant's company id satisfies
/// it; an invoice, a generated invoice and an unapplied payment would each
/// have named a company the caller cannot see.
#[sqlx::test]
async fn a_foreign_company_cannot_be_created_against(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (other_tenant, _, _, _) = common::seed_tenant_with_admin(&f.pool, "other-msp").await;
    let foreign = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Foreign Co')")
        .bind(foreign)
        .bind(other_tenant)
        .execute(&f.pool)
        .await
        .expect("foreign company");

    for company in [foreign, Uuid::new_v4()] {
        let (status, body) = f
            .call(
                reqwest::Method::POST,
                "/api/v1/invoices",
                json!({
                    "company_id": company,
                    "invoice_date": "2026-09-01",
                    "lines": [{
                        "line_type": "service",
                        "description": "Work",
                        "quantity": "1",
                        "unit_price": "10.00",
                    }],
                }),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "invoice: {body}");
        assert!(body.to_string().contains("company_id"), "{body}");

        // Generated from time entries: without the check this refuses for
        // having no billable time, which is not what is wrong.
        let (status, body) = f
            .call(
                reqwest::Method::POST,
                "/api/v1/invoices/from-time-entries",
                json!({ "company_id": company, "invoice_date": "2026-09-01" }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "generated: {body}"
        );
        assert!(
            !body.to_string().contains("billable"),
            "the refusal is about the company: {body}"
        );

        // An unapplied payment names no invoice to be checked against.
        let (status, body) = f
            .call(
                reqwest::Method::POST,
                "/api/v1/payments",
                json!({
                    "company_id": company,
                    "payment_date": "2026-09-02",
                    "amount": "50.00",
                    "payment_method": "check",
                }),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "payment: {body}");
    }

    let written: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM invoices) + (SELECT count(*) FROM payments)",
    )
    .fetch_one(&f.pool)
    .await
    .expect("count");
    assert_eq!(written, 0, "nothing was written");
}

/// The applied-payment path keeps its own refusal: the company has to match
/// the invoice's, which already pins it to this tenant (PMS-1235).
#[sqlx::test]
async fn a_payment_still_has_to_match_its_invoices_company(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let invoice = f.draft(f.acme, None).await;
    let (status, body) = f
        .call(
            reqwest::Method::POST,
            "/api/v1/payments",
            json!({
                "invoice_id": invoice,
                "company_id": f.globex,
                "payment_date": "2026-09-02",
                "amount": "50.00",
                "payment_method": "check",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("does not match"), "{body}");
}

/// Another tenant's company, or one that does not exist, is refused: the FK
/// alone would accept the first, because it bypasses RLS.
#[sqlx::test]
async fn only_a_company_of_this_organization_is_accepted(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (other_tenant, _, _, _) = common::seed_tenant_with_admin(&f.pool, "other-msp").await;
    let foreign = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, 'Foreign Co')")
        .bind(foreign)
        .bind(other_tenant)
        .execute(&f.pool)
        .await
        .expect("foreign company");
    let invoice = f.draft(f.acme, None).await;

    for company in [foreign, Uuid::new_v4()] {
        let (status, body) = f.update(&invoice, json!({ "company_id": company })).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{company}: {body}"
        );
    }
    assert!(f.company_changes(&invoice).await.is_empty());
}

/// Naming the company it already has is not a move.
#[sqlx::test]
async fn the_same_company_is_not_a_move(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let contact = common::seed_billing_contact(&f.pool, f.acme).await;
    let invoice = f.draft(f.acme, Some(contact)).await;
    let (status, same) = f.update(&invoice, json!({ "company_id": f.acme })).await;
    assert_eq!(status, StatusCode::OK, "{same}");
    assert_eq!(
        same["billing_contact_id"],
        json!(contact),
        "nothing cleared"
    );
    assert!(f.company_changes(&invoice).await.is_empty());
}

/// A draft whose contents are its company's stays with its company, and the
/// refusal names what holds it there. Each case is set up directly, then the
/// invoice is shown to be unchanged.
#[sqlx::test]
async fn a_draft_holding_its_companys_work_stays_put(pool: PgPool) {
    let f = Fixture::new(pool).await;

    // Billed time.
    let billed = f.draft(f.acme, None).await;
    let work_type: Uuid = sqlx::query_scalar(
        "INSERT INTO work_types (tenant_id, name) VALUES ($1, 'Onsite') RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&f.pool)
    .await
    .expect("work type");
    sqlx::query(
        "INSERT INTO time_entries (tenant_id, user_id, date, duration_minutes, work_type_id, \
                                   company_id, is_billable, billing_status, invoice_id, \
                                   hourly_rate, total_amount) \
         VALUES ($1, $2, '2026-09-01', 60, $3, $4, TRUE, 'billed', $5, 150.00, 150.00)",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(f.admin_id)
    .bind(work_type)
    .bind(f.acme)
    .bind(billed.parse::<Uuid>().unwrap())
    .execute(&f.pool)
    .await
    .expect("billed time entry");

    // A line naming Acme's project.
    let ticketed = f.draft(f.acme, None).await;
    let project: Uuid = sqlx::query_scalar(
        "INSERT INTO projects (tenant_id, name, company_id) \
         VALUES ($1, 'Office move', $2) RETURNING id",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(f.acme)
    .fetch_one(&f.pool)
    .await
    .expect("project");
    sqlx::query("UPDATE invoice_lines SET project_id = $2 WHERE invoice_id = $1")
        .bind(ticketed.parse::<Uuid>().unwrap())
        .bind(project)
        .execute(&f.pool)
        .await
        .expect("line names the project");

    // A recorded payment.
    let paid = f.draft(f.acme, None).await;
    sqlx::query(
        "INSERT INTO payments (tenant_id, invoice_id, company_id, payment_date, amount, payment_method) \
         VALUES ($1, $2, $3, '2026-09-02', 100, 'check')",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .bind(paid.parse::<Uuid>().unwrap())
    .bind(f.acme)
    .execute(&f.pool)
    .await
    .expect("payment");

    for (invoice, holds) in [
        (&billed, "time entr"),
        (&ticketed, "ticket or project"),
        (&paid, "payment"),
    ] {
        let (status, body) = f.update(invoice, json!({ "company_id": f.globex })).await;
        assert_eq!(status, StatusCode::CONFLICT, "{holds}: {body}");
        let message = body.to_string();
        assert!(message.contains(holds), "{message}");
        assert!(
            message.contains("Acme Ltd") && message.contains("Globex Corp"),
            "{message}"
        );
        let company: Uuid = sqlx::query_scalar("SELECT company_id FROM invoices WHERE id = $1")
            .bind(invoice.parse::<Uuid>().unwrap())
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(company, f.acme, "{holds}: unchanged");
    }
}
