//! PMS-953: credit notes, the correction path an issued invoice never had.
//!
//! Before this, `update_invoice` refused every edit once an invoice was frozen
//! and nothing anywhere wrote `void` or `written_off`, so an MSP that sent a
//! wrong invoice had no move inside the product. These tests pin the path that
//! replaces that dead end, and pin the rules that are easy to get wrong in the
//! other direction: crediting a draft, crediting past the total, hiding a
//! charge inside a credit, and moving the status ladder for invoices that have
//! no credits at all.
//!
//! PMS-1333 took one rule back out. Crediting used to be what wrote `void`,
//! which read a credited invoice as a cancelled one; it is not, so a credit
//! that clears the balance now settles the invoice to `paid` and voiding is
//! `POST /invoices/{id}/void`, its own act with its own preconditions.

mod common;

use mokosh_test::mokosh_test;
use rust_decimal::Decimal;
use serde_json::Value;
use sqlx::PgPool;
use std::str::FromStr;

/// Create a company, then an invoice for `amount` on it, and send it. Returns
/// `(company_id, invoice_id)`. Sending is the point: a credit note is only
/// meaningful against a document the customer already holds.
async fn sent_invoice(
    app: &common::TestApp,
    token: &str,
    pool: &PgPool,
    amount: &str,
) -> (uuid::Uuid, String) {
    let company_id = common::seed_company(pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(pool, company_id).await;
    let invoice_id = draft_invoice(app, token, company_id, amount).await;
    send_invoice(app, token, &invoice_id).await;
    (company_id, invoice_id)
}

async fn draft_invoice(
    app: &common::TestApp,
    token: &str,
    company_id: uuid::Uuid,
    amount: &str,
) -> String {
    let resp = app
        .client
        .post(app.url("/api/v1/invoices"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "company_id": company_id,
            "invoice_date": "2026-08-01",
            "due_date": "2026-08-31",
            "lines": [{
                "line_type": "service",
                "description": "Managed services, August",
                "quantity": "1",
                "unit_price": amount,
            }],
        }))
        .send()
        .await
        .expect("send create invoice");
    assert!(
        resp.status().is_success(),
        "create invoice should 2xx, got {}",
        resp.status()
    );
    let invoice: Value = resp.json().await.expect("invoice JSON");
    invoice["id"].as_str().expect("invoice id").to_string()
}

async fn send_invoice(app: &common::TestApp, token: &str, invoice_id: &str) {
    let resp = app
        .client
        .put(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .json(&serde_json::json!({ "status": "sent", "skip_email": true }))
        .send()
        .await
        .expect("send invoice");
    assert!(
        resp.status().is_success(),
        "sending the invoice should 2xx, got {}",
        resp.status()
    );
}

async fn get_invoice(app: &common::TestApp, token: &str, invoice_id: &str) -> Value {
    let resp = app
        .client
        .get(app.url(&format!("/api/v1/invoices/{invoice_id}")))
        .bearer_auth(token)
        .send()
        .await
        .expect("send get invoice");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    resp.json().await.expect("invoice JSON")
}

/// Raise a credit note. Returns the raw response so a test can assert on a
/// refusal as easily as on a success.
async fn credit(
    app: &common::TestApp,
    token: &str,
    invoice_id: &str,
    amount: &str,
) -> reqwest::Response {
    app.client
        .post(app.url("/api/v1/credit-notes"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "reason": "Billed for a month the client had already cancelled",
            "lines": [{
                "line_type": "adjustment",
                "description": "August managed services",
                "quantity": "1",
                "unit_price": amount,
            }],
        }))
        .send()
        .await
        .expect("send create credit note")
}

fn dec(v: &Value) -> Decimal {
    Decimal::from_str(v.as_str().unwrap_or("0")).expect("decimal")
}

/// The invoice is corrected without being touched: its own lines, total and
/// number are exactly what the customer received, and only the derived balance
/// moves. That separation is the whole reason a credit note exists rather than
/// an edit.
#[mokosh_test]
async fn a_credit_reduces_the_balance_without_editing_the_invoice(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let (_company_id, invoice_id) = sent_invoice(&app, &token, &pool, "1000").await;

    let before = get_invoice(&app, &token, &invoice_id).await;
    let resp = credit(&app, &token, &invoice_id, "250").await;
    assert!(
        resp.status().is_success(),
        "raising a credit note should 2xx, got {}",
        resp.status()
    );
    let note: Value = resp.json().await.expect("credit note JSON");

    assert_eq!(note["credit_note_number"].as_str(), Some("CN-000001"));
    assert_eq!(note["status"].as_str(), Some("issued"));
    assert_eq!(dec(&note["total"]), Decimal::from(250));
    assert_eq!(
        note["invoice_number"].as_str(),
        before["invoice_number"].as_str(),
        "the credit note names the document it corrects"
    );

    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(dec(&after["amount_credited"]), Decimal::from(250));
    assert_eq!(dec(&after["balance_due"]), Decimal::from(750));
    assert_eq!(
        after["status"].as_str(),
        Some("sent"),
        "a partial credit leaves the invoice where it was"
    );

    // Untouched, which is the point.
    assert_eq!(dec(&after["total"]), dec(&before["total"]));
    assert_eq!(dec(&after["subtotal"]), dec(&before["subtotal"]));
    assert_eq!(
        after["invoice_number"].as_str(),
        before["invoice_number"].as_str()
    );
    assert_eq!(
        after["lines"].as_array().map(|l| l.len()),
        before["lines"].as_array().map(|l| l.len())
    );
}

/// PMS-1333: crediting an invoice for its whole total does NOT void it.
///
/// PMS-953 made crediting the writer of `void`, the status nothing could
/// reach. That read a credited invoice as a cancelled one, and it is not: the
/// document stood, the customer holds it, and the credit note is the
/// correction. The balance reaches zero, so the invoice lands on `paid`, which
/// is also Stripe's answer ("if a credit note reduces the balance of an open
/// invoice to 0, the invoice status changes to paid",
/// <https://docs.stripe.com/invoicing/dashboard/credit-notes>), and it carries
/// no payment date, because nobody paid.
#[mokosh_test]
async fn crediting_the_whole_balance_does_not_void_the_invoice(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let (_company_id, invoice_id) = sent_invoice(&app, &token, &pool, "1000").await;

    let resp = credit(&app, &token, &invoice_id, "1000").await;
    assert!(resp.status().is_success());

    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(
        after["status"].as_str(),
        Some("paid"),
        "a fully credited invoice is settled, not cancelled: {after}"
    );
    assert!(after["voided_at"].is_null(), "nothing voided it: {after}");
    assert_eq!(dec(&after["balance_due"]), Decimal::ZERO);
    assert_eq!(dec(&after["amount_credited"]), Decimal::from(1000));
    assert!(
        after["paid_at"].is_null(),
        "a credited invoice was not paid, so it carries no payment date"
    );
}

/// PMS-1333: a partial credit on a sent invoice leaves it sent, with the
/// balance reduced by exactly the credit. The case either side of the one
/// above, and the one an MSP hits most.
#[mokosh_test]
async fn a_partial_credit_leaves_a_sent_invoice_sent(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let (_company_id, invoice_id) = sent_invoice(&app, &token, &pool, "1000").await;

    let resp = credit(&app, &token, &invoice_id, "250").await;
    assert!(resp.status().is_success());

    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(after["status"].as_str(), Some("sent"), "{after}");
    assert!(after["voided_at"].is_null());
    assert_eq!(dec(&after["amount_credited"]), Decimal::from(250));
    assert_eq!(dec(&after["balance_due"]), Decimal::from(750));
}

/// PMS-1333: and a voided invoice cannot then be credited. Voiding says the
/// document never stood, so there is no charge for a credit note to correct.
#[mokosh_test]
async fn a_voided_invoice_refuses_a_credit_note(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let (_company_id, invoice_id) = sent_invoice(&app, &token, &pool, "400").await;

    // Back to draft, the only status a void is allowed from, then void it.
    sqlx::query("UPDATE invoices SET status = 'draft' WHERE id = $1")
        .bind(uuid::Uuid::from_str(&invoice_id).expect("invoice id"))
        .execute(&pool)
        .await
        .expect("return the invoice to draft");
    let voided = app
        .client
        .post(app.url(&format!("/api/v1/invoices/{invoice_id}/void")))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "reason": "Raised against the wrong company" }))
        .send()
        .await
        .expect("send void");
    assert!(voided.status().is_success(), "{}", voided.status());

    let resp = credit(&app, &token, &invoice_id, "100").await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.expect("refusal JSON");
    assert!(
        body.to_string().contains("voided"),
        "the refusal should say why: {body}"
    );
}

/// PMS-1226: the void threshold is the invoice's full total, not the already-
/// paid remainder. `INV-000042`, total 100.00, fully paid: a 5.00 goodwill
/// credit note (a post-payment adjustment `create_credit_note` documents as
/// intended) must not void it, because `i.total - p.paid` is already zero and
/// any credit at all used to satisfy `p.credited >= i.total - p.paid`.
#[mokosh_test]
async fn a_partial_credit_on_a_fully_paid_invoice_leaves_it_paid(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let (company_id, invoice_id) = sent_invoice(&app, &token, &pool, "100").await;

    sqlx::query("UPDATE invoices SET invoice_number = 'INV-000042' WHERE id = $1")
        .bind(uuid::Uuid::from_str(&invoice_id).expect("invoice id"))
        .execute(&pool)
        .await
        .expect("stamp invoice number");

    let payment = app
        .client
        .post(app.url("/api/v1/payments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "company_id": company_id,
            "payment_date": "2026-08-15",
            "amount": "100",
            "payment_method": "check",
        }))
        .send()
        .await
        .expect("send record-payment request");
    assert!(
        payment.status().is_success(),
        "recording the full payment should 2xx, got {}",
        payment.status()
    );

    let paid = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(paid["invoice_number"].as_str(), Some("INV-000042"));
    assert_eq!(paid["status"].as_str(), Some("paid"));

    let resp = credit(&app, &token, &invoice_id, "5").await;
    assert!(
        resp.status().is_success(),
        "raising the goodwill credit note should 2xx, got {}",
        resp.status()
    );

    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(
        after["status"].as_str(),
        Some("paid"),
        "a partial credit on a fully-paid invoice must not void it"
    );
    assert_eq!(dec(&after["amount_credited"]), Decimal::from(5));
    assert_eq!(dec(&after["balance_due"]), Decimal::from(-5));
    assert!(
        !after["paid_at"].is_null(),
        "the invoice is still paid, so its payment date stands"
    );
}

/// A credit note is never edited, for the reason its invoice is not. Voiding
/// changes no amount and no line; the credit simply stops counting, and the
/// invoice walks back to the status it would have had.
#[mokosh_test]
async fn voiding_a_credit_note_restores_the_balance(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let (_company_id, invoice_id) = sent_invoice(&app, &token, &pool, "1000").await;

    let note: Value = credit(&app, &token, &invoice_id, "1000")
        .await
        .json()
        .await
        .expect("credit note JSON");
    let note_id = note["id"].as_str().expect("credit note id").to_string();
    // PMS-1333: settled by the credit, not cancelled by it.
    assert_eq!(
        get_invoice(&app, &token, &invoice_id).await["status"].as_str(),
        Some("paid")
    );

    let resp = app
        .client
        .post(app.url(&format!("/api/v1/credit-notes/{note_id}/void")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send void");
    assert!(
        resp.status().is_success(),
        "voiding should 2xx, got {}",
        resp.status()
    );
    let voided: Value = resp.json().await.expect("voided JSON");
    assert_eq!(voided["status"].as_str(), Some("void"));
    assert!(!voided["voided_at"].is_null());
    assert_eq!(
        dec(&voided["total"]),
        Decimal::from(1000),
        "voiding is not an edit: the amounts stay as issued"
    );

    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(dec(&after["amount_credited"]), Decimal::ZERO);
    assert_eq!(dec(&after["balance_due"]), Decimal::from(1000));
    assert_eq!(
        after["status"].as_str(),
        Some("sent"),
        "the invoice returns to where it was before the credit"
    );

    // Voiding twice is a conflict, not a silent second no-op.
    let again = app
        .client
        .post(app.url(&format!("/api/v1/credit-notes/{note_id}/void")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send second void");
    assert_eq!(again.status(), reqwest::StatusCode::CONFLICT);
}

/// The cap is the total less what is already credited, and is checked across
/// several notes rather than per note.
#[mokosh_test]
async fn a_credit_cannot_exceed_what_is_left_to_credit(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let (_company_id, invoice_id) = sent_invoice(&app, &token, &pool, "1000").await;

    let over = credit(&app, &token, &invoice_id, "1001").await;
    assert_eq!(over.status(), reqwest::StatusCode::BAD_REQUEST);

    assert!(credit(&app, &token, &invoice_id, "600")
        .await
        .status()
        .is_success());
    let second = credit(&app, &token, &invoice_id, "500").await;
    assert_eq!(
        second.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "600 is already credited, so only 400 is left"
    );
    assert!(credit(&app, &token, &invoice_id, "400")
        .await
        .status()
        .is_success());

    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(dec(&after["amount_credited"]), Decimal::from(1000));
    // PMS-1333: credited to zero across two notes is still settled, not void.
    assert_eq!(after["status"].as_str(), Some("paid"));
}

/// An invoice the customer has already paid can still be credited in full.
/// That is exactly the case where they are owed money back, so the cap is
/// deliberately NOT reduced by what has been paid.
#[mokosh_test]
async fn a_paid_invoice_can_still_be_credited_in_full(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let (company_id, invoice_id) = sent_invoice(&app, &token, &pool, "1000").await;

    let paid = app
        .client
        .post(app.url("/api/v1/payments"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "company_id": company_id,
            "amount": "1000",
            "payment_date": "2026-08-15",
            "payment_method": "check",
        }))
        .send()
        .await
        .expect("send payment");
    assert!(
        paid.status().is_success(),
        "payment should 2xx, got {}",
        paid.status()
    );
    assert_eq!(
        get_invoice(&app, &token, &invoice_id).await["status"].as_str(),
        Some("paid")
    );

    assert!(credit(&app, &token, &invoice_id, "1000")
        .await
        .status()
        .is_success());
    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(dec(&after["amount_credited"]), Decimal::from(1000));
    assert_eq!(
        dec(&after["balance_due"]),
        Decimal::from(-1000),
        "the negative balance is the money owed back, and it is visible rather than clamped"
    );
}

/// A draft invoice can still be edited, so a credit note against it would
/// correct a document nobody was sent.
#[mokosh_test]
async fn a_draft_invoice_is_refused_because_it_can_still_be_edited(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let company_id = common::seed_company(&pool).await;
    // PMS-993: an invoice cannot be sent without a billing contact.
    common::seed_billing_contact(&pool, company_id).await;
    let invoice_id = draft_invoice(&app, &token, company_id, "1000").await;

    let resp = credit(&app, &token, &invoice_id, "100").await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("edited"),
        "the refusal says what to do instead, got {body}"
    );
}

/// The document as a whole is the credit, so a negative line inside it is a
/// charge in disguise. Checking only the total would miss one that a larger
/// positive line offsets, which is why the check is per line.
#[mokosh_test]
async fn a_charge_cannot_hide_inside_a_credit(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let (_company_id, invoice_id) = sent_invoice(&app, &token, &pool, "1000").await;

    let resp = app
        .client
        .post(app.url("/api/v1/credit-notes"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "invoice_id": invoice_id,
            "reason": "Adjustment",
            "lines": [
                { "line_type": "adjustment", "description": "Credit", "quantity": "1", "unit_price": "500" },
                { "line_type": "service", "description": "Rebilled", "quantity": "1", "unit_price": "-100" },
            ],
        }))
        .send()
        .await
        .expect("send mixed-sign credit note");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "the total would have been a positive 400 and passed a total-only check"
    );

    let after = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(dec(&after["amount_credited"]), Decimal::ZERO);
}

/// The regression pin. Credits were folded into the recompute that already
/// owned `amount_paid`, and the status ladder gained an arm; an invoice with no
/// credits must behave exactly as it did before, payment transitions included.
#[mokosh_test]
async fn an_invoice_with_no_credits_behaves_exactly_as_before(pool: PgPool) {
    let (_admin_id, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let (company_id, invoice_id) = sent_invoice(&app, &token, &pool, "1000").await;

    let sent = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(sent["status"].as_str(), Some("sent"));
    assert_eq!(dec(&sent["amount_credited"]), Decimal::ZERO);
    assert_eq!(dec(&sent["balance_due"]), Decimal::from(1000));

    for (amount, expected) in [("400", "partially_paid"), ("600", "paid")] {
        let resp = app
            .client
            .post(app.url("/api/v1/payments"))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "invoice_id": invoice_id,
                "company_id": company_id,
                "amount": amount,
                "payment_date": "2026-08-15",
                "payment_method": "check",
            }))
            .send()
            .await
            .expect("send payment");
        assert!(resp.status().is_success());
        let after = get_invoice(&app, &token, &invoice_id).await;
        assert_eq!(after["status"].as_str(), Some(expected));
        assert_eq!(dec(&after["amount_credited"]), Decimal::ZERO);
    }

    let paid = get_invoice(&app, &token, &invoice_id).await;
    assert_eq!(dec(&paid["balance_due"]), Decimal::ZERO);
    assert!(
        !paid["paid_at"].is_null(),
        "a genuinely paid invoice still gets its payment date"
    );
}

/// The QA dataset now carries a corrected invoice, not only invoices that went
/// out right the first time. A `void` status and a non-zero `amount_credited`
/// are states no other seeded row reaches, so without this the seed exercises
/// every billing path except the one PMS-953 added.
///
/// It also runs the seed, which nothing else in the suite does: the credited
/// invoice has to be created, sent and credited in sequence through three
/// services, and a compile is not evidence that sequence works.
#[mokosh_test]
async fn the_qa_seed_carries_a_credited_invoice(pool: PgPool) {
    // The seed attributes every record to a user, and fails closed when the
    // tenant has none.
    let (_admin_id, _email, _password) = common::seed_admin(&pool).await;
    // It also fails closed on any tenant not explicitly marked QA, so mark it.
    sqlx::query(
        "UPDATE tenants SET settings = COALESCE(settings, '{}'::jsonb) || '{\"is_qa\": true}'::jsonb \
         WHERE id = $1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .execute(&pool)
    .await
    .expect("mark the tenant as QA");

    let db = mokosh_server::db::Database::from_pool(pool.clone());
    let report = mokosh_server::modules::seed::qa_seed(&db, common::DEFAULT_TENANT_ID)
        .await
        .expect("qa seed");
    assert_eq!(report.credit_notes, 1, "one credited invoice, {report}");
    // PMS-955: the catalog is seeded before the invoices, and the credited
    // invoice's line sells the first product in it.
    assert_eq!(report.products, 3, "{report}");

    let row: (String, Decimal, Decimal) = sqlx::query_as(
        r#"
        SELECT i.status, i.amount_credited, i.balance_due
        FROM credit_notes cn
        JOIN invoices i ON i.id = cn.invoice_id
        WHERE cn.tenant_id = $1
        "#,
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("the seeded credit note's invoice");

    let (status, credited, balance) = row;
    assert_eq!(status, "sent", "a partial credit leaves the invoice sent");
    assert_eq!(credited, Decimal::from(500));
    assert_eq!(
        balance,
        Decimal::from(1500),
        "2000 invoiced less 500 credited"
    );

    // Teardown removes the note as well as the invoice; a credit note holds a
    // plain reference to its invoice, so leaving one behind would make the
    // invoice undeletable and the teardown non-idempotent.
    let torn = mokosh_server::modules::seed::qa_teardown(&db, common::DEFAULT_TENANT_ID)
        .await
        .expect("qa teardown");
    assert_eq!(torn.credit_notes, 1, "{torn}");
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credit_notes WHERE tenant_id = $1")
        .bind(common::DEFAULT_TENANT_ID)
        .fetch_one(&pool)
        .await
        .expect("count credit notes");
    assert_eq!(left, 0);
}
