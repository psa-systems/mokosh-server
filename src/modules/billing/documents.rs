//! PMS-911: an invoice and a statement as documents a client receives.
//!
//! Everything here turns billing data plus an [`Issuer`] into a
//! [`crate::pdf::Document`]. No layout: the generator owns that, and these
//! functions own what a commercial document has to say.
//!
//! ## Why an invoice and a statement are built differently
//!
//! An invoice renders from its FROZEN issuer (PMS-911) because a client holds a
//! copy of the one they were sent, and PMS-953 already says an issued invoice
//! cannot change. A statement renders from the CURRENT issuer, because PMS-954
//! deliberately made it a read model that writes and stores nothing: there is no
//! statement row for a snapshot to hang off, and adding one would be inventing
//! an entity to hold a copy of something reproducible. The artefact that was
//! actually SENT to a client becomes a stored PDF under PMS-959; until then a
//! statement is a report, and reports render from today.

use rust_decimal::Decimal;
use uuid::Uuid;

use crate::pdf::{Document, Logo};
use crate::storage::{FileLedger, FileRecord, LocalStore, ObjectKey, ObjectStore};
use crate::utils::error::AppResult;

use super::issuer::Issuer;
use super::models::{CreditNoteResponse, InvoiceResponse, StatementResponse};

/// The box a logo is fitted into, top right of the first page. Generous enough
/// for a wordmark, small enough that a square logo cannot push the body down
/// the page.
const LOGO_WIDTH_MM: f32 = 45.0;
const LOGO_HEIGHT_MM: f32 = 20.0;

/// Money, as a document shows it.
///
/// Two decimals always, because an invoice that reads `1200` where it means
/// `1200.00` looks like a rounding, and the currency beside it because a
/// document leaving the building has to say which dollars it means.
fn money(amount: Decimal, currency: Option<&str>) -> String {
    let code = currency.unwrap_or("USD");
    format!("{amount:.2} {code}")
}

fn logo(bytes: Option<Vec<u8>>) -> Option<Logo> {
    bytes.map(|bytes| Logo {
        bytes,
        max_width_mm: LOGO_WIDTH_MM,
        max_height_mm: LOGO_HEIGHT_MM,
    })
}

/// The issuer's block: who is billing, and everything a client needs to
/// identify them.
///
/// Only the lines that have a value. An MSP that has filled nothing in gets its
/// name alone, which is the whole of the no-branding acceptance criterion: a
/// valid invoice, not a page of empty labels.
fn issuer_lines(issuer: &Issuer) -> Vec<String> {
    let mut lines = vec![issuer.name.clone()];
    if let Some(trading) = &issuer.trading_name {
        lines.push(format!("trading as {trading}"));
    }
    if let Some(address) = &issuer.postal_address {
        // The one multi-line branding value, so it arrives as several lines
        // rather than as one with newlines in it.
        lines.extend(address.replace('\r', "").lines().map(str::to_string));
    }
    if let Some(tax_id) = &issuer.tax_id {
        lines.push(tax_id.clone());
    }
    lines.extend(
        [&issuer.email, &issuer.phone, &issuer.website]
            .into_iter()
            .flatten()
            .cloned(),
    );
    lines
}

/// Build the invoice document.
pub fn invoice(
    invoice: &InvoiceResponse,
    issuer: &Issuer,
    logo_bytes: Option<Vec<u8>>,
) -> Document {
    let currency = invoice.currency.as_deref();
    let mut document = Document::new("Invoice")
        .subtitle(invoice.invoice_number.clone())
        .logo(logo(logo_bytes))
        .lines("From", issuer_lines(issuer))
        .lines(
            "Bill to",
            vec![invoice
                .company_name
                .clone()
                .unwrap_or_else(|| "Customer".to_string())],
        );

    let mut details = vec![
        ("Invoice number".to_string(), invoice.invoice_number.clone()),
        ("Invoice date".to_string(), invoice.invoice_date.to_string()),
        ("Due date".to_string(), invoice.due_date.to_string()),
        ("Status".to_string(), invoice.status.as_str().to_string()),
    ];
    // The lookup name if there is one, the legacy free-text terms otherwise
    // (PMS-333), and no line at all when there is neither.
    if let Some(terms) = invoice
        .payment_term_name
        .clone()
        .or_else(|| invoice.payment_terms.clone())
    {
        details.push(("Payment terms".to_string(), terms));
    }
    if let Some(po) = &invoice.po_number {
        details.push(("PO number".to_string(), po.clone()));
    }
    document = document.fields("Details", details);

    if let Some(lines) = &invoice.lines {
        document = document.table(
            "Items",
            vec![
                "Description".into(),
                "Qty".into(),
                "Unit price".into(),
                "Amount".into(),
            ],
            lines
                .iter()
                .map(|line| {
                    vec![
                        line.description.clone(),
                        format!("{}", line.quantity.normalize()),
                        money(line.unit_price, currency),
                        money(line.total, currency),
                    ]
                })
                .collect(),
        );
    }

    let mut totals = vec![
        ("Subtotal".to_string(), money(invoice.subtotal, currency)),
        ("Tax".to_string(), money(invoice.tax_amount, currency)),
    ];
    if !invoice.discount_amount.is_zero() {
        totals.push((
            "Discount".to_string(),
            money(invoice.discount_amount, currency),
        ));
    }
    totals.push(("Total".to_string(), money(invoice.total, currency)));
    totals.push(("Paid".to_string(), money(invoice.amount_paid, currency)));
    // Only when there is one: a credit note is an exceptional event and a
    // permanent `0.00 USD` line invites the question of what it means.
    if !invoice.amount_credited.is_zero() {
        totals.push((
            "Credited".to_string(),
            money(invoice.amount_credited, currency),
        ));
    }
    totals.push((
        "Balance due".to_string(),
        money(invoice.balance_due, currency),
    ));
    document = document.fields("Totals", totals);

    if let Some(notes) = &invoice.notes {
        document = document.lines("Notes", vec![notes.clone()]);
    }
    document
}

/// Build the credit-note document.
///
/// A credit note is a document about a document, so it names the invoice it
/// corrects on its face: a client filing it away has to be able to see what it
/// cancels without opening anything else.
pub fn credit_note(
    note: &CreditNoteResponse,
    issuer: &Issuer,
    logo_bytes: Option<Vec<u8>>,
) -> Document {
    let currency = note.currency.as_deref();
    let mut details = vec![
        (
            "Credit note number".to_string(),
            note.credit_note_number.clone(),
        ),
        ("Issue date".to_string(), note.issue_date.to_string()),
        ("Status".to_string(), note.status.as_str().to_string()),
        ("Reason".to_string(), note.reason.clone()),
    ];
    if let Some(number) = &note.invoice_number {
        details.push(("Against invoice".to_string(), number.clone()));
    }

    let mut document = Document::new("Credit Note")
        .subtitle(note.credit_note_number.clone())
        .logo(logo(logo_bytes))
        .lines("From", issuer_lines(issuer))
        .lines(
            "Credit to",
            vec![note
                .company_name
                .clone()
                .unwrap_or_else(|| "Customer".to_string())],
        )
        .fields("Details", details);

    if let Some(lines) = &note.lines {
        document = document.table(
            "Items",
            vec![
                "Description".into(),
                "Qty".into(),
                "Unit price".into(),
                "Amount".into(),
            ],
            lines
                .iter()
                .map(|line| {
                    vec![
                        line.description.clone(),
                        format!("{}", line.quantity.normalize()),
                        money(line.unit_price, currency),
                        money(line.total, currency),
                    ]
                })
                .collect(),
        );
    }

    document = document.fields(
        "Totals",
        vec![
            ("Subtotal".to_string(), money(note.subtotal, currency)),
            ("Tax".to_string(), money(note.tax_amount, currency)),
            ("Total credited".to_string(), money(note.total, currency)),
        ],
    );
    if let Some(notes) = &note.notes {
        document = document.lines("Notes", vec![notes.clone()]);
    }
    document
}

/// PMS-959: keep the document that was issued.
///
/// Written inside the transaction that freezes the invoice or creates the
/// credit note, so a document cannot be issued without one, and the ledger row
/// goes through the same transaction so a rollback takes both.
///
/// The object write itself is not transactional: a rollback after it leaves the
/// bytes behind. That is litter rather than a problem, because the key is the
/// document's own id, so the next successful attempt overwrites it and nothing
/// can reach an object whose row never committed.
pub async fn store_issued(
    tx: &mut crate::db::TenantTransaction<'_>,
    tenant_id: Uuid,
    document_id: Uuid,
    number: &str,
    entity_type: &str,
    bytes: &[u8],
) -> AppResult<()> {
    let key = ObjectKey::financial_document(tenant_id, document_id);
    LocalStore::from_env().put(&key, bytes).await?;
    FileLedger::record_in_tx(
        tx,
        tenant_id,
        &key,
        // A fresh id, NOT the document's: the ledger is keyed on the object and
        // a `files` row already exists for other objects under a feature's own
        // id. Deriving it from the document id keeps one row per document
        // without colliding with anything a feature stored under that id.
        document_file_id(document_id),
        FileRecord {
            original_name: &format!("{number}.pdf"),
            mime_type: "application/pdf",
            file_size: bytes.len() as i64,
            uploaded_by_id: None,
            entity_type,
            entity_id: Some(document_id),
        },
    )
    .await
}

/// The `files` row id for a document's stored PDF.
///
/// Version 5-shaped: derived from the document id so it is stable across
/// re-issues of the same document and cannot collide with a feature row keyed
/// on the document id itself. Deterministic, so a second store of the same
/// document upserts one row rather than adding a second.
fn document_file_id(document_id: Uuid) -> Uuid {
    let mut bytes = *document_id.as_bytes();
    // Flip the two bits that make it a distinct value while keeping it a valid
    // v4-shaped UUID; nothing parses meaning out of this id, it only has to be
    // stable and distinct.
    bytes[6] ^= 0x10;
    bytes[8] ^= 0x20;
    Uuid::from_bytes(bytes)
}

/// The stored document, if one was kept.
///
/// `None` for a draft, and for anything issued before PMS-959; the caller
/// renders live in that case, which is what those documents always did.
pub async fn read_issued(tenant_id: Uuid, document_id: Uuid) -> Option<Vec<u8>> {
    LocalStore::from_env()
        .read(&ObjectKey::financial_document(tenant_id, document_id))
        .await
        .ok()
}

/// Build the statement document.
pub fn statement(
    statement: &StatementResponse,
    issuer: &Issuer,
    logo_bytes: Option<Vec<u8>>,
) -> Document {
    // A statement carries no currency of its own: it spans documents that each
    // carry one, so the code is left off rather than guessed at.
    let amount = |value: Decimal| format!("{value:.2}");
    let mut document = Document::new("Statement of Account")
        .subtitle(format!(
            "{} to {}",
            statement.period_start, statement.period_end
        ))
        .logo(logo(logo_bytes))
        .lines("From", issuer_lines(issuer))
        .lines(
            "Account",
            vec![statement
                .company_name
                .clone()
                .unwrap_or_else(|| "Customer".to_string())],
        )
        .fields(
            "Opening",
            vec![(
                "Balance brought forward".to_string(),
                amount(statement.opening_balance),
            )],
        );

    if !statement.invoices.is_empty() {
        document = document.table(
            "Invoices",
            vec![
                "Number".into(),
                "Date".into(),
                "Due".into(),
                "Status".into(),
                "Total".into(),
            ],
            statement
                .invoices
                .iter()
                .map(|i| {
                    vec![
                        i.invoice_number.clone(),
                        i.invoice_date.to_string(),
                        i.due_date.to_string(),
                        i.status.as_str().to_string(),
                        amount(i.total),
                    ]
                })
                .collect(),
        );
    }
    if !statement.payments.is_empty() {
        document = document.table(
            "Payments",
            vec![
                "Date".into(),
                "Invoice".into(),
                "Method".into(),
                "Reference".into(),
                "Amount".into(),
            ],
            statement
                .payments
                .iter()
                .map(|p| {
                    vec![
                        p.payment_date.to_string(),
                        p.invoice_number.clone().unwrap_or_default(),
                        p.payment_method.as_str().to_string(),
                        p.reference_number.clone().unwrap_or_default(),
                        amount(p.amount),
                    ]
                })
                .collect(),
        );
    }
    if !statement.refunds.is_empty() {
        document = document.table(
            "Refunds",
            vec!["Date".into(), "Invoice".into(), "Amount".into()],
            statement
                .refunds
                .iter()
                .map(|r| {
                    vec![
                        r.refund_date.to_string(),
                        r.invoice_number.clone().unwrap_or_default(),
                        amount(r.amount),
                    ]
                })
                .collect(),
        );
    }
    if !statement.credit_notes.is_empty() {
        document = document.table(
            "Credit notes",
            vec![
                "Number".into(),
                "Date".into(),
                "Invoice".into(),
                "Reason".into(),
                "Total".into(),
            ],
            statement
                .credit_notes
                .iter()
                .map(|c| {
                    vec![
                        c.credit_note_number.clone(),
                        c.issue_date.to_string(),
                        c.invoice_number.clone().unwrap_or_default(),
                        c.reason.clone(),
                        amount(c.total),
                    ]
                })
                .collect(),
        );
    }

    document.fields(
        "Closing",
        vec![
            ("Invoiced".to_string(), amount(statement.total_invoiced)),
            ("Paid".to_string(), amount(statement.total_paid)),
            ("Refunded".to_string(), amount(statement.total_refunded)),
            ("Credited".to_string(), amount(statement.total_credited)),
            ("Balance due".to_string(), amount(statement.closing_balance)),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An MSP that filled nothing in still gets a named issuer block, which is
    /// the whole of the no-branding acceptance criterion: a valid document, not
    /// a page of empty labels.
    #[test]
    fn an_issuer_with_nothing_filled_in_is_one_line() {
        let issuer = Issuer {
            name: "Acme IT".to_string(),
            ..Default::default()
        };
        assert_eq!(issuer_lines(&issuer), vec!["Acme IT".to_string()]);
    }

    /// And a full one puts the address on its own lines rather than printing
    /// newlines inside one.
    #[test]
    fn an_address_arrives_as_separate_lines() {
        let issuer = Issuer {
            name: "Acme IT Services Pty Ltd".to_string(),
            trading_name: Some("Acme IT".to_string()),
            postal_address: Some("12 Example St\r\nSydney NSW 2000".to_string()),
            tax_id: Some("ABN 12 345 678 901".to_string()),
            email: Some("billing@acme.example".to_string()),
            ..Default::default()
        };
        let lines = issuer_lines(&issuer);
        assert_eq!(
            lines,
            vec![
                "Acme IT Services Pty Ltd",
                "trading as Acme IT",
                "12 Example St",
                "Sydney NSW 2000",
                "ABN 12 345 678 901",
                "billing@acme.example",
            ]
        );
        assert!(
            lines.iter().all(|l| !l.contains('\n')),
            "no line may carry its own newline: {lines:?}"
        );
    }

    /// Two decimals and a currency, because `1200` where `1200.00` is meant
    /// reads as a rounding.
    #[test]
    fn money_says_what_it_means() {
        assert_eq!(money(Decimal::new(120000, 2), Some("AUD")), "1200.00 AUD");
        assert_eq!(money(Decimal::new(1200, 0), None), "1200.00 USD");
    }
}
