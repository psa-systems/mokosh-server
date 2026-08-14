//! Server-side invoice PDF renderer.
//!
//! Reads a fully-joined [`InvoiceResponse`] (the same DTO the portal
//! + agent invoice-detail endpoints already return) and produces a
//! single-page PDF using [`printpdf`]. Pure Rust, no C deps -
//! matches the musl / Alpine deployment target the OCI image
//! already builds against.
//!
//! Layout is intentionally minimal (the customer's Save-as-PDF from
//! the SPA's Print button is a close alternative; the server-side
//! render exists so a workflow / email-attach path can produce the
//! same document without a browser session):
//!
//! - Header row: "INVOICE" + invoice number, right-aligned
//! - Meta grid: issued / due / status
//! - Bill To block + PO / terms (when present)
//! - Line-item table with description / qty / unit-price / total
//! - Totals stack: subtotal / discount / tax / total / balance due
//! - Optional notes block
//!
//! Uses Helvetica (built into printpdf, no external font file
//! needed) throughout so a deploy without asset provisioning still
//! renders a legible invoice.

use super::models::{InvoiceLineType, InvoiceResponse};
use crate::utils::error::{AppError, AppResult};
use printpdf::{BuiltinFont, Mm, PdfDocument};
use rust_decimal::Decimal;

/// Points-per-mm at 72 DPI; used to convert a raw font size in points
/// to a mm rise for line spacing. Kept as a `f32` to match printpdf's
/// `Mm(f32)` API.
const MM_PER_POINT: f32 = 25.4 / 72.0;

/// A4 page dimensions, in millimetres. Matches every western portal
/// invoice we ship today. Letter is a follow-up when a US tenant
/// asks for it.
const PAGE_WIDTH_MM: f32 = 210.0;
const PAGE_HEIGHT_MM: f32 = 297.0;
const MARGIN_MM: f32 = 15.0;

/// Column X offsets for the line-item table (mm from left edge).
const COL_DESC_X: f32 = MARGIN_MM;
const COL_QTY_X: f32 = 115.0;
const COL_UNIT_X: f32 = 140.0;
const COL_TOTAL_X: f32 = 175.0;

/// Convert a font point size to a mm rise (rough baseline-to-baseline
/// advance for the printpdf built-in fonts). One point == 1/72 inch.
fn line_height_mm(font_pt: f32) -> f32 {
    font_pt * MM_PER_POINT * 1.25
}

/// Render `invoice` as a single-page A4 PDF and return the bytes.
///
/// `msp_name` is the MSP the invoice belongs to (rendered at the top
/// as the "from" line so the recipient sees who the invoice came
/// from). Kept as a distinct arg rather than embedded in the
/// `InvoiceResponse` DTO because the invoice row itself has no
/// concept of the MSP identity.
pub fn render_invoice_pdf(msp_name: &str, invoice: &InvoiceResponse) -> AppResult<Vec<u8>> {
    let (doc, page1, layer1) = PdfDocument::new(
        format!("Invoice {}", invoice.invoice_number),
        Mm(PAGE_WIDTH_MM),
        Mm(PAGE_HEIGHT_MM),
        "layer1",
    );
    let layer = doc.get_page(page1).get_layer(layer1);

    // Built-in Helvetica so we do not need to ship a font file with
    // the container image. printpdf loads these variants directly
    // without a file read.
    let font_regular = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| AppError::Internal(format!("pdf font load failed: {e}")))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| AppError::Internal(format!("pdf bold font load failed: {e}")))?;

    let base_x = MARGIN_MM;
    let mut y = PAGE_HEIGHT_MM - MARGIN_MM;

    // Header: MSP name (bold) + right-aligned "INVOICE" + number.
    let hdr_pt = 20.0_f32;
    layer.use_text(msp_name, hdr_pt, Mm(base_x), Mm(y), &font_bold);
    let title = format!("INVOICE #{}", invoice.invoice_number);
    let title_width_estimate_mm = (title.chars().count() as f32) * hdr_pt * MM_PER_POINT * 0.55;
    layer.use_text(
        &title,
        hdr_pt,
        Mm(PAGE_WIDTH_MM - MARGIN_MM - title_width_estimate_mm),
        Mm(y),
        &font_bold,
    );
    y -= line_height_mm(hdr_pt) * 1.6;

    // Meta grid: issued / due / status. One row, three columns.
    let meta_pt = 10.0_f32;
    let issued = invoice.invoice_date.format("%b %-d, %Y").to_string();
    let due = invoice.due_date.format("%b %-d, %Y").to_string();
    let status = format!("{:?}", invoice.status);
    layer.use_text("Issued", meta_pt, Mm(base_x), Mm(y), &font_bold);
    layer.use_text("Due", meta_pt, Mm(base_x + 50.0), Mm(y), &font_bold);
    layer.use_text("Status", meta_pt, Mm(base_x + 100.0), Mm(y), &font_bold);
    y -= line_height_mm(meta_pt);
    layer.use_text(&issued, meta_pt, Mm(base_x), Mm(y), &font_regular);
    layer.use_text(&due, meta_pt, Mm(base_x + 50.0), Mm(y), &font_regular);
    layer.use_text(&status, meta_pt, Mm(base_x + 100.0), Mm(y), &font_regular);
    y -= line_height_mm(meta_pt) * 2.0;

    // Bill To block. Company name headline + optional PO / terms.
    layer.use_text("Bill To", meta_pt, Mm(base_x), Mm(y), &font_bold);
    y -= line_height_mm(meta_pt);
    layer.use_text(
        invoice.company_name.as_deref().unwrap_or("-"),
        12.0,
        Mm(base_x),
        Mm(y),
        &font_regular,
    );
    y -= line_height_mm(12.0);
    if let Some(po) = invoice.po_number.as_deref().filter(|s| !s.is_empty()) {
        layer.use_text(
            format!("PO: {po}"),
            meta_pt,
            Mm(base_x),
            Mm(y),
            &font_regular,
        );
        y -= line_height_mm(meta_pt);
    }
    let terms = invoice
        .payment_term_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(invoice.payment_terms.as_deref().filter(|s| !s.is_empty()));
    if let Some(t) = terms {
        layer.use_text(
            format!("Terms: {t}"),
            meta_pt,
            Mm(base_x),
            Mm(y),
            &font_regular,
        );
        y -= line_height_mm(meta_pt);
    }
    y -= line_height_mm(meta_pt);

    // Line items table.
    let table_pt = 10.0_f32;
    layer.use_text("Description", table_pt, Mm(COL_DESC_X), Mm(y), &font_bold);
    layer.use_text("Qty", table_pt, Mm(COL_QTY_X), Mm(y), &font_bold);
    layer.use_text("Unit price", table_pt, Mm(COL_UNIT_X), Mm(y), &font_bold);
    layer.use_text("Total", table_pt, Mm(COL_TOTAL_X), Mm(y), &font_bold);
    y -= line_height_mm(table_pt);

    let lines = invoice.lines.as_deref().unwrap_or(&[]);
    if lines.is_empty() {
        layer.use_text(
            "No line items.",
            table_pt,
            Mm(COL_DESC_X),
            Mm(y),
            &font_regular,
        );
        y -= line_height_mm(table_pt);
    } else {
        for line in lines {
            // Truncate long descriptions rather than wrap: single-
            // page layout would otherwise overflow. Follow-up would
            // paginate; the print-from-browser path handles long
            // invoices in the meantime.
            let mut desc = line.description.clone();
            if desc.chars().count() > 60 {
                desc = desc.chars().take(57).collect::<String>() + "...";
            }
            if !matches!(line.line_type, InvoiceLineType::Service) {
                let type_label = line.line_type.as_str();
                desc.push_str(&format!(" [{type_label}]"));
            }
            layer.use_text(&desc, table_pt, Mm(COL_DESC_X), Mm(y), &font_regular);
            layer.use_text(
                format_decimal(&line.quantity),
                table_pt,
                Mm(COL_QTY_X),
                Mm(y),
                &font_regular,
            );
            layer.use_text(
                format_money(&line.unit_price),
                table_pt,
                Mm(COL_UNIT_X),
                Mm(y),
                &font_regular,
            );
            layer.use_text(
                format_money(&line.total),
                table_pt,
                Mm(COL_TOTAL_X),
                Mm(y),
                &font_regular,
            );
            y -= line_height_mm(table_pt);
            if y < MARGIN_MM + 60.0 {
                // Reserve enough vertical room for the totals stack
                // + notes below. Truncate the line list rather than
                // spill onto page 2 for this MVP.
                layer.use_text(
                    "(more items not shown)",
                    table_pt,
                    Mm(COL_DESC_X),
                    Mm(y),
                    &font_regular,
                );
                y -= line_height_mm(table_pt);
                break;
            }
        }
    }
    y -= line_height_mm(table_pt);

    // Totals stack, right-aligned. printpdf has no built-in text
    // measurement so we approximate right alignment by rendering
    // each line starting at COL_UNIT_X (labels) and COL_TOTAL_X
    // (values).
    let total_pt = 11.0_f32;
    layer.use_text("Subtotal", total_pt, Mm(COL_UNIT_X), Mm(y), &font_regular);
    layer.use_text(
        format_money(&invoice.subtotal),
        total_pt,
        Mm(COL_TOTAL_X),
        Mm(y),
        &font_regular,
    );
    y -= line_height_mm(total_pt);
    if !invoice.discount_amount.is_zero() {
        layer.use_text("Discount", total_pt, Mm(COL_UNIT_X), Mm(y), &font_regular);
        layer.use_text(
            format!("-{}", format_money(&invoice.discount_amount)),
            total_pt,
            Mm(COL_TOTAL_X),
            Mm(y),
            &font_regular,
        );
        y -= line_height_mm(total_pt);
    }
    if !invoice.tax_amount.is_zero() {
        layer.use_text("Tax", total_pt, Mm(COL_UNIT_X), Mm(y), &font_regular);
        layer.use_text(
            format_money(&invoice.tax_amount),
            total_pt,
            Mm(COL_TOTAL_X),
            Mm(y),
            &font_regular,
        );
        y -= line_height_mm(total_pt);
    }
    layer.use_text("Total", 13.0, Mm(COL_UNIT_X), Mm(y), &font_bold);
    layer.use_text(
        format_money(&invoice.total),
        13.0,
        Mm(COL_TOTAL_X),
        Mm(y),
        &font_bold,
    );
    y -= line_height_mm(13.0);
    if invoice.balance_due != invoice.total {
        layer.use_text(
            "Balance due",
            total_pt,
            Mm(COL_UNIT_X),
            Mm(y),
            &font_regular,
        );
        layer.use_text(
            format_money(&invoice.balance_due),
            total_pt,
            Mm(COL_TOTAL_X),
            Mm(y),
            &font_regular,
        );
        y -= line_height_mm(total_pt);
    }

    // Notes block at the bottom, when present.
    if let Some(notes) = invoice.notes.as_deref().filter(|s| !s.is_empty()) {
        y -= line_height_mm(total_pt);
        layer.use_text("Notes", total_pt, Mm(base_x), Mm(y), &font_bold);
        y -= line_height_mm(total_pt);
        for chunk in wrap_text(notes, 90) {
            layer.use_text(&chunk, meta_pt, Mm(base_x), Mm(y), &font_regular);
            y -= line_height_mm(meta_pt);
            if y < MARGIN_MM {
                break;
            }
        }
    }

    doc.save_to_bytes()
        .map_err(|e| AppError::Internal(format!("pdf save failed: {e}")))
}

/// Format a decimal with two fixed decimal places. Approximates the
/// SPA's `format_money_str` output; a full-fidelity match (grouped
/// thousands, currency symbol) is a follow-up when the layout gets a
/// real currency indicator.
fn format_money(v: &Decimal) -> String {
    // Fixed 2 decimal places matches the invoice DTO's own
    // presentation on the wire.
    format!("{:.2}", v)
}

/// Format a quantity: trim trailing zeros on the decimal so `1.0000`
/// reads as `1` and `2.5000` reads as `2.5`.
fn format_decimal(v: &Decimal) -> String {
    let normalized = v.normalize();
    normalized.to_string()
}

/// Split a paragraph into <= `max_chars` chunks at whitespace so a
/// long notes line does not exit the page bounds. Naïve; good enough
/// for MVP.
fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.chars().count() <= max_chars {
            out.push(line.to_string());
            continue;
        }
        let mut current = String::new();
        for word in line.split_whitespace() {
            if current.chars().count() + word.chars().count() + 1 > max_chars {
                out.push(std::mem::take(&mut current));
            }
            if !current.is_empty() {
                current.push(' ');
            }
            current.push_str(word);
        }
        if !current.is_empty() {
            out.push(current);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;

    fn sample_invoice() -> InvoiceResponse {
        use super::super::models::*;
        use chrono::{NaiveDate, TimeZone, Utc};
        InvoiceResponse {
            id: uuid::Uuid::nil(),
            tenant_id: uuid::Uuid::nil(),
            invoice_number: "INV-000001".to_string(),
            company_id: uuid::Uuid::nil(),
            company_name: Some("Acme Corp".to_string()),
            billing_contact_id: None,
            contract_id: None,
            status: InvoiceStatus::Pending,
            invoice_date: NaiveDate::from_ymd_opt(2026, 8, 1).unwrap(),
            due_date: NaiveDate::from_ymd_opt(2026, 8, 15).unwrap(),
            payment_terms: Some("Net 15".to_string()),
            payment_term_id: None,
            payment_term_name: None,
            subtotal: Decimal::new(10000, 2),
            tax_amount: Decimal::new(1000, 2),
            discount_amount: Decimal::new(0, 2),
            total: Decimal::new(11000, 2),
            amount_paid: Decimal::new(0, 2),
            balance_due: Decimal::new(11000, 2),
            currency: Some("USD".to_string()),
            notes: Some("Thanks for your business.".to_string()),
            po_number: Some("PO-42".to_string()),
            sent_at: None,
            paid_at: None,
            created_at: Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap(),
            updated_at: Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap(),
            lines: Some(vec![InvoiceLineResponse {
                id: uuid::Uuid::nil(),
                line_type: InvoiceLineType::Service,
                description: "Managed IT services".to_string(),
                quantity: Decimal::new(10, 0),
                unit_price: Decimal::new(10000, 2),
                total: Decimal::new(100000, 2),
                ticket_id: None,
                project_id: None,
                sort_order: 0,
            }]),
        }
    }

    #[test]
    fn renders_pdf_bytes() {
        let inv = sample_invoice();
        let bytes = render_invoice_pdf("Test MSP", &inv).expect("render");
        assert!(bytes.len() > 500, "pdf smaller than a header alone: {}", bytes.len());
        // PDF files start with `%PDF-`.
        assert_eq!(&bytes[..5], b"%PDF-", "not a pdf: prefix {:?}", &bytes[..8]);
    }

    #[test]
    fn wrap_text_splits_on_whitespace() {
        let out = wrap_text("this is a long sentence that should wrap at 20 chars", 20);
        assert!(out.iter().all(|l| l.chars().count() <= 20), "{:?}", out);
    }

    #[test]
    fn format_money_pads_two_decimals() {
        assert_eq!(format_money(&Decimal::new(10, 0)), "10.00");
        assert_eq!(format_money(&Decimal::new(1050, 2)), "10.50");
    }
}
