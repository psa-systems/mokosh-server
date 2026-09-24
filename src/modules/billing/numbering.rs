//! PMS-979: what an invoice number is, and who it belongs to.
//!
//! Every invoice in a tenant used to draw from one counter, so a number was
//! `INV-000042`: it said nothing about whose invoice it was, and it told every
//! customer who received one how many invoices the MSP had issued in total.
//! That was survivable while numbers were internal and stopped being so when
//! the portal started showing them.
//!
//! The scheme here is a short per-customer prefix, a dash, and a zero-padded
//! per-customer sequence: `A7QF-000001`. A customer's invoices are visibly
//! theirs, their history reads consecutively, and the tenant's volume is no
//! longer on the document.
//!
//! Four things are decided rather than incidental.
//!
//! **The prefix is random, not derived from the name.** Names collide, names
//! change, and a derived identifier stops being stable the first time a
//! customer rebrands. Migration 174 settled the same question for `portal_id`
//! and this follows it.
//!
//! **The alphabet excludes I, L, O, 0 and 1**, so a number read back over the
//! phone cannot become a different customer's. That leaves 31 characters and
//! 923,521 prefixes per tenant, which is the "medium future" the issue asks
//! for rather than infinite scale; a collision retries rather than being
//! assumed away.
//!
//! **The counter is a table row, not a Postgres sequence.** A sequence keeps
//! its increment when the transaction that took it rolls back, and a refused
//! send or a failed create would then leave a hole in a customer's numbering.
//! Gap-free is an audit expectation on invoices, so the counter rolls back
//! with everything else and concurrent creates queue on the row.
//!
//! **The scheme is selectable and recorded.** `billing_prefs/invoice_numbering`
//! chooses it per tenant and defaults to the old tenant-wide counter, because
//! an MSP's invoice numbering is an accounting decision and changing it under
//! them mid-year is not this issue's call to make. Every invoice records which
//! scheme produced its number, so the next change is also a switch rather than
//! a renumbering.
//!
//! The year is deliberately not part of a number. Every invoice-numbering
//! discussion reaches for it, and adding it later would restart every
//! customer's sequence each January, which is the renumbering this design
//! exists to avoid.

use uuid::Uuid;

use crate::modules::auth::tenant::TenantId;
use crate::utils::error::{AppError, AppResult};

/// Unambiguous when read aloud or written by hand: no I, L, O, 0 or 1.
pub const PREFIX_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// Four characters, which is 923,521 prefixes per tenant.
pub const PREFIX_LEN: usize = 4;

/// How many fresh prefixes to try before giving up. A collision needs two
/// draws from 923,521 to match, so five failures in a row means something
/// other than chance and should fail loudly rather than spin.
const PREFIX_ATTEMPTS: usize = 5;

/// Which scheme produced a number. Stored on the invoice so a later change is
/// a switch rather than a renumbering (`invoices.number_scheme`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberScheme {
    /// The pre-PMS-979 shape: one counter per tenant, `INV-000042`.
    TenantSequence,
    /// Per-customer prefix and counter, `A7QF-000001`.
    CompanyPrefix,
}

impl NumberScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TenantSequence => "tenant_sequence",
            Self::CompanyPrefix => "company_prefix",
        }
    }

    /// The tenant's setting, or the default. Unknown text reads as the
    /// default rather than failing a create: the settings route validates the
    /// value on the way in (`validate_setting_value`), so a value outside the
    /// set can only be a hand-edited row, and refusing every invoice would be
    /// a worse answer to it than numbering one the old way.
    pub fn from_setting(value: Option<&str>) -> Self {
        match value {
            Some("company_prefix") => Self::CompanyPrefix,
            _ => Self::TenantSequence,
        }
    }
}

/// One random prefix. Uniqueness is the index's job, not this function's.
pub fn generate_prefix() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    (0..PREFIX_LEN)
        .map(|_| PREFIX_ALPHABET[rng.random_range(0..PREFIX_ALPHABET.len())] as char)
        .collect()
}

/// The company's prefix, assigning one if it has none.
///
/// Lazy rather than backfilled, the `ensure_portal_id` shape (PMS-928): a
/// company that is never invoiced never needs one, and an existing tenant
/// does not have to be migrated before it can issue an invoice.
///
/// The UPDATE guards on `invoice_prefix IS NULL`, so two concurrent first
/// invoices for one company cannot overwrite each other: the loser reads back
/// what the winner installed. A unique violation means two DIFFERENT companies
/// drew the same prefix, which retries with a fresh draw.
pub async fn ensure_company_prefix(
    tx: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    company_id: Uuid,
) -> AppResult<String> {
    let existing: Option<Option<String>> =
        sqlx::query_scalar("SELECT invoice_prefix FROM companies WHERE id = $1 AND tenant_id = $2")
            .bind(company_id)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(existing) = existing else {
        return Err(AppError::NotFound("Company".to_string()));
    };
    if let Some(prefix) = existing {
        return Ok(prefix);
    }

    for _ in 0..PREFIX_ATTEMPTS {
        let candidate = generate_prefix();
        let updated = sqlx::query(
            "UPDATE companies SET invoice_prefix = $1, updated_at = NOW() \
             WHERE id = $2 AND tenant_id = $3 AND invoice_prefix IS NULL",
        )
        .bind(&candidate)
        .bind(company_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await;
        match updated {
            Ok(result) if result.rows_affected() == 1 => return Ok(candidate),
            // Nobody updated: another writer assigned one first. Read theirs.
            Ok(_) => {
                let theirs: Option<String> = sqlx::query_scalar(
                    "SELECT invoice_prefix FROM companies WHERE id = $1 AND tenant_id = $2",
                )
                .bind(company_id)
                .bind(tenant_id)
                .fetch_optional(&mut *tx)
                .await?
                .flatten();
                if let Some(prefix) = theirs {
                    return Ok(prefix);
                }
            }
            // A unique violation is another company holding this draw.
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("23505") => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(AppError::internal(
        "could not assign an invoice prefix for this company after several attempts",
    ))
}

/// Take the next number for this company, seeding the counter on first use.
///
/// Gap-free by construction: the row is updated inside the caller's
/// transaction, so a create that rolls back gives the number back, and a
/// concurrent create blocks on the row rather than reading a stale counter.
pub async fn next_company_number(
    tx: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    company_id: Uuid,
) -> AppResult<i32> {
    let bumped: Option<(i32,)> = sqlx::query_as(
        "UPDATE invoice_company_sequences SET last_number = last_number + 1 \
         WHERE tenant_id = $1 AND company_id = $2 RETURNING last_number",
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((n,)) = bumped {
        return Ok(n);
    }
    // First invoice for this customer. `ON CONFLICT DO NOTHING` plus a
    // re-bump covers the race where two first invoices arrive together: one
    // inserts, the other finds the row and takes 2.
    let inserted: Option<(i32,)> = sqlx::query_as(
        "INSERT INTO invoice_company_sequences (tenant_id, company_id, last_number) \
         VALUES ($1, $2, 1) ON CONFLICT (tenant_id, company_id) DO NOTHING \
         RETURNING last_number",
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((n,)) = inserted {
        return Ok(n);
    }
    let (n,): (i32,) = sqlx::query_as(
        "UPDATE invoice_company_sequences SET last_number = last_number + 1 \
         WHERE tenant_id = $1 AND company_id = $2 RETURNING last_number",
    )
    .bind(tenant_id)
    .bind(company_id)
    .fetch_one(&mut *tx)
    .await?;
    Ok(n)
}

/// Format a number under the per-customer scheme.
pub fn format_company_number(prefix: &str, sequence: i32) -> String {
    format!("{prefix}-{sequence:06}")
}

/// Read the tenant's chosen scheme. Runs on the caller's tenant-GUC
/// connection because `tenant_settings` is RLS-covered.
pub async fn read_scheme(
    tx: &mut sqlx::PgConnection,
    tenant_id: TenantId,
) -> AppResult<NumberScheme> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM tenant_settings \
         WHERE tenant_id = $1 AND category = 'billing_prefs' AND key = 'invoice_numbering'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    Ok(NumberScheme::from_setting(
        value.as_ref().and_then(|v| v.as_str()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Shape first: four characters from the unambiguous alphabet.
    #[test]
    fn a_prefix_is_four_unambiguous_characters() {
        for _ in 0..500 {
            let prefix = generate_prefix();
            assert_eq!(prefix.len(), PREFIX_LEN, "{prefix}");
            for c in prefix.chars() {
                assert!(
                    PREFIX_ALPHABET.contains(&(c as u8)),
                    "{c} is not in the alphabet: {prefix}"
                );
                assert!(
                    !"ILO01".contains(c),
                    "{c} is ambiguous when read aloud: {prefix}"
                );
            }
        }
    }

    /// It is a draw, not a derivation. 500 draws landing on one value would
    /// mean the generator is keyed on something, which is the failure this
    /// scheme is built to avoid.
    #[test]
    fn prefixes_are_drawn_rather_than_derived() {
        let drawn: HashSet<String> = (0..500).map(|_| generate_prefix()).collect();
        assert!(drawn.len() > 400, "only {} distinct in 500", drawn.len());
    }

    /// The customer-facing shape, and the zero padding that keeps a list of a
    /// customer's invoices sorting in issue order as text.
    #[test]
    fn a_number_reads_as_prefix_dash_sequence() {
        assert_eq!(format_company_number("A7QF", 1), "A7QF-000001");
        assert_eq!(format_company_number("A7QF", 42), "A7QF-000042");
        assert_eq!(format_company_number("A7QF", 999_999), "A7QF-999999");
        // Past the padding it grows rather than wrapping or truncating.
        assert_eq!(format_company_number("A7QF", 1_000_000), "A7QF-1000000");
    }

    /// The default is the old scheme, so no existing tenant's numbering moves
    /// when this ships. Only the exact opt-in value switches it.
    #[test]
    fn the_scheme_defaults_to_the_tenant_counter() {
        assert_eq!(
            NumberScheme::from_setting(None),
            NumberScheme::TenantSequence
        );
        assert_eq!(
            NumberScheme::from_setting(Some("tenant_sequence")),
            NumberScheme::TenantSequence
        );
        assert_eq!(
            NumberScheme::from_setting(Some("company_prefix")),
            NumberScheme::CompanyPrefix
        );
        // A hand-edited row numbers the old way rather than refusing every
        // invoice the tenant tries to create.
        assert_eq!(
            NumberScheme::from_setting(Some("something-else")),
            NumberScheme::TenantSequence
        );
    }
}
