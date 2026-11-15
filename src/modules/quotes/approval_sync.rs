//! PMS-1624: an approvals decision on a quote moves the quote's status.
//!
//! `src/modules/approvals/` records sign-off for four targets and, by
//! deliberate design, gates none of them: `ApprovalsService::decide` writes
//! only `ticket_approvals`. For quotes that left two independent records of
//! one idea, which could disagree in both directions - an `approved` approval
//! row on a quote still sitting at `submitted`, or an `approved` quote with no
//! approval row at all. PMS-1573 is where that came to light, as a defect
//! report saying `approved` was unreachable.
//!
//! This module is the one place that writes `quotes.status` on behalf of an
//! approval, and it lives in the quotes module rather than in approvals so the
//! column keeps one owner. The approvals service calls [`apply_decision`]
//! inside its own transaction, after the approval row is updated, which is
//! what lets the count below see the decision being made.
//!
//! # The rule
//!
//! A quote goes `approved` when every staff-addressed approval on it is
//! decided and all of them approved. Any rejection moves it to `rejected` at
//! once, and the veto stands: the quote has left `submitted`, so a later
//! approval of a second row finds nothing to move.
//!
//! Only out of `submitted`. A decision landing on a `draft`, `sent`,
//! `cancelled` or already-decided quote is still recorded - an approver must
//! never be blocked by a status change they had no part in - and simply does
//! not move it.
//!
//! # Only staff-addressed approvals count
//!
//! A row addressed to a contact (`approver_contact_id`) is the CLIENT asking
//! for or giving sign-off, and `QuoteStatus` keeps the client's decision in
//! `Accepted` / `Declined`, spelled differently from the internal
//! `Approved` / `Rejected` precisely so the two cannot be confused. Letting a
//! contact's decision write the internal status would collapse that
//! distinction, and letting a contact-addressed row sit `pending` and block
//! the internal chain would stall staff sign-off on a customer. So this
//! counts, and is driven by, `approver_contact_id IS NULL` rows only.

use sqlx::PgConnection;
use uuid::Uuid;

use super::models::QuoteStatus;
use crate::utils::error::AppResult;

// SPEC-13.1393
/// What a decision does to a quote in `current`, given how its other
/// staff-addressed approvals stand.
///
/// Pure, so the arithmetic is testable without a database: the counts are
/// what the query below answers, and every combination of them has one right
/// answer that is easier to read here than inside a transaction.
///
/// `pending` and `rejected` are counted AFTER the decision has been written,
/// so the row being decided is included in them.
pub(crate) fn outcome(current: QuoteStatus, pending: i64, rejected: i64) -> Option<QuoteStatus> {
    // A quote that has left `submitted` is not in an approval; the decision
    // is recorded and nothing moves.
    if current != QuoteStatus::Submitted {
        return None;
    }
    // One rejection is a veto, whoever else approved and whoever has not
    // answered yet. Waiting for the rest would leave a quote in `submitted`
    // that a named approver has already turned down.
    if rejected > 0 {
        return Some(QuoteStatus::Rejected);
    }
    // Everyone has answered and nobody objected.
    if pending == 0 {
        return Some(QuoteStatus::Approved);
    }
    // Still waiting on somebody.
    None
}

// SPEC-13.1394
/// Apply a decision on `quote_id` to the quote's own status, inside the
/// caller's transaction. Returns the status it moved to, or `None`.
///
/// Locks the quote row first: two approvers deciding the last two rows at
/// once would otherwise both read `submitted` and both compute an outcome,
/// and the pair "reject, approve" would land in whichever order the writes
/// happened to commit. PMS-1236 closed the same race on the approval row.
pub(crate) async fn apply_decision(
    conn: &mut PgConnection,
    tenant_id: Uuid,
    quote_id: Uuid,
) -> AppResult<Option<QuoteStatus>> {
    let current: Option<String> =
        sqlx::query_scalar("SELECT status FROM quotes WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
            .bind(tenant_id)
            .bind(quote_id)
            .fetch_optional(&mut *conn)
            .await?;
    // A decision on an approval whose parent has been deleted is still a
    // valid decision; there is just no quote left to move.
    let Some(current) = current else {
        return Ok(None);
    };
    let current = QuoteStatus::from_str(&current).unwrap_or(QuoteStatus::Draft);

    let (pending, rejected): (i64, i64) = sqlx::query_as(
        r#"SELECT COUNT(*) FILTER (WHERE status = 'pending'),
                  COUNT(*) FILTER (WHERE status = 'rejected')
           FROM ticket_approvals
           WHERE tenant_id = $1
             AND target = 'quote'
             AND entity_id = $2
             AND approver_contact_id IS NULL"#,
    )
    .bind(tenant_id)
    .bind(quote_id)
    .fetch_one(&mut *conn)
    .await?;

    let Some(next) = outcome(current, pending, rejected) else {
        return Ok(None);
    };
    sqlx::query("UPDATE quotes SET status = $3 WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(quote_id)
        .bind(next.as_str())
        .execute(&mut *conn)
        .await?;
    Ok(Some(next))
}

// SPEC-13.1395, SPEC-13.1370
/// Whether a staff-addressed approval on `quote_id` is still awaiting a
/// decision.
///
/// `update_quote` refuses a manual `approved` while one is, so a quote under
/// an approval chain has one authority rather than two: "Mark approved" and
/// the chain would otherwise race, and whichever landed second would be
/// silently ignored.
///
/// A manual `rejected` is deliberately still allowed. It is the same answer a
/// veto gives, so it creates no conflicting claim, and refusing it would
/// strand a quote whose named approver has gone on leave.
pub(crate) async fn has_pending_staff_approval(
    conn: &mut PgConnection,
    tenant_id: Uuid,
    quote_id: Uuid,
) -> AppResult<bool> {
    let pending: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM ticket_approvals
           WHERE tenant_id = $1
             AND target = 'quote'
             AND entity_id = $2
             AND approver_contact_id IS NULL
             AND status = 'pending'"#,
    )
    .bind(tenant_id)
    .bind(quote_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(pending > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every shape the counts can take, against every status.
    ///
    /// Table-driven because the interesting part is the combinations, and a
    /// test per case would hide which ones are missing.
    #[test]
    fn the_outcome_table_is_complete() {
        for (current, pending, rejected, want, why) in [
            (
                QuoteStatus::Submitted,
                0,
                0,
                Some(QuoteStatus::Approved),
                "everyone answered, nobody objected",
            ),
            (
                QuoteStatus::Submitted,
                1,
                0,
                None,
                "still waiting on an approver",
            ),
            (
                QuoteStatus::Submitted,
                0,
                1,
                Some(QuoteStatus::Rejected),
                "a veto with everyone answered",
            ),
            (
                QuoteStatus::Submitted,
                2,
                1,
                Some(QuoteStatus::Rejected),
                "a veto does not wait for the rest",
            ),
            (QuoteStatus::Draft, 0, 0, None, "not in an approval"),
            (
                QuoteStatus::Approved,
                0,
                0,
                None,
                "already decided; a second pass must not rewrite it",
            ),
            (QuoteStatus::Rejected, 0, 0, None, "the veto stands"),
            (
                QuoteStatus::Sent,
                0,
                0,
                None,
                "issued; no staff write may touch it",
            ),
            (
                QuoteStatus::Accepted,
                0,
                1,
                None,
                "the client has answered; an internal veto is too late",
            ),
            (
                QuoteStatus::Converted,
                0,
                0,
                None,
                "a record, not a workflow",
            ),
            (QuoteStatus::Cancelled, 0, 0, None, "killed internally"),
            (
                QuoteStatus::Expired,
                0,
                0,
                None,
                "derived, never written here",
            ),
            (QuoteStatus::Declined, 0, 1, None, "the client has answered"),
        ] {
            assert_eq!(
                outcome(current, pending, rejected),
                want,
                "{} with {pending} pending and {rejected} rejected: {why}",
                current.as_str()
            );
        }
    }

    /// The veto is checked before the "everyone answered" rule, so a quote
    /// whose last outstanding decision is a rejection is rejected rather than
    /// approved. Stated on its own because swapping the two `if`s compiles
    /// and passes a careless reading.
    #[test]
    fn a_rejection_outranks_a_complete_chain() {
        assert_eq!(
            outcome(QuoteStatus::Submitted, 0, 1),
            Some(QuoteStatus::Rejected),
            "a chain that is complete AND contains a rejection is rejected"
        );
    }
}
