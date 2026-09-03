//! What `?sort=` accepts, per list endpoint (PMS-897).
//!
//! One definition, shared by the server that validates it and the client that
//! constructs it. Before this, mokosh-apps mirrored these lists by hand in
//! `src/utils/sort_keys.rs`, and the file said so:
//!
//! > Mirrored by hand because the allow-lists are locals inside the server's
//! > service functions and are not exported through `mokosh-types`.
//!
//! That copy went stale within a day of being written: PMS-894 added five sort
//! keys to the ticket list and nothing obliged the mirror to follow. The three
//! parity audits that preceded it found the same shape three times.
//!
//! **Public keys only. No SQL.** A key here is what a caller puts in the query
//! string; the column or expression it orders by is the server's business and
//! must not cross the wire. `PaginationParams::order_by_mapped` exists
//! precisely so a joined column can be sorted without naming it, and that
//! separation is worth nothing if the mapping leaks through here.
//!
//! Not here on purpose: the sort DIRECTION, which is its own parameter with its
//! own contract, and each endpoint's DEFAULT ordering, which is a server
//! implementation choice a client has no reason to know.

/// `GET /api/v1/auth/users`.
pub const USERS: &[&str] = &[
    "email",
    "first_name",
    "last_name",
    "role",
    "status",
    "created_at",
];

/// `GET /api/v1/contacts/companies`.
pub const COMPANIES: &[&str] = &["name", "created_at", "updated_at"];

/// `GET /api/v1/contacts/contacts`.
pub const CONTACTS: &[&str] = &["first_name", "last_name", "email", "created_at"];

/// `GET /api/v1/invoices`.
pub const INVOICES: &[&str] = &["invoice_date", "due_date", "total", "created_at"];

/// `GET /api/v1/payments`.
pub const PAYMENTS: &[&str] = &["payment_date", "amount", "created_at"];

/// `GET /api/v1/mileage`.
pub const MILEAGE: &[&str] = &["date", "distance_miles", "created_at"];

/// `GET /api/v1/projects`.
pub const PROJECTS: &[&str] = &["name", "start_date", "created_at"];

/// `GET /api/v1/quotes`.
pub const QUOTES: &[&str] = &["created_at", "valid_until", "total", "title"];

/// `GET /api/v1/quotes` (the second lister, without `title`).
pub const QUOTE_REQUESTS: &[&str] = &["created_at", "valid_until", "total"];

/// `GET /api/v1/tickets`, the joined lister the SPA's ticket list consumes.
///
/// Wider than [`TICKETS_BARE`] because these order by joined columns, which
/// only that query has aliases for. PMS-894 added the last five; the client's
/// hand mirror still listed the first three plus `priority_id` when PMS-897
/// replaced it, which is the drift this module exists to end.
pub const TICKETS: &[&str] = &[
    "created_at",
    "updated_at",
    "sla_due_date",
    "ticket_number",
    "company_name",
    "status",
    "priority",
    "assigned_to_name",
];

/// The lower-level ticket lister, which selects `FROM tickets t` with no joins
/// and so has no alias to order a joined column by.
pub const TICKETS_BARE: &[&str] = &["created_at", "updated_at", "sla_due_date", "priority_id"];

/// `GET /api/v1/time-entries`.
pub const TIME_ENTRIES: &[&str] = &["date", "duration_minutes", "created_at"];

#[cfg(test)]
mod tests {
    use super::*;

    /// A key here is a wire value. Anything qualified, parenthesised or spaced
    /// is a SQL expression that has escaped the server, which is the one
    /// mistake this module could make that would be worse than the hand mirror
    /// it replaces: `order_by_mapped` exists so a joined column can be sorted
    /// without naming it.
    #[test]
    fn no_key_is_sql() {
        let lists: &[(&str, &[&str])] = &[
            ("USERS", USERS),
            ("COMPANIES", COMPANIES),
            ("CONTACTS", CONTACTS),
            ("INVOICES", INVOICES),
            ("PAYMENTS", PAYMENTS),
            ("MILEAGE", MILEAGE),
            ("PROJECTS", PROJECTS),
            ("QUOTES", QUOTES),
            ("QUOTE_REQUESTS", QUOTE_REQUESTS),
            ("TICKETS", TICKETS),
            ("TICKETS_BARE", TICKETS_BARE),
            ("TIME_ENTRIES", TIME_ENTRIES),
        ];
        for (name, keys) in lists {
            assert!(!keys.is_empty(), "{name} is empty");
            for key in *keys {
                assert!(
                    key.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                    "{name} carries `{key}`, which is not a bare wire key"
                );
            }
            let mut sorted = keys.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), keys.len(), "{name} repeats a key");
        }
    }
}
