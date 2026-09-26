//! Pagination utilities for API responses.
//!
//! Handler convention (PMS-127): every paginated `list_*` handler
//! takes `Query<PaginationParams>`, calls the service with
//! `&PaginationParams`, and wraps the result in
//! `PaginatedResponse::from_params(items, &pagination, total)`. When
//! a handler also accepts a filter, both extractors live side-by-side
//! (`Query<XxxFilter>` + `Query<PaginationParams>`) and axum parses
//! the same query string twice. This relies on every `*Filter` type
//! (and `PaginationParams` itself) using serde defaults for missing
//! fields and NOT setting `#[serde(deny_unknown_fields)]`. Adding
//! `deny_unknown_fields` to a filter type would silently 400 every
//! `?page=2`-style request hitting that handler. If a future filter
//! must be strict, fold pagination into the same struct via
//! `#[serde(flatten)] pagination: PaginationParams` instead of
//! stacking two `Query<_>` extractors.

use serde::{Deserialize, Serialize};

use crate::utils::error::{AppError, AppResult};

/// Pagination parameters from query string
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PaginationParams {
    /// Page number (1-indexed)
    #[serde(default = "default_page")]
    pub page: u32,
    /// Items per page
    #[serde(default = "default_per_page")]
    pub per_page: u32,
    /// Sort field
    pub sort: Option<String>,
    /// Sort direction (asc/desc)
    #[serde(default = "default_sort_dir")]
    pub sort_dir: String,
}

fn default_page() -> u32 {
    1
}

fn default_per_page() -> u32 {
    25
}

fn default_sort_dir() -> String {
    "desc".to_string()
}

/// MAPPS-533: the 422 both `order_by` helpers return.
///
/// Names the parameter and lists what it accepts, because a rejection that does
/// not say what would have worked just moves the guessing to the client.
/// `validation_field` is this codebase's existing 422 shape, so this reads like
/// every other field-level rejection rather than introducing a convention.
fn unknown_sort(requested: &str, allowed: &[&str]) -> AppError {
    AppError::validation_field(
        "sort",
        format!(
            "unknown sort field `{requested}`; accepted: {}",
            allowed.join(", ")
        ),
    )
}

impl PaginationParams {
    /// PMS-1238: `sort_dir` other than asc/desc is a 422, not a silent DESC.
    /// An empty value (the `Default` shape) stays the descending default.
    fn direction(&self) -> AppResult<&'static str> {
        match self.sort_dir.to_lowercase().as_str() {
            "asc" => Ok("ASC"),
            "" | "desc" => Ok("DESC"),
            other => Err(AppError::validation_field(
                "sort_dir",
                format!("unknown sort direction `{other}`; accepted: asc, desc"),
            )),
        }
    }

    /// Maximum allowed items per page
    pub const MAX_PER_PAGE: u32 = 100;

    /// Calculate the offset for database queries
    pub fn offset(&self) -> u32 {
        (self.page.saturating_sub(1)) * self.per_page()
    }

    /// Get the per_page value, clamped to MAX_PER_PAGE
    pub fn per_page(&self) -> u32 {
        self.per_page.clamp(1, Self::MAX_PER_PAGE)
    }

    /// Get the limit for database queries
    pub fn limit(&self) -> u32 {
        self.per_page()
    }

    /// Check if sort direction is ascending
    pub fn is_ascending(&self) -> bool {
        self.sort_dir.to_lowercase() == "asc"
    }

    /// Get SQL ORDER BY clause
    /// Build an `ORDER BY` body (`"<column> <ASC|DESC>"`) from the request's
    /// `sort` (validated against `allowed_fields`) or `default_field`.
    ///
    /// `default_field` MUST be a bare column name: this appends the direction,
    /// so `"created_at DESC"` would yield `"created_at DESC DESC"` and a SQL
    /// syntax error. To keep that footgun non-fatal (it bit four call sites -
    /// PMS-145) we defensively keep only the first whitespace token.
    /// PMS-894: `order_by` for a query whose sortable columns are joined, so
    /// the name a client sends is not the SQL that sorts by it.
    ///
    /// Takes `(public key, SQL expression)` pairs and matches on the key, so
    /// `sort=company` becomes `ORDER BY co.name` without the API ever
    /// admitting a column name, let alone accepting one. The plain
    /// [`Self::order_by`] cannot do this: it splices the client's string
    /// straight in, which is safe only while the sortable columns and the
    /// public names are the same word.
    ///
    /// MAPPS-533: rejects an unknown key exactly as [`Self::order_by`] does.
    /// The 422 names the public keys, never the SQL they map to.
    pub fn order_by_mapped(
        &self,
        default_sql: &str,
        allowed: &[(&str, &str)],
    ) -> AppResult<String> {
        self.reject_over_cap_per_page()?;
        let sql = match self.sort.as_deref() {
            Some(requested) => match allowed.iter().find(|(key, _)| *key == requested) {
                Some((_, expr)) => *expr,
                None => {
                    let keys: Vec<&str> = allowed.iter().map(|(key, _)| *key).collect();
                    return Err(unknown_sort(requested, &keys));
                }
            },
            None => default_sql,
        };

        let direction = self.direction()?;

        Ok(format!("{} {}", sql, direction))
    }

    /// A `per_page` above [`Self::MAX_PER_PAGE`] is a 422 that names the
    /// requested value and the cap, so a client cannot mistake a truncated
    /// page for a whole page. `per_page` below 1 keeps its silent clamp to 1
    /// (a request for zero rows is a different class of mistake), and a
    /// request that omits `per_page` keeps the default.
    pub fn reject_over_cap_per_page(&self) -> AppResult<()> {
        if self.per_page > Self::MAX_PER_PAGE {
            return Err(AppError::validation_field(
                "per_page",
                format!(
                    "{} exceeds the maximum of {}",
                    self.per_page,
                    Self::MAX_PER_PAGE
                ),
            ));
        }
        Ok(())
    }

    /// MAPPS-533: an unrecognised `sort` is a 422, not a silent fallback.
    ///
    /// This used to drop the value and sort by the default, answering 200 with
    /// rows in an order the caller never asked for. That silence is what let a
    /// client-side mismatch survive three parity audits: the SPA sent
    /// `company_type`, `company_name` and `-updated_at`, none of them
    /// allow-listed, and no request ever failed.
    ///
    /// The allow-list itself stays, and stays the only thing that reaches SQL.
    /// Rejecting is about telling the caller, not about what is safe to splice.
    /// A `sort` that is absent is unchanged - it uses `default_field` - so a
    /// caller that never asks to sort can never see a 422.
    pub fn order_by(&self, default_field: &str, allowed_fields: &[&str]) -> AppResult<String> {
        self.reject_over_cap_per_page()?;
        let default_field = default_field
            .split_whitespace()
            .next()
            .unwrap_or(default_field);
        let field = match self.sort.as_deref() {
            Some(requested) if !allowed_fields.contains(&requested) => {
                return Err(unknown_sort(requested, allowed_fields));
            }
            Some(requested) => requested,
            None => default_field,
        };

        let direction = self.direction()?;

        Ok(format!("{} {}", field, direction))
    }

    /// PMS-1194: for a handler that has not been wired to an allow-list,
    /// this is the whole contract. A `sort` param used to be accepted and
    /// silently dropped there, so a 200 gave no signal about whether the
    /// order the client asked for was the order it got; MAPPS-527 shipped a
    /// client built on that false assumption. Call this before using
    /// `pagination` in any handler whose service call does not itself go
    /// through `order_by` / `order_by_mapped`, so the caller gets a 422
    /// naming `sort` instead of a 200 in the default order. A `sort` that is
    /// absent is unchanged, exactly as with the two helpers above: a caller
    /// that never asks to sort never sees this.
    pub fn reject_unsupported_sort(&self) -> AppResult<()> {
        self.reject_over_cap_per_page()?;
        match self.sort.as_deref() {
            Some(requested) => Err(AppError::validation_field(
                "sort",
                format!("unknown sort field `{requested}`; this endpoint does not support sorting"),
            )),
            None => Ok(()),
        }
    }
}

/// Paginated response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    /// The data items
    pub data: Vec<T>,
    /// Pagination metadata
    pub meta: PaginationMeta,
}

/// Pagination metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMeta {
    /// Current page number
    pub page: u32,
    /// Items per page
    pub per_page: u32,
    /// Total number of items
    pub total: u64,
    /// Total number of pages
    pub total_pages: u32,
    /// Whether there is a next page
    pub has_next: bool,
    /// Whether there is a previous page
    pub has_prev: bool,
}

impl<T> PaginatedResponse<T> {
    /// Create a new paginated response
    pub fn new(data: Vec<T>, page: u32, per_page: u32, total: u64) -> Self {
        // Guard against per_page == 0: division by zero yields NaN/inf,
        // which casts to a nonsensical total_pages (0 or u32::MAX). Clamp
        // to at least one item per page so paging math stays well defined.
        let per_page = per_page.max(1);
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

        Self {
            data,
            meta: PaginationMeta {
                page,
                per_page,
                total,
                total_pages,
                has_next: page < total_pages,
                has_prev: page > 1,
            },
        }
    }

    /// Create from pagination params
    pub fn from_params(data: Vec<T>, params: &PaginationParams, total: u64) -> Self {
        Self::new(data, params.page, params.per_page(), total)
    }

    /// Map the data items to a new type
    pub fn map<U, F>(self, f: F) -> PaginatedResponse<U>
    where
        F: FnMut(T) -> U,
    {
        PaginatedResponse {
            data: self.data.into_iter().map(f).collect(),
            meta: self.meta,
        }
    }
}

#[cfg(test)]
mod pms894_tests {
    use super::*;

    fn params(sort: Option<&str>, dir: &str) -> PaginationParams {
        PaginationParams {
            page: 1,
            per_page: 25,
            sort: sort.map(|s| s.to_string()),
            sort_dir: dir.to_string(),
        }
    }

    const TICKET_SORTS: &[(&str, &str)] =
        &[("company_name", "co.name"), ("priority", "tp.sort_order")];

    /// PMS-894: the public key is what a client sends; the SQL is what sorts.
    /// The API never admits a column name, which is the point of the mapped
    /// variant: `order_by` splices the client's own string in, so it can only
    /// ever offer columns whose public name IS their SQL name.
    #[test]
    fn a_mapped_key_sorts_by_its_expression_not_its_name() {
        assert_eq!(
            params(Some("company_name"), "asc")
                .order_by_mapped("t.created_at", TICKET_SORTS)
                .expect("an allow-listed key is accepted"),
            "co.name ASC"
        );
        assert_eq!(
            params(Some("priority"), "desc")
                .order_by_mapped("t.created_at", TICKET_SORTS)
                .expect("an allow-listed key is accepted"),
            "tp.sort_order DESC"
        );
    }

    /// The field-level message inside a `Validation` error. The `Display` of
    /// that variant is a fixed summary ("one or more fields are invalid"), so
    /// the detail a caller acts on lives in its `errors`, not in `to_string()`.
    fn sort_field_message(err: &AppError) -> String {
        match err {
            AppError::Validation { errors, .. } => {
                let e = errors
                    .iter()
                    .find(|e| e.field == "sort")
                    .expect("the rejection names the `sort` field");
                e.message.clone()
            }
            other => panic!("expected a validation error, got {other:?}"),
        }
    }

    /// MAPPS-533: an unknown key is rejected, not quietly swapped for the
    /// default. PMS-894 wrote this test the other way round and left the
    /// question open; this is the answer.
    ///
    /// The rejection still keeps arbitrary text out of the SQL - that never
    /// depended on the fallback - and it now also tells the caller, which the
    /// fallback could not.
    #[test]
    fn an_unknown_key_is_rejected() {
        let err = params(Some("co.name"), "asc")
            .order_by_mapped("t.created_at", TICKET_SORTS)
            .expect_err("the SQL expression is not itself an accepted key");
        assert_eq!(err.status_code(), 422);
        let message = sort_field_message(&err);
        assert!(
            message.contains("co.name") && message.contains("company_name"),
            "the 422 names what was asked for and what is accepted, got {message}"
        );

        assert!(params(Some("; DROP TABLE tickets"), "asc")
            .order_by_mapped("t.created_at", TICKET_SORTS)
            .is_err());

        // No `sort` at all is not an error: a caller that never asks to sort
        // cannot be told it asked wrongly.
        assert_eq!(
            params(None, "desc")
                .order_by_mapped("t.created_at", TICKET_SORTS)
                .expect("absent sort uses the default"),
            "t.created_at DESC"
        );
    }

    /// The same contract on the plain helper, where the twelve list endpoints
    /// live.
    #[test]
    fn the_plain_helper_rejects_and_lists_what_it_accepts() {
        let allowed = ["name", "created_at", "updated_at"];
        let err = params(Some("company_type"), "asc")
            .order_by("name", &allowed)
            .expect_err("company_type is not allow-listed");
        assert_eq!(err.status_code(), 422);
        let message = sort_field_message(&err);
        for key in allowed {
            assert!(
                message.contains(key),
                "the 422 must list `{key}`, got {message}"
            );
        }

        assert_eq!(
            params(Some("name"), "asc")
                .order_by("created_at", &allowed)
                .expect("an allow-listed key is accepted"),
            "name ASC"
        );
        assert_eq!(
            params(None, "desc")
                .order_by("created_at", &allowed)
                .expect("absent sort uses the default"),
            "created_at DESC"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_params_defaults() {
        // Note: Rust Default gives 0 for u32, serde defaults are only for deserialization
        let params = PaginationParams::default();
        assert_eq!(params.page, 0);
        assert_eq!(params.per_page, 0);
        assert!(params.sort_dir.is_empty());

        // Test that per_page() clamps to minimum of 1
        assert_eq!(params.per_page(), 1);
    }

    #[test]
    fn test_pagination_offset() {
        let params = PaginationParams {
            page: 3,
            per_page: 10,
            ..Default::default()
        };
        assert_eq!(params.offset(), 20);

        let first_page = PaginationParams {
            page: 1,
            per_page: 25,
            ..Default::default()
        };
        assert_eq!(first_page.offset(), 0);
    }

    #[test]
    fn test_pagination_per_page_clamping() {
        let over_max = PaginationParams {
            per_page: 500,
            ..Default::default()
        };
        assert_eq!(over_max.per_page(), PaginationParams::MAX_PER_PAGE);

        let zero = PaginationParams {
            per_page: 0,
            ..Default::default()
        };
        assert_eq!(zero.per_page(), 1);
    }

    /// A `per_page` above the cap is a 422 that names the requested value and
    /// the cap, so a client cannot mistake a truncated page for a whole one.
    /// The clamp on the getter stays for callers that reach it directly, but
    /// every handler that goes through `order_by` / `order_by_mapped` /
    /// `reject_unsupported_sort` gets the rejection instead.
    #[test]
    fn per_page_above_the_cap_is_a_422() {
        let over_cap = PaginationParams {
            per_page: 500,
            ..Default::default()
        };
        let err = over_cap
            .reject_over_cap_per_page()
            .expect_err("500 is above the 100-row cap");
        assert_eq!(err.status_code(), 422);
        let message = match &err {
            AppError::Validation { errors, .. } => errors
                .iter()
                .find(|e| e.field == "per_page")
                .expect("the rejection names the `per_page` field")
                .message
                .clone(),
            other => panic!("expected validation, got {other:?}"),
        };
        assert!(
            message.contains("500") && message.contains("100"),
            "the 422 names what was asked for and the cap, got {message}"
        );

        let at_cap = PaginationParams {
            per_page: PaginationParams::MAX_PER_PAGE,
            ..Default::default()
        };
        at_cap.reject_over_cap_per_page().expect("100 is the cap");

        let under_cap = PaginationParams {
            per_page: 25,
            ..Default::default()
        };
        under_cap.reject_over_cap_per_page().expect("25 is under");

        let below_min = PaginationParams {
            per_page: 0,
            ..Default::default()
        };
        below_min
            .reject_over_cap_per_page()
            .expect("zero clamps on the getter, does not reject");
    }

    /// The three sort helpers piggyback on the cap check, so any of the ~69
    /// list handlers already threading `order_by` gets the 422 for free.
    #[test]
    fn order_by_rejects_a_per_page_above_the_cap() {
        let over_cap = PaginationParams {
            per_page: 500,
            sort: Some("name".to_string()),
            sort_dir: "asc".to_string(),
            ..Default::default()
        };
        let err = over_cap
            .order_by("name", &["name"])
            .expect_err("order_by must reject an over-cap per_page");
        assert_eq!(err.status_code(), 422);

        let err = over_cap
            .order_by_mapped("t.name", &[("name", "t.name")])
            .expect_err("order_by_mapped must reject an over-cap per_page");
        assert_eq!(err.status_code(), 422);

        let err = over_cap
            .reject_unsupported_sort()
            .expect_err("reject_unsupported_sort must reject an over-cap per_page");
        assert_eq!(err.status_code(), 422);
    }

    #[test]
    fn an_unknown_sort_dir_is_rejected() {
        let p = PaginationParams {
            sort_dir: "sideways".to_string(),
            ..Default::default()
        };
        assert!(p.order_by("id", &["id"]).is_err());
    }

    #[test]
    fn test_is_ascending() {
        let asc = PaginationParams {
            sort_dir: "asc".to_string(),
            ..Default::default()
        };
        assert!(asc.is_ascending());

        let desc = PaginationParams {
            sort_dir: "desc".to_string(),
            ..Default::default()
        };
        assert!(!desc.is_ascending());

        let asc_upper = PaginationParams {
            sort_dir: "ASC".to_string(),
            ..Default::default()
        };
        assert!(asc_upper.is_ascending());
    }

    #[test]
    fn test_order_by() {
        let params = PaginationParams {
            sort: Some("name".to_string()),
            sort_dir: "asc".to_string(),
            ..Default::default()
        };
        let allowed = &["name", "created_at", "updated_at"];
        assert_eq!(params.order_by("created_at", allowed).unwrap(), "name ASC");

        // MAPPS-533: this asserted `"created_at DESC"` - the silent fallback.
        // An unknown field is now the caller's error, which is the whole change.
        let invalid_sort = PaginationParams {
            sort: Some("invalid_field".to_string()),
            ..Default::default()
        };
        assert!(invalid_sort.order_by("created_at", allowed).is_err());
    }

    #[test]
    fn test_paginated_response() {
        let data = vec![1, 2, 3, 4, 5];
        let response = PaginatedResponse::new(data, 1, 5, 20);

        assert_eq!(response.data.len(), 5);
        assert_eq!(response.meta.page, 1);
        assert_eq!(response.meta.per_page, 5);
        assert_eq!(response.meta.total, 20);
        assert_eq!(response.meta.total_pages, 4);
        assert!(response.meta.has_next);
        assert!(!response.meta.has_prev);
    }

    #[test]
    fn test_paginated_response_last_page() {
        let data = vec![1, 2];
        let response = PaginatedResponse::new(data, 4, 5, 17);

        assert_eq!(response.meta.page, 4);
        assert_eq!(response.meta.total_pages, 4);
        assert!(!response.meta.has_next);
        assert!(response.meta.has_prev);
    }

    #[test]
    fn test_paginated_response_clamps_zero_per_page() {
        // per_page == 0 must not yield a degenerate total_pages from a
        // divide-by-zero; it is clamped to 1 so every item is one page.
        let response = PaginatedResponse::new(vec![1, 2, 3], 1, 0, 3);
        assert_eq!(response.meta.per_page, 1);
        assert_eq!(response.meta.total_pages, 3);

        // total == 0 with per_page == 0 previously produced NaN -> 0,
        // which is fine, but the clamp keeps the path well defined.
        let empty: PaginatedResponse<i32> = PaginatedResponse::new(vec![], 1, 0, 0);
        assert_eq!(empty.meta.per_page, 1);
        assert_eq!(empty.meta.total_pages, 0);
    }

    #[test]
    fn test_paginated_response_map() {
        let data = vec![1, 2, 3];
        let response = PaginatedResponse::new(data, 1, 10, 3);
        let mapped = response.map(|x| x * 2);

        assert_eq!(mapped.data, vec![2, 4, 6]);
        assert_eq!(mapped.meta.total, 3);
    }
}

/// PMS-1194: every handler that extracts `Query<PaginationParams>` either
/// honours `sort` through an allow-list or refuses it, never both accepting
/// and silently ignoring it. This scans the actual route source rather than
/// trusting a comment, the `finance_gate` / `repo_hygiene` shape this
/// codebase already uses for a rule that has to stay true as new handlers
/// are added.
#[cfg(test)]
mod pms1194_sort_guard {
    /// `(module, source)` for every `routes.rs` that extracts
    /// `Query<PaginationParams>`. Adding a tenth module means adding its
    /// file here too, or this scan silently stops covering it.
    const ROUTE_FILES: &[(&str, &str)] = &[
        ("assets", include_str!("../modules/assets/routes.rs")),
        ("audit", include_str!("../modules/audit/routes.rs")),
        ("auth", include_str!("../modules/auth/routes.rs")),
        ("billing", include_str!("../modules/billing/routes.rs")),
        ("calendar", include_str!("../modules/calendar/routes.rs")),
        ("contacts", include_str!("../modules/contacts/routes.rs")),
        ("contracts", include_str!("../modules/contracts/routes.rs")),
        (
            "invitations",
            include_str!("../modules/invitations/routes.rs"),
        ),
        (
            "knowledge_base",
            include_str!("../modules/knowledge_base/routes.rs"),
        ),
        (
            "mileage_tracking",
            include_str!("../modules/mileage_tracking/routes.rs"),
        ),
        (
            "notifications",
            include_str!("../modules/notifications/routes.rs"),
        ),
        ("projects", include_str!("../modules/projects/routes.rs")),
        ("quotes", include_str!("../modules/quotes/routes.rs")),
        ("rmm", include_str!("../modules/rmm/routes.rs")),
        ("settings", include_str!("../modules/settings/routes.rs")),
        ("sla", include_str!("../modules/sla/routes.rs")),
        ("tenants", include_str!("../modules/tenants/routes.rs")),
        ("tickets", include_str!("../modules/tickets/routes.rs")),
        (
            "time_tracking",
            include_str!("../modules/time_tracking/routes.rs"),
        ),
    ];

    /// Handlers whose service call is already wired to a `sort`
    /// allow-list via `order_by` / `order_by_mapped`, named
    /// `module::handler_fn`. Verified by reading the matching
    /// `service.rs` at the time this list was written; a handler that
    /// stops calling one of those two functions has to drop out of this
    /// list and start calling `reject_unsupported_sort` instead, or this
    /// test fails.
    const HONOURED: &[&str] = &[
        "auth::list_users",
        "billing::list_invoices",
        "billing::list_payments",
        "contacts::list_companies",
        "contacts::list_contacts",
        "mileage_tracking::list_mileage_entries",
        "projects::list_projects",
        "quotes::list_quotes",
        "tenants::list_tenants",
        "tickets::list_tickets",
        "time_tracking::list_time_entries",
    ];

    #[test]
    fn every_pagination_handler_honours_or_rejects_sort() {
        let mut seen = 0usize;
        let mut bad: Vec<String> = Vec::new();

        for (module, src) in ROUTE_FILES {
            for chunk in src.split("async fn ").skip(1) {
                if !chunk.contains("Query<PaginationParams>") {
                    continue;
                }
                let Some((name, rest)) = chunk.split_once('(') else {
                    continue;
                };
                let Some((_args, body)) = rest.split_once(") ->") else {
                    continue;
                };

                seen += 1;
                let key = format!("{module}::{name}");
                let honoured = HONOURED.contains(&key.as_str());
                let rejects = body.contains("reject_unsupported_sort");
                if !honoured && !rejects {
                    bad.push(key);
                }
            }
        }

        assert!(
            seen >= 70,
            "the scan found only {seen} handlers extracting \
             `Query<PaginationParams>`, so it has stopped matching this \
             codebase's shape and is no longer proving anything"
        );
        assert!(
            bad.is_empty(),
            "these handlers extract `Query<PaginationParams>` but neither \
             honour `sort` through an allow-list nor reject it: {bad:?}. \
             Either wire the service call to `order_by` / `order_by_mapped` \
             and add the handler to HONOURED, or call \
             `pagination.reject_unsupported_sort()?` before using \
             `pagination`."
        );
    }
}
