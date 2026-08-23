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

impl PaginationParams {
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
    /// Same silent fallback as its sibling, deliberately: an unknown key sorts
    /// by the default rather than erroring. See the note on `order_by`.
    pub fn order_by_mapped(&self, default_sql: &str, allowed: &[(&str, &str)]) -> String {
        let sql = self
            .sort
            .as_ref()
            .and_then(|k| {
                allowed
                    .iter()
                    .find(|(key, _)| key == k)
                    .map(|(_, expr)| *expr)
            })
            .unwrap_or(default_sql);

        let direction = if self.is_ascending() { "ASC" } else { "DESC" };

        format!("{} {}", sql, direction)
    }

    /// NOTE (PMS-894): an unrecognised `sort` is dropped and the default is
    /// used, so a client that asks for a column this list does not allow gets
    /// a differently-ordered page and a 200. That is deliberate - the value is
    /// spliced into SQL, so anything not on the list must not reach it - but it
    /// does turn a client bug into a wrong answer rather than an error.
    /// Rejecting with a 400 was considered and left alone: every caller would
    /// have to be audited first, and a page that sorts by the wrong column is a
    /// smaller harm than a list that stops rendering.
    pub fn order_by(&self, default_field: &str, allowed_fields: &[&str]) -> String {
        let default_field = default_field
            .split_whitespace()
            .next()
            .unwrap_or(default_field);
        let field = self
            .sort
            .as_ref()
            .filter(|f| allowed_fields.contains(&f.as_str()))
            .map(|s| s.as_str())
            .unwrap_or(default_field);

        let direction = if self.is_ascending() { "ASC" } else { "DESC" };

        format!("{} {}", field, direction)
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
            params(Some("company_name"), "asc").order_by_mapped("t.created_at", TICKET_SORTS),
            "co.name ASC"
        );
        assert_eq!(
            params(Some("priority"), "desc").order_by_mapped("t.created_at", TICKET_SORTS),
            "tp.sort_order DESC"
        );
    }

    /// An unknown key falls back rather than reaching the query. This is the
    /// behaviour the note on `order_by` describes: it keeps arbitrary text out
    /// of the SQL, and it means a client asking for a column that is not on the
    /// list gets a differently-ordered page and a 200.
    #[test]
    fn an_unknown_key_falls_back_to_the_default() {
        assert_eq!(
            params(Some("co.name"), "asc").order_by_mapped("t.created_at", TICKET_SORTS),
            "t.created_at ASC",
            "the SQL expression is not itself an accepted key"
        );
        assert_eq!(
            params(Some("; DROP TABLE tickets"), "asc")
                .order_by_mapped("t.created_at", TICKET_SORTS),
            "t.created_at ASC"
        );
        assert_eq!(
            params(None, "desc").order_by_mapped("t.created_at", TICKET_SORTS),
            "t.created_at DESC"
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
        assert_eq!(params.order_by("created_at", allowed), "name ASC");

        let invalid_sort = PaginationParams {
            sort: Some("invalid_field".to_string()),
            ..Default::default()
        };
        assert_eq!(
            invalid_sort.order_by("created_at", allowed),
            "created_at DESC"
        );
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
