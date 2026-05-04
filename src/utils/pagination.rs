//! Pagination utilities for API responses

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
        self.per_page.min(Self::MAX_PER_PAGE).max(1)
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
    pub fn order_by(&self, default_field: &str, allowed_fields: &[&str]) -> String {
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

/// Filter parameters that can be combined with pagination
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FilterParams {
    /// Search query
    pub q: Option<String>,
    /// Filter by status
    pub status: Option<String>,
    /// Filter by company ID
    pub company_id: Option<uuid::Uuid>,
    /// Filter by assigned user ID
    pub assigned_to: Option<uuid::Uuid>,
    /// Filter by date range start
    pub from_date: Option<chrono::NaiveDate>,
    /// Filter by date range end
    pub to_date: Option<chrono::NaiveDate>,
    /// Filter by tags (comma-separated)
    pub tags: Option<String>,
}

impl FilterParams {
    /// Get tags as a vector
    pub fn tags_vec(&self) -> Vec<String> {
        self.tags
            .as_ref()
            .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default()
    }

    /// Check if any filter is active
    pub fn has_filters(&self) -> bool {
        self.q.is_some()
            || self.status.is_some()
            || self.company_id.is_some()
            || self.assigned_to.is_some()
            || self.from_date.is_some()
            || self.to_date.is_some()
            || self.tags.is_some()
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
    fn test_paginated_response_map() {
        let data = vec![1, 2, 3];
        let response = PaginatedResponse::new(data, 1, 10, 3);
        let mapped = response.map(|x| x * 2);

        assert_eq!(mapped.data, vec![2, 4, 6]);
        assert_eq!(mapped.meta.total, 3);
    }

    #[test]
    fn test_filter_params_tags() {
        let params = FilterParams {
            tags: Some("tag1, tag2, tag3".to_string()),
            ..Default::default()
        };
        assert_eq!(params.tags_vec(), vec!["tag1", "tag2", "tag3"]);

        let empty = FilterParams::default();
        assert!(empty.tags_vec().is_empty());
    }

    #[test]
    fn test_filter_params_has_filters() {
        let empty = FilterParams::default();
        assert!(!empty.has_filters());

        let with_query = FilterParams {
            q: Some("search".to_string()),
            ..Default::default()
        };
        assert!(with_query.has_filters());

        let with_status = FilterParams {
            status: Some("active".to_string()),
            ..Default::default()
        };
        assert!(with_status.has_filters());
    }
}
