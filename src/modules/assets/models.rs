//! Assets DTOs.

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct AssetTypeResponse {
    pub id: Uuid,
    pub name: String,
    pub icon: Option<String>,
    pub parent_type_id: Option<Uuid>,
    pub is_active: bool,
    /// PMS-456: ITIL CI class tag (hardware / software / service /
    /// network / document / location, or a tenant-coined value).
    /// Opt-in; types created before this column shipped surface as
    /// `None` and the SPA renders them as "Unclassified".
    pub itil_category: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertAssetTypeRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub icon: Option<String>,
    pub parent_type_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub is_active: bool,
    // PMS-456: optional ITIL CI classification. Free-text VARCHAR(50)
    // so a tenant can coin a new category without a schema migration;
    // the SPA offers the standard ITIL classes as suggestions.
    #[validate(length(max = 50))]
    #[serde(default)]
    pub itil_category: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetResponse {
    pub id: Uuid,
    pub asset_tag: Option<String>,
    pub name: String,
    pub asset_type_id: Uuid,
    pub company_id: Uuid,
    /// PMS-336: owning company display name, resolved via LEFT JOIN on
    /// companies (mirrors how TicketResponse surfaces company_name). The
    /// Assets list Company column and asset detail render this. Option
    /// because the JOIN is left; in practice an asset always has a
    /// company_id so it is populated for every row.
    pub company_name: Option<String>,
    pub site_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub status: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub purchase_date: Option<NaiveDate>,
    pub purchase_price: Option<Decimal>,
    pub warranty_expiry: Option<NaiveDate>,
    pub end_of_life: Option<NaiveDate>,
    // PMS-454: CMDB expansion fields.
    pub assigned_user_id: Option<Uuid>,
    /// Resolved display name for `assigned_user_id` (first_name + last_name),
    /// surfaced so the SPA renders "Issued to Alice Smith" without an extra
    /// `/auth/users` lookup. `None` when the asset is unassigned, the user
    /// was deleted, or the assigned user has not yet completed onboarding.
    pub assigned_user_name: Option<String>,
    /// Primary IP rendered as a string ("10.1.2.3" / "fe80::1") so the
    /// SPA does not have to special-case INET. Stored as INET on the
    /// server side so a malformed value is rejected at write time.
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub installed_date: Option<NaiveDate>,
    pub department: Option<String>,
    pub in_transit_ticket_id: Option<Uuid>,
    /// PMS-456: per-CI lifecycle position (planned / in_service /
    /// retired, or a tenant-coined value). `None` for assets created
    /// before the column shipped; the SPA renders `None` as "Unknown".
    pub itil_lifecycle_stage: Option<String>,
    // PMS-454: licence section (QA-expanded scope). `None` for assets
    // that carry no licence (the common case for hardware).
    pub license_vendor: Option<String>,
    pub license_seat_count: Option<i32>,
    pub license_expiry: Option<NaiveDate>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// PMS-1061: what a contact receives for an asset, on the dual-plane
/// reads. The purchase price, the network identity (`ip_address`,
/// `hostname`, `mac_address`), the assignee, the licence terms, the RMM
/// lifecycle and the transit ticket are the MSP's operating data; what
/// the customer verifies is the device (tag, name, type, make, model,
/// serial) and its dates. The shape the retired portal router served
/// (`PortalAsset`), which PMS-1025's sweep replaced with the staff type.
/// Every key is always present (`null` when unset) so the shape is stable.
#[derive(Debug, Clone, Serialize)]
pub struct ContactAssetResponse {
    pub id: Uuid,
    /// The caller's own company: what the session already says, never a
    /// foreign one, since the scope check runs before the projection.
    pub company_id: Uuid,
    pub asset_tag: Option<String>,
    pub name: String,
    pub asset_type_id: Uuid,
    pub status: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub warranty_expiry: Option<NaiveDate>,
    pub end_of_life: Option<NaiveDate>,
}

impl From<AssetResponse> for ContactAssetResponse {
    fn from(a: AssetResponse) -> Self {
        Self {
            id: a.id,
            company_id: a.company_id,
            asset_tag: a.asset_tag,
            name: a.name,
            asset_type_id: a.asset_type_id,
            status: a.status,
            manufacturer: a.manufacturer,
            model: a.model,
            serial_number: a.serial_number,
            warranty_expiry: a.warranty_expiry,
            end_of_life: a.end_of_life,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, validator::Validate)]
pub struct AssetFilter {
    pub company_id: Option<Uuid>,
    pub asset_type_id: Option<Uuid>,
    #[validate(length(max = 100))]
    pub status: Option<String>,
    /// PMS-344 follow-up: free-text search on the asset name, used by
    /// the AssetPicker on the ticket form / inline editor. ILIKE-matched
    /// in the service, mirroring CompanyFilter.q.
    #[validate(length(max = 200))]
    pub q: Option<String>,
}

// -- PMS-1486 (asset search v2) ---------------------------------------------
//
// The structured-filter body `POST /api/v1/assets/search` accepts. The
// `AssetField` + `FacetOp` enums are the ONLY vocab the server honours; a
// pill the SPA composes against anything else is a 422 at the validate
// boundary rather than an empty list. `q` lowers to one ILIKE scan against
// the `search_haystack` column migration 267 adds. See
// docs/mokosh-assets/02-search-redesign.md for the design.

/// A single filter pill. One field, one operator, one or more values.
#[derive(Debug, Clone, Deserialize)]
pub struct FacetFilter {
    pub field: AssetField,
    pub op: FacetOp,
    /// Zero or more values, interpreted per `op`:
    /// - `Eq` / `In` / `NotIn`: one or more scalars; `In` and `NotIn`
    ///   compile to `IN (...)` / `NOT IN (...)`.
    /// - `IsNull` / `IsNotNull`: must be empty; a non-empty values list
    ///   is a 422 at the handler.
    /// - `Before` / `After`: exactly one scalar, parsed as a date (or
    ///   a timestamp lowered to a date).
    /// - `Within`: exactly one object `{"days": N}`; lowered to
    ///   `field BETWEEN NOW()::date AND (NOW()::date + N)`.
    /// - `ContainsTag`: exactly one string; valid only for `AssetField::Tags`.
    #[serde(default)]
    pub values: Vec<serde_json::Value>,
}

/// Every field the server knows how to filter by. Snake-case over the
/// wire so the SPA sends `assigned_user` rather than `AssignedUser`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetField {
    AssetType,
    Status,
    Company,
    Site,
    AssignedUser,
    Department,
    ItilLifecycleStage,
    WarrantyExpiry,
    EndOfLife,
    PurchaseDate,
    InstalledDate,
    Tags,
    Manufacturer,
    Model,
    LicenseVendor,
}

/// The operator vocab. The handler and the service enforce every (field, op)
/// pair that is legal; a pair that is not is a 422 at the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacetOp {
    Eq,
    In,
    NotIn,
    IsNull,
    IsNotNull,
    Before,
    After,
    /// `{"days": N}` convenience for "the next N days from today".
    Within,
    /// `AssetField::Tags` only.
    ContainsTag,
}

/// One sort clause. The default sort when `sort` is empty is `name ASC`,
/// which matches today's list.
#[derive(Debug, Clone, Deserialize)]
pub struct SortClause {
    pub field: AssetField,
    #[serde(default)]
    pub direction: SortDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}

/// The POST body for `/api/v1/assets/search`.
#[derive(Debug, Clone, Deserialize, Default, Validate)]
pub struct AssetSearchRequest {
    /// Trimmed, lowercased, ILIKE'd with surrounding wildcards against
    /// the `search_haystack` column. Empty / absent => no haystack
    /// filter. pg_trgm needs 3+ chars to reach the GIN, so a shorter
    /// string falls back to a sequential scan the service accepts; the
    /// facet filters alone keep the plan bounded in practice.
    #[validate(length(max = 200))]
    pub q: Option<String>,
    /// Facet filters, AND-combined. Validated per (field, op) pair.
    #[serde(default)]
    pub filters: Vec<FacetFilter>,
    /// Overrides the default `name ASC`.
    #[serde(default)]
    pub sort: Vec<SortClause>,
}

/// One row of the `/api/v1/assets/search/facets` response. The SPA's
/// sidebar renders a row per value with its count under the currently-
/// applied filter set.
#[derive(Debug, Clone, Serialize)]
pub struct FacetValueCount {
    /// JSON scalar (string / uuid / i64). `null` for `IsNull` buckets.
    pub value: serde_json::Value,
    /// Human label; same string as `value` for a text facet, the
    /// resolved tenant/company/user name for a Uuid facet.
    pub label: Option<String>,
    pub count: i64,
}

/// The facets endpoint's response. One key per facet the SPA renders in
/// its sidebar. Keys the current filter has already pinned (e.g. a
/// `status` pill is applied) return the top values AMONG THE REMAINING
/// rows so the sidebar leads with "next pill worth adding".
#[derive(Debug, Clone, Serialize, Default)]
pub struct AssetFacetsResponse {
    pub status: Vec<FacetValueCount>,
    pub company: Vec<FacetValueCount>,
    pub asset_type: Vec<FacetValueCount>,
    pub assigned_user: Vec<FacetValueCount>,
    pub department: Vec<FacetValueCount>,
    pub manufacturer: Vec<FacetValueCount>,
    pub itil_lifecycle_stage: Vec<FacetValueCount>,
    /// Canned saved-view counts; one entry each when non-zero.
    pub warranty_expiring_in_30_days: i64,
    pub end_of_life_passed: i64,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateAssetRequest {
    pub asset_tag: Option<String>,
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub asset_type_id: Uuid,
    pub company_id: Uuid,
    pub site_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    #[serde(default = "default_active")]
    pub status: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub purchase_date: Option<NaiveDate>,
    pub purchase_price: Option<Decimal>,
    pub warranty_expiry: Option<NaiveDate>,
    pub end_of_life: Option<NaiveDate>,
    // PMS-454: CMDB expansion fields. Each is optional so the create
    // path does not break for existing callers; the server applies its
    // column defaults when omitted.
    pub assigned_user_id: Option<Uuid>,
    #[validate(length(max = 45))]
    pub ip_address: Option<String>,
    #[validate(length(max = 255))]
    pub hostname: Option<String>,
    #[validate(length(max = 50))]
    pub mac_address: Option<String>,
    pub installed_date: Option<NaiveDate>,
    #[validate(length(max = 100))]
    pub department: Option<String>,
    pub in_transit_ticket_id: Option<Uuid>,
    // PMS-456: optional ITIL CI lifecycle stage. Free-text VARCHAR(50)
    // so a tenant can coin a stage without a migration. The SPA
    // suggests planned / in_service / retired.
    #[validate(length(max = 50))]
    #[serde(default)]
    pub itil_lifecycle_stage: Option<String>,
    // PMS-454: licence section (QA-expanded scope). Each optional so the
    // create path stays unchanged for callers that omit it.
    #[validate(length(max = 150))]
    pub license_vendor: Option<String>,
    #[validate(range(min = 0))]
    pub license_seat_count: Option<i32>,
    pub license_expiry: Option<NaiveDate>,
}

fn default_active() -> String {
    "active".into()
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateAssetRequest {
    pub asset_tag: Option<String>,
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    pub asset_type_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub status: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub purchase_date: Option<NaiveDate>,
    pub purchase_price: Option<Decimal>,
    pub warranty_expiry: Option<NaiveDate>,
    pub end_of_life: Option<NaiveDate>,
    // PMS-454: CMDB expansion fields. Each optional so a partial PUT
    // only touches the fields the SPA actually sends.
    pub assigned_user_id: Option<Uuid>,
    #[validate(length(max = 45))]
    pub ip_address: Option<String>,
    #[validate(length(max = 255))]
    pub hostname: Option<String>,
    #[validate(length(max = 50))]
    pub mac_address: Option<String>,
    pub installed_date: Option<NaiveDate>,
    #[validate(length(max = 100))]
    pub department: Option<String>,
    pub in_transit_ticket_id: Option<Uuid>,
    // PMS-456: optional ITIL CI lifecycle stage. None leaves the
    // column untouched (matches the rest of the partial-update
    // pattern on this DTO).
    #[validate(length(max = 50))]
    #[serde(default)]
    pub itil_lifecycle_stage: Option<String>,
    // PMS-454: licence section (QA-expanded scope). None leaves each
    // column untouched on a partial PUT.
    #[validate(length(max = 150))]
    pub license_vendor: Option<String>,
    #[validate(range(min = 0))]
    pub license_seat_count: Option<i32>,
    pub license_expiry: Option<NaiveDate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetRelationshipResponse {
    pub id: Uuid,
    pub parent_asset_id: Uuid,
    pub child_asset_id: Uuid,
    pub relationship_type: String,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateAssetRelationshipRequest {
    pub child_asset_id: Uuid,
    /// "contains" | "connected_to" | "depends_on" | "hosts"
    pub relationship_type: String,
}

/// PMS-475: one node in the CI impact-graph response. The route
/// flattens upstream + downstream edges into the same shape so the
/// SPA renders them with a uniform card without branching on
/// direction. `parent_asset_id` is the "upstream side" of the edge
/// (the asset the child depends on / is hosted by / is connected
/// to), and `asset_id` is the resolved-from side - which one is the
/// root asset varies with `direction`.
#[derive(Debug, Clone, Serialize)]
pub struct AssetImpactNode {
    pub asset_id: Uuid,
    pub name: String,
    pub parent_asset_id: Uuid,
    pub child_asset_id: Uuid,
    pub relationship_type: String,
    /// "upstream" | "downstream". `both` direction returns nodes
    /// from each half stamped with their own discriminator.
    pub direction: String,
    /// 1 = direct neighbour of the root, growing by one per hop.
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetImpactResponse {
    /// The asset that the traversal anchored on.
    pub root_asset_id: Uuid,
    /// Effective depth applied to the walk after clamping the
    /// caller's `depth` query param against the per-tenant
    /// `ci/impact_max_depth` setting and the hard server ceiling
    /// (10). Surfaced so the SPA can render "truncated at depth N".
    pub depth: u32,
    pub direction: String,
    pub nodes: Vec<AssetImpactNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigurationItemResponse {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub name: String,
    pub category: Option<String>,
    pub value: String, // decrypted
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// List view of a configuration item. Deliberately omits the secret
/// `value` so the encrypted payload is never leaked in a list; fetch the
/// single-item reveal endpoint (audited) to decrypt it.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigurationItemSummary {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub name: String,
    pub category: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertConfigurationItemRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub category: Option<String>,
    pub value: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialResponse {
    pub id: Uuid,
    pub name: String,
    pub company_id: Option<Uuid>,
    pub asset_id: Option<Uuid>,
    pub credential_type: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub last_rotated: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// List view of a vault credential. Deliberately omits `username`,
/// `password`, and `notes` (all encrypted at rest) so secrets are never
/// leaked in a list; fetch the single-credential reveal endpoint
/// (audited) to decrypt them.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialSummary {
    pub id: Uuid,
    pub name: String,
    pub company_id: Option<Uuid>,
    pub asset_id: Option<Uuid>,
    pub credential_type: String,
    pub url: Option<String>,
    pub last_rotated: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateCredentialRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub credential_type: String,
    pub username: String,
    pub password: String,
    // PMS-351: a stored credential's login URL is free-text the user types,
    // so validate it like the RMM `api_url` field. `url` (any scheme) rather
    // than the company-website http(s)-only rule, because a saved credential
    // may legitimately target rdp://, ssh://, etc. Empty/None stays accepted.
    #[validate(url)]
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetAuditLogResponse {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub action: String,
    pub changes: Option<serde_json::Value>,
    pub performed_by_id: Option<Uuid>,
    /// Resolved actor display name, joined server-side so the client never
    /// has to look `performed_by_id` up against its own roster (PMS-1478).
    /// `"<first> <last>"`, falling back to the user's email when the
    /// profile name is still empty (a JIT-provisioned user), and `None`
    /// only when `performed_by_id` is `NULL` or the user row is gone.
    pub performed_by_name: Option<String>,
    pub performed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential_req(url: serde_json::Value) -> CreateCredentialRequest {
        serde_json::from_value(serde_json::json!({
            "name": "domain-admin",
            "credential_type": "domain",
            "username": "administrator",
            "password": "sup3r-s3cret-pw",
            "url": url,
        }))
        .expect("request deserializes")
    }

    // PMS-351: a stored credential's login URL must reject the same junk the
    // company website field does, while still accepting any real scheme.
    #[test]
    fn credential_url_validated() {
        assert!(credential_req(serde_json::json!(null)).validate().is_ok());
        assert!(
            credential_req(serde_json::json!("https://vault.example.com"))
                .validate()
                .is_ok()
        );
        assert!(credential_req(serde_json::json!("rdp://10.0.0.5"))
            .validate()
            .is_ok());
        for bad in ["not-a-valid-url", "example.com"] {
            assert!(
                credential_req(serde_json::json!(bad)).validate().is_err(),
                "{bad} should be rejected"
            );
        }
    }
}
