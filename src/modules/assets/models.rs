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
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertAssetTypeRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    pub icon: Option<String>,
    pub parent_type_id: Option<Uuid>,
    #[serde(default = "default_true")]
    pub is_active: bool,
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
}

fn default_active() -> String {
    "active".into()
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpdateAssetRequest {
    pub asset_tag: Option<String>,
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
