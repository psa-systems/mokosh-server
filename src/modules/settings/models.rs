//! Settings DTOs.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize)]
pub struct TenantSettingResponse {
    pub id: Uuid,
    pub category: String,
    pub key: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertTenantSettingRequest {
    #[validate(length(min = 1, max = 50))]
    pub category: String,
    #[validate(length(min = 1, max = 100))]
    pub key: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleConfigResponse {
    pub id: Uuid,
    pub module_name: String,
    pub is_enabled: bool,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct UpsertModuleConfigRequest {
    pub is_enabled: bool,
    #[serde(default)]
    pub config: serde_json::Value,
}
