//! Settings module: tenant settings + per-module config.

pub mod email;
pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::settings_routes;
pub use service::{
    read_ci_impact_max_depth, read_default_due_business_days, read_email_intake_default_company,
    read_max_minutes_per_day, read_workflow_rule_max_depth, SettingsService,
};
