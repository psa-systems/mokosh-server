//! Settings module: tenant settings + per-module config.

// PMS-789: the deployment-wide product name, a system setting on the default
// tenant like the email config next door.
pub mod app_name;
pub mod email;
pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::settings_routes;
pub use service::read_tenant_zone;
pub use service::{
    read_ci_impact_max_depth, read_default_currency, read_default_due_business_days,
    read_email_intake_default_company, read_max_minutes_per_day, read_track_breaks,
    read_workflow_rule_max_depth, SettingsService,
};
