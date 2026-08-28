//! Mokosh Server Modules
//!
//! This module contains all the business logic modules for Mokosh Server.
//! Each module is designed to be a discrete unit with its own API.

pub mod approvals;
pub mod assets;
pub mod audit;
pub mod auth;
pub mod billing;
/// MAPPS-617 (mokosh-branding prompt 001): shared branding helpers.
/// Owns the tenant + Company brand merge (`effective::effective_branding`).
/// Prompt 002 extends this with the parameterized asset store + Company-
/// scoped multipart handlers; prompts 003/004 are client-side.
pub mod branding;
pub mod calendar;
pub mod contact_portal;
pub mod contacts;
pub mod contracts;
pub mod dashboards;
pub mod data_transfer;
pub mod email_intake;
pub mod forms;
pub mod invitations;
pub mod ip_enrich;
pub mod knowledge_base;
pub mod mileage_tracking;
pub mod notifications;
pub mod platform;
pub mod portal_roles;
pub mod projects;
pub mod quotes;
pub mod reports;
pub mod rmm;
pub mod saved_reports;
pub mod search;
pub mod seed;
pub mod settings;
pub mod sla;
pub mod teams;
pub mod tenants;
pub mod ticket_templates;
pub mod tickets;
pub mod time_tracking;
pub mod workflows;
