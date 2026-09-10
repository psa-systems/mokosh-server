//! Provider status collection and reporting (PMS-989).
//!
//! Mokosh selects a provider per capability (configuration, tenant secrets,
//! app-tier secrets, storage, authentication, email) and until now nothing
//! answered "which providers is this process actually using". `/ready` says
//! "database up, Infisical probe up" without establishing that any secret
//! is READ from Infisical, which is the exact shape of the Bunyip incident
//! `docs/providers.md` exists to prevent.
//!
//! This module ships ONE collector that gathers the running process's
//! provider state across every kind and renders it two ways: a JSON envelope
//! for BUNYIP-634 to aggregate, and an HTML admin page for standalone
//! deployments with no Bunyip. Same collector, two renderings, so the two
//! cannot disagree.

pub mod status;
