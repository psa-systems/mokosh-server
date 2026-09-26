//! PMS-1310: installed integrations, and what each one is allowed to do.
//!
//! Before this there was no integrations concept: a payment connection, a
//! contact connection and an RMM connection each got their own table with their
//! own `provider` column, `is_active` flag and sync interval. That shape answers
//! "is Stripe connected" and cannot answer the question an integrations page
//! exists for, which is who does the invoicing. Connecting Stripe says nothing
//! about whether Stripe, Mokosh or Xero issues the document, so an integration
//! DECLARES its capabilities ([`registry`]) and a tenant says which of them it
//! is handing over (`integrations.enabled_capabilities`).
//!
//! Three things are worth knowing before changing anything here.
//!
//! **The supported set is code, the enabled set is data.** What a provider can
//! do is a property of its implementation in this build, so it lives in
//! [`registry::REGISTRY`] and not in a column; a column could hold a capability
//! the code cannot serve and nothing would fail until a tenant relied on it.
//! [`service::IntegrationsService`] is the only writer and enforces the subset.
//!
//! **One home per connection.** `payment_gateway_configs` (Stripe, PayPal) and
//! `contact_sync_connections` (Google) already record whether those providers
//! are connected for a tenant. This subsystem must not answer that too while
//! they do, so each registry entry names the subsystem that owns its connection
//! and the service refuses `connect`, `disconnect` and a capability change for a
//! provider whose home is elsewhere, naming where it is configured and the issue
//! that moves it. No row is written for such a provider at all, so the two
//! tables cannot disagree in the meantime. PMS-1312 (Stripe) and PMS-1315
//! (contacts) each flip one entry and backfill its rows in the same change.
//!
//! **Credentials are not here.** They go through [`crate::secrets`] under
//! `SecretKind::Integration`, so an operator decides whether they live in
//! Postgres or in Infisical. `integrations.config` is for non-secret settings,
//! and a credential in it is a defect: that separation is the reason PMS-1310
//! waited for the secrets provider (PMS-1311) to land first.
//!
//! The admin page itself is the mokosh-apps half and is its own issue. What this
//! module serves is everything that page needs: the catalog with a description
//! and a supported set per provider, the tenant's enabled set, the poll setting
//! where one applies, and connect / disconnect.

pub mod models;
pub mod registry;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::integration_routes;
pub use service::IntegrationsService;
