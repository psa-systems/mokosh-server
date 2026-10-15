//! Asset catalog (PMS-1492): the device-catalog + bulk-order half of
//! the asset-tracking redesign (phase 3; design doc at
//! `docs/mokosh-assets/04-templates-and-bulk-order.md`).
//!
//! Three concepts share this module:
//!
//! - `asset_models`: known device models (Dell Latitude 5450,
//!   Workstation). Deduplicated per tenant on
//!   `(manufacturer, model, asset_type_id)` so the typeahead has one
//!   canonical row per shape.
//! - `asset_templates`: a frozen (model + per-order context) shape
//!   the operator saves for repeat orders. Lands in MR2.
//! - signature detector: a materialised view that surfaces hot
//!   patterns ("you have 7 identical Latitudes this week"). Lands
//!   in MR3.
//!
//! `POST /assets/bulk-create` is the fan-out verb that writes N asset
//! rows from one request body; it lives in the `assets` module next to
//! the single-asset `POST /assets` because it writes the same table,
//! and the catalog module exposes only the model it reads from.
//!
//! Every route in this module is gated on `Feature::AssetsCatalog`;
//! the toggle off returns 404 before any DB round trip, so a tenant
//! on an opt-out deployment behaves the same as one on a server
//! shipped before this module.

#[cfg(feature = "server")]
pub mod models;
#[cfg(feature = "server")]
pub mod routes;
#[cfg(feature = "server")]
pub mod service;

#[cfg(feature = "server")]
pub use models::*;
#[cfg(feature = "server")]
pub use routes::asset_catalog_routes;
#[cfg(feature = "server")]
pub use service::AssetCatalogService;
