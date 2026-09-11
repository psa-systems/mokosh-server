//! JSON renderer for [`super::ProviderStatusReport`].
//!
//! Pure function of the report. PMS-1014 moved the envelope shape into the
//! shared [`dunite_provider_status`] crate; this module keeps the public
//! entry point so the route mount site is unchanged, and delegates to
//! [`envelope::envelope`] for the byte-identical
//! `{schema_version, report, generated_at}` shape.

use chrono::Utc;
use dunite_provider_status::envelope;
use serde_json::Value;

use super::ProviderStatusReport;

/// The schema version of the JSON envelope. Re-exported from the shared
/// contract so a caller that reads `SCHEMA_VERSION` here still gets one
/// answer for every producer.
pub use dunite_provider_status::envelope::SCHEMA_VERSION;

/// Render the JSON envelope. The nested report shape comes from serialising
/// [`ProviderStatusReport`] through its derives, so adding a field to the
/// report automatically reaches the wire without a second serialiser to
/// keep in step.
pub fn render_json(report: &ProviderStatusReport) -> Value {
    envelope::envelope(report, Utc::now())
}
