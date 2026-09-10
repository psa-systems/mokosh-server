//! JSON renderer for [`super::ProviderStatusReport`].
//!
//! Pure function of the report. The envelope carries a schema version so
//! BUNYIP-634's aggregator has a stable shape to bind to, plus a
//! `generated_at` distinct from the report's own `collected_at`: the two
//! are almost always the same, but a caller that renders a cached report
//! will differ, and a consumer that spots the drift can act on it.

use chrono::Utc;
use serde_json::{json, Value};

use super::ProviderStatusReport;

/// The schema version of the JSON envelope. Bump when the envelope's shape
/// changes; the nested report shape is versioned by its own serialisation.
pub const SCHEMA_VERSION: &str = "1";

/// Render the JSON envelope. `serde_json::to_value` produces the nested
/// report from its derives, so adding a field to `ProviderStatusReport`
/// automatically reaches the wire without a second serialiser to keep in
/// step.
pub fn render_json(report: &ProviderStatusReport) -> Value {
    let inner = serde_json::to_value(report).expect(
        "ProviderStatusReport is derive-Serialize and holds only \
         serialisable primitives; conversion is infallible",
    );
    json!({
        "schema_version": SCHEMA_VERSION,
        "report": inner,
        "generated_at": Utc::now().to_rfc3339(),
    })
}
