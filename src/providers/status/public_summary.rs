//! PMS-1144: outward-facing provider-configuration summary.
//!
//! [`super::route`] serves the full [`super::ProviderStatusReport`] behind
//! `RequireAdmin`: it carries per-key provenance, live-vs-recorded staleness,
//! reachability messages, and a generation actor. That is what an operator
//! looking at the standalone HTML page wants, and what BUNYIP-634 will
//! eventually aggregate under a machine credential.
//!
//! PMS-1144 wants a smaller half of the same picture, reachable BY BUNYIP
//! from the outside with no credential exchange: per Mokosh instance, which
//! providers are CONFIGURED for the deployment-scoped kinds. That answers
//! the standup question "which auth path is this instance using?" without
//! asking an operator to log in and read the admin page.
//!
//! The rules that make an unauthenticated endpoint safe:
//!
//! - **Identity only.** Only the [`&'static str`] provider name per kind,
//!   the hosting-profile name, and a schema version. No values, no
//!   credentials, no URLs, no reachability strings, no per-key rows, no
//!   generation actor. Everything else the report holds is a NON-goal here
//!   and must never leak in from a later [`super::ProviderStatusReport`]
//!   field addition, which is what
//!   [`super::tests::public_summary_carries_no_secret_looking_strings`]
//!   asserts.
//! - **Deployment-scoped kinds only.** `configuration`, `secrets_application`,
//!   `storage`, `authentication`, `email`. The tenant tier
//!   (`secrets_tenant`) is deliberately omitted: every tenant chooses their
//!   own gateway/RMM providers per row, so a single per-instance identity
//!   is meaningless. BUNYIP-634 gets that shape from its aggregator instead.
//!
//! Both halves are pinned by tests below.

use serde::Serialize;

use super::ProviderStatusReport;

/// The schema version of the public summary envelope. Bumped when the
/// envelope's shape changes; adding a new kind (a new provider capability
/// the deployment configures) is a shape change and requires a bump.
pub const SCHEMA_VERSION: &str = "1";

/// The public summary: hosting profile + enabled provider names per
/// deployment-scoped kind. See the module doc for what deliberately does
/// NOT appear here.
#[derive(Debug, Clone, Serialize)]
pub struct PublicProviderSummary {
    pub schema_version: &'static str,
    pub hosting_profile: &'static str,
    pub providers: PublicProviders,
}

/// Enabled provider names per deployment-scoped kind, in priority order.
///
/// A concrete struct rather than a map because the SHAPE is fixed - a
/// consumer can bind types to it - and because a map with `&'static str`
/// keys reads less well on the wire.
#[derive(Debug, Clone, Serialize)]
pub struct PublicProviders {
    pub configuration: Vec<&'static str>,
    pub secrets_application: Vec<&'static str>,
    pub storage: Vec<&'static str>,
    pub authentication: Vec<&'static str>,
    pub email: Vec<&'static str>,
}

/// Reduce a [`ProviderStatusReport`] to the outward summary. Pure over its
/// input, so the endpoint that calls `super::collect().summarize()` and the
/// tests that build a report by hand share one derivation.
pub fn summarize(report: &ProviderStatusReport) -> PublicProviderSummary {
    let names_for = |kind: &'static str| -> Vec<&'static str> {
        report
            .kinds
            .iter()
            .find(|k| k.kind == kind)
            .map(|k| k.enabled.iter().map(|e| e.name).collect())
            .unwrap_or_default()
    };
    PublicProviderSummary {
        schema_version: SCHEMA_VERSION,
        hosting_profile: report.hosting_profile,
        providers: PublicProviders {
            configuration: names_for("configuration"),
            secrets_application: names_for("secrets_application"),
            storage: names_for("storage"),
            authentication: names_for("authentication"),
            email: names_for("email"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::status::collect;

    /// A live collection round-trips through the summary and back to the
    /// serialised envelope, with the shape callers can bind to: a schema
    /// version, a hosting profile, and per-kind arrays.
    #[test]
    fn a_live_collection_produces_the_documented_envelope_shape() {
        let report = collect();
        let summary = summarize(&report);
        let value = serde_json::to_value(&summary).expect("summary serialises");
        assert!(value["schema_version"].is_string());
        assert!(value["hosting_profile"].is_string());
        for kind in [
            "configuration",
            "secrets_application",
            "storage",
            "authentication",
            "email",
        ] {
            assert!(
                value["providers"][kind].is_array(),
                "providers.{kind} must be an array"
            );
        }
    }

    /// The tenant-tier kind is deliberately absent from the summary: a
    /// single per-instance identity is meaningless when every tenant
    /// chooses their own gateway/RMM providers.
    #[test]
    fn the_tenant_tier_is_absent_from_the_summary() {
        let report = collect();
        let value = serde_json::to_value(summarize(&report)).unwrap();
        assert!(
            value["providers"]["secrets_tenant"].is_null(),
            "the tenant tier is deliberately absent from the outward summary"
        );
    }

    /// A hand-built report round-trips through summarize with the names its
    /// kinds carry. Kinds the report omits render as empty arrays rather
    /// than error, so a future kind added upstream does not break the shape.
    #[test]
    fn missing_kinds_render_as_empty_arrays() {
        use chrono::Utc;

        use crate::providers::status::{
            GenerationHeader, ProviderKindReport, ProviderStatusReport,
        };

        let report = ProviderStatusReport {
            hosting_profile: "self-hosted",
            deviations: Vec::new(),
            configuration_generation: GenerationHeader {
                number: 1,
                resolved_at: Utc::now(),
                actor: "System".to_string(),
            },
            kinds: vec![ProviderKindReport {
                kind: "authentication",
                enabled: Vec::new(),
                serving: None,
                keys: Vec::new(),
                enumeration: None,
            }],
            collected_at: Utc::now(),
        };
        let summary = summarize(&report);
        assert!(summary.providers.configuration.is_empty());
        assert!(summary.providers.storage.is_empty());
        assert!(summary.providers.email.is_empty());
        assert!(summary.providers.authentication.is_empty());
    }

    /// The summary carries NO credential-shaped value: no URLs, no long
    /// opaque strings, no per-key provenance rows, no generation actor,
    /// no timestamps. Enforced by inspecting the JSON tree and refusing
    /// any leaf value that is not either the hosting-profile name, the
    /// schema-version literal, or a known short provider identifier
    /// (`environment`, `file`, `database`, `bunyip`, `infisical`, `local`,
    /// `smtp`, `log`, `s3`, `platform_admin`, `system`).
    ///
    /// A source-scan-plus-serialise pair so a future field addition on the
    /// underlying report has to explicitly state its case for reaching
    /// this endpoint: a NEW leaf value the assertion below does not
    /// recognise fails the test, and either the field belongs on the full
    /// admin report (not the summary), or a new short identifier gets
    /// added here alongside the argument that it is a name and not a
    /// value.
    #[test]
    fn public_summary_carries_no_secret_looking_strings() {
        let report = collect();
        let value = serde_json::to_value(summarize(&report)).unwrap();

        // Allowed leaf strings. Every leaf on the summary must be one of
        // these, else the assertion fails and the diff has to explain why
        // a new string is safe to expose unauth.
        let allowed_kinds = ["self-hosted", "saas"];
        let allowed_versions = ["1"];
        let allowed_provider_names = [
            "environment",
            "file",
            "database",
            "bunyip",
            "infisical",
            "local",
            "smtp",
            "log",
            "s3",
        ];

        // Walk the JSON tree; every leaf must be a member of one of the
        // allowed sets above.
        fn walk(
            value: &serde_json::Value,
            path: &str,
            allowed_kinds: &[&str],
            allowed_versions: &[&str],
            allowed_provider_names: &[&str],
        ) {
            match value {
                serde_json::Value::String(s) => {
                    let ok = allowed_kinds.contains(&s.as_str())
                        || allowed_versions.contains(&s.as_str())
                        || allowed_provider_names.contains(&s.as_str());
                    assert!(
                        ok,
                        "unexpected leaf string {s:?} at {path}: the outward summary must only \
                         carry the hosting profile, the schema version, or a known short provider \
                         identifier"
                    );
                }
                serde_json::Value::Number(_) | serde_json::Value::Bool(_) => {
                    panic!(
                        "unexpected numeric/bool leaf at {path}: the outward summary is \
                         string-only by design"
                    );
                }
                serde_json::Value::Null => {}
                serde_json::Value::Array(items) => {
                    for (i, item) in items.iter().enumerate() {
                        walk(
                            item,
                            &format!("{path}[{i}]"),
                            allowed_kinds,
                            allowed_versions,
                            allowed_provider_names,
                        );
                    }
                }
                serde_json::Value::Object(fields) => {
                    for (k, v) in fields {
                        walk(
                            v,
                            &format!("{path}.{k}"),
                            allowed_kinds,
                            allowed_versions,
                            allowed_provider_names,
                        );
                    }
                }
            }
        }
        walk(
            &value,
            "$",
            &allowed_kinds,
            &allowed_versions,
            &allowed_provider_names,
        );
    }
}
