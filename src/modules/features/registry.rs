//! The feature-toggle registry (PMS-1414): one [`Feature`] variant per switch,
//! one `feature_toggles` row per stored state.
//!
//! Ported from BUNYIP-840. The registry is the LIST of features and the table is
//! only a record of what somebody changed, which is what makes a missing row
//! read as off and a new variant need no migration.
//!
//! # How this differs from `config::flags`
//!
//! Both answer "is this on", and they are not interchangeable, so the choice is
//! worth stating rather than leaving to whoever adds the next switch.
//!
//! [`crate::config::flags`] (PMS-983) is for a switch whose value belongs to the
//! DEPLOYMENT's configuration: it comes from the configuration provider, it can
//! be set before the database exists, and changing it is a deploy. `ENCRYPTION_KEY`
//! is not a flag, but `LOGIN_APPROVAL_ENABLED` is that shape: an operator decision
//! about how the deployment behaves, which nobody should be able to flip from a
//! web page while a suspicious login is in flight.
//!
//! A FEATURE here is for work in progress: merged, dark, and flipped on in
//! staging by an admin without a deploy so it can be looked at. The point is to
//! stop features living on branches, which is the cost BUNYIP-840 named.
//!
//! PMS-1414 deliberately does not move the two existing flags into this table.
//! BUNYIP-840 made the same call about `tier_config.orgs_enabled`, and for the
//! same reason: a port that also rewires live behaviour cannot be reverted by
//! reverting it.
//!
//! # Renaming a key is adding a feature
//!
//! [`Feature::key`] is the `feature_toggles.key` value and the wire name in the
//! public probe. Renaming one does not migrate anything: the old row stops
//! matching, reads as an unknown key, and the feature reads as OFF on every
//! deployment that had it on. If a key has to change, write a migration that
//! moves the row.

use std::collections::{BTreeMap, BTreeSet};

/// One admin-managed feature switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// The integrations overview (MAPPS-971, server PMS-1310). Gates nothing
    /// yet: the page and its routes are live, and this entry exists so the
    /// registry ships exercised rather than empty.
    ///
    /// Chosen as the first entry for the same reason BUNYIP-840 chose
    /// `tenant_hostnames`: it names real work, it is honest that it gates
    /// nothing today, and flipping it cannot break anything while that is true.
    IntegrationsOverview,
}

impl Feature {
    /// Every registered feature, in admin-page order.
    pub const ALL: &'static [Feature] = &[Feature::IntegrationsOverview];

    /// The stable key: the `feature_toggles.key` value and the wire name. Never
    /// rename one; see the module docs.
    pub const fn key(self) -> &'static str {
        match self {
            Feature::IntegrationsOverview => "integrations_overview",
        }
    }

    /// The admin page's row title.
    pub const fn label(self) -> &'static str {
        match self {
            Feature::IntegrationsOverview => "Integrations overview",
        }
    }

    /// The admin page's help text: what the switch shows or hides, in the terms
    /// of somebody deciding whether to flip it.
    pub const fn help(self) -> &'static str {
        match self {
            Feature::IntegrationsOverview => {
                "The Settings page listing what this organization delegates to other systems. \
                 Nothing reads this switch yet, so flipping it changes nothing today."
            }
        }
    }

    /// The owning issue, for code, logs and the admin page's provenance. Never
    /// customer-facing copy.
    pub const fn issue(self) -> &'static str {
        match self {
            Feature::IntegrationsOverview => "MAPPS-971",
        }
    }

    /// The variant a stored key names, or `None` for a key no variant matches.
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.key() == key)
    }
}

/// The resolved state of every registered feature.
///
/// Holds only what is ON, so the default is every feature off, which is the
/// state before the first load finishes and the state of a database with no
/// rows. Those being the same answer is the point: a process that cannot read
/// the table yet behaves like one with nothing switched on, rather than guessing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeatureToggles {
    on: BTreeSet<Feature>,
}

impl FeatureToggles {
    /// Resolve stored `(key, enabled)` rows against the registry.
    ///
    /// An unknown key is ignored with one warning per process. Warned once
    /// rather than per load because the refresh runs every 60 seconds, and a
    /// stale row would otherwise produce a log line a minute forever.
    pub fn from_rows<'a>(rows: impl IntoIterator<Item = (&'a str, bool)>) -> Self {
        let mut on = BTreeSet::new();
        for (key, enabled) in rows {
            match Feature::from_key(key) {
                Some(feature) if enabled => {
                    on.insert(feature);
                }
                Some(_) => {}
                None => warn_unknown_key_once(key),
            }
        }
        Self { on }
    }

    pub fn is_enabled(&self, feature: Feature) -> bool {
        self.on.contains(&feature)
    }

    /// Every registered feature and its state, for the admin list and the public
    /// probe.
    ///
    /// Built from [`Feature::ALL`] rather than from the rows, so a feature with
    /// no row appears as `false` instead of being absent. A client that had to
    /// tell "off" from "not in the map" would get that wrong once and then gate
    /// on the wrong thing.
    pub fn as_map(&self) -> BTreeMap<&'static str, bool> {
        Feature::ALL
            .iter()
            .map(|feature| (feature.key(), self.is_enabled(*feature)))
            .collect()
    }
}

/// Unknown keys already warned about, so a stale row warns once per process.
fn warn_unknown_key_once(key: &str) {
    use std::sync::{Mutex, OnceLock};
    static WARNED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let warned = WARNED.get_or_init(|| Mutex::new(BTreeSet::new()));
    let first = warned
        .lock()
        .map(|mut set| set.insert(key.to_string()))
        .unwrap_or(false);
    if first {
        tracing::warn!(
            key = %key,
            "feature_toggles row names no registered feature; read as off. A removed feature's \
             row is kept on purpose so a rollback finds the operator's intent."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registry entry is self-consistent: the key round-trips, and the
    /// shape the table's CHECK requires is the shape the enum declares.
    ///
    /// The CHECK (`^[a-z][a-z0-9_]*$`) lives in migration 261 and the keys live
    /// here, so nothing but this test stops a variant shipping a key the
    /// database would refuse. The failure would be an upsert error at the moment
    /// an admin flips the switch, which is the worst time to find out.
    #[test]
    fn every_key_round_trips_and_matches_the_tables_check() {
        for feature in Feature::ALL {
            assert_eq!(Feature::from_key(feature.key()), Some(*feature));
            let key = feature.key();
            assert!(
                !key.is_empty()
                    && key.starts_with(|c: char| c.is_ascii_lowercase())
                    && key
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{key} would be refused by migration 261's CHECK"
            );
        }
        assert_eq!(Feature::from_key("no_such_feature"), None);
    }

    /// Two variants cannot share a key, label or issue by accident.
    ///
    /// A duplicate key is the one that matters: `from_key` returns the first
    /// match, so two variants sharing a key would make one of them permanently
    /// unreachable and permanently off, with nothing failing.
    #[test]
    fn no_two_features_share_a_key() {
        let keys: BTreeSet<&str> = Feature::ALL.iter().map(|f| f.key()).collect();
        assert_eq!(
            keys.len(),
            Feature::ALL.len(),
            "two features share a key, so one is unreachable and silently off"
        );
    }

    /// A missing row is off, an unknown key is ignored, and the map still lists
    /// every registered feature.
    ///
    /// The last clause is the one a client depends on: `as_map` is built from the
    /// registry, so a feature nobody has ever flipped appears as `false` rather
    /// than being absent, and a caller never has to distinguish the two.
    #[test]
    fn a_missing_row_is_off_and_an_unknown_key_is_ignored() {
        let empty = FeatureToggles::from_rows(Vec::<(&str, bool)>::new());
        for feature in Feature::ALL {
            assert!(
                !empty.is_enabled(*feature),
                "{} should default off",
                feature.key()
            );
        }
        assert_eq!(
            empty.as_map().len(),
            Feature::ALL.len(),
            "the map lists every registered feature even with no rows"
        );

        let with_unknown = FeatureToggles::from_rows(vec![("a_feature_this_build_removed", true)]);
        assert_eq!(
            with_unknown, empty,
            "an unknown key changes nothing; it is read as absent, not as an error"
        );

        let on = FeatureToggles::from_rows(vec![(Feature::IntegrationsOverview.key(), true)]);
        assert!(on.is_enabled(Feature::IntegrationsOverview));
        // And an explicit `false` row is the same as no row at all.
        let off = FeatureToggles::from_rows(vec![(Feature::IntegrationsOverview.key(), false)]);
        assert_eq!(off, empty);
    }
}
