//! Feature toggles (PMS-1414): switches an admin flips without a deploy.
//!
//! Ported from BUNYIP-840, whose framing is the reason this exists: every major
//! feature ships behind an on/off switch, off in production and on in staging,
//! so unfinished work merges dark instead of living on a branch.
//!
//! Four pieces, each in its own file because each is a different kind of thing:
//! [`registry`] is the list of features and the resolution rule, [`service`] is
//! the stored rows and the process snapshot, [`job`] is the interval refresh, and
//! [`routes`] is the operator surface plus the public probe.
//!
//! See `docs/feature-toggles.md` for how to add one.

pub mod job;
pub mod registry;
pub mod routes;
pub mod service;

pub use job::FeatureToggleRefresh;
pub use registry::{Feature, FeatureToggles};
pub use service::FeatureSnapshot;
