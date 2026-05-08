//! Build-time version information.
//!
//! `build.rs` captures three values at compile time and exports them as
//! env vars (`MOKOSH_GIT_HASH`, `MOKOSH_GIT_DESCRIBE`, `MOKOSH_BUILD_DATE`).
//! This module exposes them as `&'static str` constants and packages them
//! into a serializable struct that the `/api/v1/version` endpoint and
//! startup logging both consume.

use serde::Serialize;

/// Crate version from `Cargo.toml` (e.g. `"0.1.0"`).
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Output of `git describe --tags --always --dirty` at build time. When
/// the build runs on a tagged commit this matches the release tag (e.g.
/// `v0.1.0`); otherwise it includes the commit count and short hash
/// (e.g. `v0.1.0-22-ged5a288`).
pub const GIT_DESCRIBE: &str = env!("MOKOSH_GIT_DESCRIBE");

/// Short git commit hash (12 chars) the binary was built from.
pub const GIT_HASH: &str = env!("MOKOSH_GIT_HASH");

/// ISO-8601 UTC timestamp of the build.
pub const BUILD_DATE: &str = env!("MOKOSH_BUILD_DATE");

/// JSON-serializable bundle returned by the `/version` endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub git_describe: &'static str,
    pub git_hash: &'static str,
    pub build_date: &'static str,
}

impl VersionInfo {
    pub const fn current() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME"),
            version: PACKAGE_VERSION,
            git_describe: GIT_DESCRIBE,
            git_hash: GIT_HASH,
            build_date: BUILD_DATE,
        }
    }

    /// Single-line summary suitable for a startup log: `"<name> <describe>
    /// (<hash>) built <date>"`.
    pub fn banner(&self) -> String {
        format!(
            "{} {} ({}) built {}",
            self.name, self.git_describe, self.git_hash, self.build_date
        )
    }
}
