//! Build script: capture git hash, git describe, and build date as
//! compile-time env vars for the `google-oauth-flow` workspace member.
//!
//! Shares its implementation with the workspace-root `build.rs` via the
//! `build-metadata` helper crate (PMS-198). This member sits two levels deep
//! under `crates/`, so the `.git` directory is `../../.git` relative to this
//! manifest.

fn main() {
    build_metadata::emit("../../.git");
}
