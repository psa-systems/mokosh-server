//! Build script: capture git hash, git describe, and build date as
//! compile-time env vars so binaries can report the exact source revision
//! they were built from.
//!
//! All the logic lives in the `build-metadata` helper crate (PMS-198) so any
//! workspace member's build script can share one implementation. The workspace
//! root's `.git` sits alongside this manifest.

// SPEC-1 and 2.151: build.rs delegates MOKOSH_GIT_HASH/MOKOSH_GIT_DESCRIBE/MOKOSH_BUILD_DATE emission to build-metadata::emit.
fn main() {
    build_metadata::emit(".git");
    // PMS-1398: `src/db/pool.rs` embeds `migrations/` with `sqlx::migrate!`,
    // which on stable registers nothing as a build dependency, so without this
    // line a dev build can keep serving a migration set that is not the tree's.
    // Cargo walks a directory named here recursively, so a new file counts.
    println!("cargo:rerun-if-changed=migrations");
}
