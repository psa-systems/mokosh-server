//! Build script: capture git hash, git describe, and build date as
//! compile-time env vars so binaries can report the exact source revision
//! they were built from.
//!
//! All the logic lives in the `build-metadata` helper crate (PMS-198) so any
//! workspace member's build script can share one implementation. The workspace
//! root's `.git` sits alongside this manifest.

fn main() {
    build_metadata::emit(".git");
}
