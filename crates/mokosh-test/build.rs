//! PMS-1398: recompile this crate when a migration is added or changed.
//!
//! `sqlx::migrate!` embeds `migrations/` at compile time, but on stable it
//! registers nothing as a build dependency (`proc_macro::tracked_path` is
//! nightly-only), so without this script cargo has no reason to rebuild after a
//! migration lands and the test harness carries a migration set that is not the
//! tree's. Cargo walks a directory named here recursively, so a NEW file counts
//! as a change and not only an edit to one it already knew about.
//!
//! The path is relative to this package's manifest, which is where cargo runs a
//! build script.

fn main() {
    // SPEC-1 and 2.162: declares migrations/ a build dependency so this crate recompiles whenever a migration is
    // added or changed, keeping the compile-time-embedded migration set from going stale relative to the tree.
    println!("cargo:rerun-if-changed=../../migrations");
}
