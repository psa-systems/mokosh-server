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
    println!("cargo:rerun-if-changed=../../migrations");
}
