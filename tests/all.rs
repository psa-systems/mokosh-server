//! The one integration test binary (PMS-1520).
//!
//! Every `tests/*.rs` used to be its own binary, and each linked the whole
//! server library: 246 of them, ~63 MB each, which is the 16 GB that
//! `cargo nextest archive` compressed into the 3 GB artifact every run
//! pushed through the Forgejo artifact store. The upload took 12 minutes
//! and timed out the runner's docker socket often enough to fail the job.
//!
//! Consolidating costs nothing under nextest, which runs each test case in its
//! own process whatever binary it came from, so a suite that mutates process
//! state is as isolated as it was. That is how CI and `just test-integration`
//! run this suite.
//!
//! It is NOT runnable with plain `cargo test`, which shares one process across
//! the whole file (PMS-1523). Nineteen cases depend on having a process to
//! themselves: eleven install a global tracing subscriber, one counts what the
//! PROCESS allocated, and the bunyip pair stands up a stub OP whose caches
//! outlive a test. Run `just test-integration`, or nextest directly.

mod common;
mod suites;
