//! The one integration test binary (PMS-1520).
//!
//! Every `tests/*.rs` used to be its own binary, and each linked the whole
//! server library: 246 of them, ~63 MB each, which is the 16 GB that
//! `cargo nextest archive` compressed into the 3 GB artifact every run
//! pushed through the Forgejo artifact store. The upload took 12 minutes
//! and timed out the runner's docker socket often enough to fail the job.
//!
//! Consolidating costs nothing in isolation: nextest runs each test case in
//! its own process whatever binary it came from, so a suite that mutates
//! process state is as isolated as it was.

mod common;
mod suites;
