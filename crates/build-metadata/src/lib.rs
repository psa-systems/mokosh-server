//! Shared build-script helper for the Mokosh workspace.
//!
//! Both the workspace-root `build.rs` and `crates/google-oauth-flow/build.rs`
//! used to carry a near-identical copy of this logic (PMS-198). They now call
//! [`emit`] so the git hash / describe / build date capture lives in exactly
//! one place. The only thing that differs between call sites is the relative
//! path to the `.git` directory, passed as `git_dir`.
//!
//! Resolution order for each value:
//!   1. Pre-set env var (`MOKOSH_GIT_HASH`, `MOKOSH_GIT_DESCRIBE`,
//!      `MOKOSH_BUILD_DATE`, `SOURCE_DATE_EPOCH`). Lets CI / Docker pass
//!      values when `.git` is not in the build context.
//!   2. `git` invocation against the surrounding working tree.
//!   3. A safe fallback (`unknown`, the Cargo package version, or "now").

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Emit the `cargo:rustc-env` + `cargo:rerun-if-*` directives that expose
/// `MOKOSH_GIT_HASH`, `MOKOSH_GIT_DESCRIBE`, and `MOKOSH_BUILD_DATE` to the
/// crate being built.
///
/// `git_dir` is the path to the `.git` directory relative to the calling
/// crate's manifest dir: `".git"` for the workspace root, `"../../.git"` for
/// a crate two levels deep under `crates/`.
pub fn emit(git_dir: &str) {
    let git_hash = resolve_git_hash();
    let git_describe = resolve_git_describe();
    let build_date = resolve_build_date();

    println!("cargo:rustc-env=MOKOSH_GIT_HASH={git_hash}");
    println!("cargo:rustc-env=MOKOSH_GIT_DESCRIBE={git_describe}");
    println!("cargo:rustc-env=MOKOSH_BUILD_DATE={build_date}");

    println!("cargo:rerun-if-env-changed=MOKOSH_GIT_HASH");
    println!("cargo:rerun-if-env-changed=MOKOSH_GIT_DESCRIBE");
    println!("cargo:rerun-if-env-changed=MOKOSH_BUILD_DATE");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-changed={git_dir}/HEAD");
    println!("cargo:rerun-if-changed={git_dir}/refs");
    println!("cargo:rerun-if-changed={git_dir}/index");
}

fn resolve_git_hash() -> String {
    if let Ok(value) = std::env::var("MOKOSH_GIT_HASH") {
        if !value.trim().is_empty() {
            return value.trim().to_string();
        }
    }
    run_git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_string())
}

fn resolve_git_describe() -> String {
    if let Ok(value) = std::env::var("MOKOSH_GIT_DESCRIBE") {
        if !value.trim().is_empty() {
            return value.trim().to_string();
        }
    }
    run_git(&["describe", "--tags", "--always", "--dirty"]).unwrap_or_else(|| {
        // Build scripts run with `CARGO_PKG_VERSION` set to the *consuming*
        // crate's version, so read it at runtime rather than via `env!`
        // (which would bake in this helper crate's own version instead).
        let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
        format!("v{version}")
    })
}

fn resolve_build_date() -> String {
    if let Ok(value) = std::env::var("MOKOSH_BUILD_DATE") {
        if !value.trim().is_empty() {
            return value.trim().to_string();
        }
    }
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        })
        .unwrap_or(0);
    format_iso8601_utc(epoch)
}

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Convert a UNIX epoch (seconds) into an ISO-8601 UTC timestamp without
/// pulling in `chrono` as a build dependency.
fn format_iso8601_utc(epoch: u64) -> String {
    let secs_per_day: u64 = 86_400;
    let days_since_epoch = epoch / secs_per_day;
    let secs_today = epoch % secs_per_day;
    let hour = secs_today / 3600;
    let minute = (secs_today % 3600) / 60;
    let second = secs_today % 60;

    let (year, month, day) = civil_from_days(days_since_epoch as i64);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// Howard Hinnant's `civil_from_days` algorithm: convert days since the
/// UNIX epoch (1970-01-01) into a (year, month, day) tuple. Used to format
/// the build date without requiring a date-time crate at build time.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}
