//! Build script: capture git hash, git describe, and build date as
//! compile-time env vars for the `google-oauth-flow` workspace member.
//!
//! Mirrors the logic in the workspace-root `build.rs` so the helper crate
//! can expose the same `VERSION` / `GIT_HASH` / `BUILD_DATE` constants.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
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
    // Workspace member sits two levels deep; paths are relative to this
    // crate's manifest dir.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
    println!("cargo:rerun-if-changed=../../.git/index");
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
    run_git(&["describe", "--tags", "--always", "--dirty"])
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")))
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

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}
