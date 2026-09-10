//! PMS-1012: the write-read-back-compare invariant, as a small library.
//!
//! `crate::modules::billing::credential_move` already implements this shape for
//! payment-gateway credentials moving out of the DB column and into the tenant
//! secret provider (PMS-968). The provider-migrate CLI wants the same shape
//! for a per-key application-tier move, and shipping a second copy would let
//! the two rules drift.
//!
//! The helper here is the invariant only: given a `read_target` and a way to
//! compare, decide whether the write landed. It does not know how the write is
//! performed, so it stays free of tier-specific state (`SecretKey` or
//! `GovernedSecret` or a `ConfigKey`) and every caller can compose it against
//! whatever provider trait they have.
//!
//! # Redaction
//!
//! `expected` is only compared to `readback` and never surfaced. The error
//! path names the failure mode but never the value on either side, matching
//! PMS-988's redaction discipline for `app_secrets`.

use crate::utils::error::{AppError, AppResult};

/// Compare a `readback` value to what was just written.
///
/// A helper rather than an inlined `!=`, because the sentence that gets
/// logged when it fails is the one the migrate CLI must render and never a
/// bare value. Returns `Ok(())` when they match; `Err(AppError::Configuration)`
/// with a redacted message when they do not.
///
/// The caller has already done the write; this is the invariant that decides
/// whether to trust it.
pub fn verify_readback(readback: Option<&str>, expected: &str) -> AppResult<()> {
    if readback == Some(expected) {
        Ok(())
    } else if readback.is_none() {
        Err(AppError::Configuration(
            "write reached provider but read-back returned no value".to_string(),
        ))
    } else {
        Err(AppError::Configuration(
            "write reached provider but read-back returned a different value".to_string(),
        ))
    }
}

/// Perform the write and the read-back for one key.
///
/// The reason this exists rather than being inlined at each CLI site: the
/// three subcommands and the credential-mover job all want the same
/// contract, and phrasing it once means the "clear old only after the
/// read-back agrees" rule is one thing to review rather than three.
///
/// The caller supplies:
///
/// - `write`: an async closure that puts `value` into the target provider.
/// - `read_back`: an async closure that reads the target provider LIVE.
///
/// `value` is passed in rather than borrowed from a closure so the helper
/// can hand it to `verify_readback` without either closure holding it.
///
/// Any error from `write` propagates unchanged. A `write` that succeeds
/// followed by a `read_back` that returns anything other than `Some(value)`
/// returns an `AppError::Configuration` whose message names the failure
/// mode and never the value.
pub async fn move_value_with_readback<'a, Write, WriteFut, ReadBack, ReadBackFut>(
    value: &'a str,
    write: Write,
    read_back: ReadBack,
) -> AppResult<()>
where
    Write: FnOnce(&'a str) -> WriteFut,
    WriteFut: std::future::Future<Output = AppResult<()>>,
    ReadBack: FnOnce() -> ReadBackFut,
    ReadBackFut: std::future::Future<Output = AppResult<Option<String>>>,
{
    write(value).await?;
    let readback = read_back().await?;
    verify_readback(readback.as_deref(), value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The good path: the read-back matches, so the invariant is Ok.
    #[test]
    fn a_readback_that_matches_is_ok() {
        verify_readback(Some("hunter2"), "hunter2").expect("matching readback must pass");
    }

    /// The bad path: the read-back is missing.
    #[test]
    fn a_missing_readback_is_an_error() {
        let err = verify_readback(None, "hunter2").expect_err("a missing readback must fail");
        let msg = err.to_string();
        assert!(msg.contains("no value"), "{msg}");
        assert!(!msg.contains("hunter2"), "the value must not leak: {msg}");
    }

    /// The bad path: the read-back is present but different.
    #[test]
    fn a_mismatched_readback_is_an_error_and_hides_both_values() {
        let err =
            verify_readback(Some("other"), "hunter2").expect_err("a mismatched readback must fail");
        let msg = err.to_string();
        assert!(msg.contains("different"), "{msg}");
        assert!(!msg.contains("hunter2"), "the expected value leaked: {msg}");
        assert!(!msg.contains("other"), "the readback value leaked: {msg}");
    }

    /// The end-to-end path: write and read-back agree.
    #[tokio::test]
    async fn move_value_writes_then_reads_and_compares() {
        let outcome = move_value_with_readback(
            "hunter2",
            |v| async move {
                assert_eq!(v, "hunter2");
                Ok(())
            },
            || async { Ok(Some("hunter2".to_string())) },
        )
        .await;
        assert!(outcome.is_ok(), "{outcome:?}");
    }

    /// The end-to-end path: write fails, read-back never runs.
    #[tokio::test]
    async fn a_write_failure_propagates_without_reading_back() {
        let read_ran = std::sync::atomic::AtomicBool::new(false);
        let outcome = move_value_with_readback(
            "hunter2",
            |_| async { Err(AppError::Configuration("no".to_string())) },
            || {
                read_ran.store(true, std::sync::atomic::Ordering::Relaxed);
                async { Ok(Some(String::new())) }
            },
        )
        .await;
        assert!(outcome.is_err());
        assert!(
            !read_ran.load(std::sync::atomic::Ordering::Relaxed),
            "the read-back must not run after a failed write"
        );
    }
}
