//! The deployment's product name (PMS-789).
//!
//! One value for the whole process, not one per tenant: it answers "which
//! deployment is this" (psa.systems vs staging), which is the same answer for
//! every tenant on the box. The store is the system-tenant `tenant_settings`
//! row owned by [`crate::modules::settings::app_name`]; this module is the
//! cache every consumer reads.
//!
//! It is a cache rather than a query because two consumers cannot make one.
//! `api::router::not_a_frontend` is the catch-all 404 handler: it takes no
//! `State`, and it has to render when the database is down, which is exactly
//! when someone is looking at it. The invitation mail builds its subject inside
//! an already-open tenant transaction, where a second `begin_with_tenant` would
//! take a second pool connection to read a display string. A synchronous read
//! of an in-memory value serves both.
//!
//! There is deliberately no `APP_NAME` environment variable. PMS-789 exists to
//! stop carrying this value in the environment, and `scripts/check-env-example.nu`
//! would then require it in `.env.example` and `compose.dev.yml` too - three
//! more places naming a string an admin can already edit.

use std::sync::{Arc, RwLock};

/// Rendered wherever no operator has set a name. Every site this replaced was
/// the literal `"Mokosh"`, so a deployment that never touches the setting
/// renders exactly what it rendered before the move.
pub const DEFAULT_APP_NAME: &str = "Mokosh";

/// Longest accepted name. Long enough for "Acme Managed Services", short
/// enough that it cannot push the meaningful part of an email subject out of a
/// mail client's preview column.
pub const MAX_APP_NAME_LEN: usize = 64;

/// `None` means "nothing configured", which reads as [`DEFAULT_APP_NAME`].
/// Distinguishing it from `Some(DEFAULT_APP_NAME)` is what lets the read API
/// tell an operator whether a name was actually set.
static APP_NAME: RwLock<Option<Arc<str>>> = RwLock::new(None);

/// The name every consumer renders. Never empty: an unset (or unusable)
/// setting yields [`DEFAULT_APP_NAME`], because a blank product name in an
/// email subject is a worse outcome than an unchanged one.
pub fn app_name() -> Arc<str> {
    APP_NAME
        .read()
        .expect("app name lock poisoned")
        .clone()
        .unwrap_or_else(|| Arc::from(DEFAULT_APP_NAME))
}

/// Replace the cached name. `None` restores the default. Takes effect on the
/// next read by every consumer in the process, which is what makes the setting
/// editable without a restart.
pub fn set_app_name(name: Option<&str>) {
    *APP_NAME.write().expect("app name lock poisoned") = name.map(Arc::from);
}

/// The one validator for this value, used by the admin write path and again
/// when a stored value is loaded at boot, so a row that predates a rule (or was
/// edited straight in the database) cannot bypass it.
///
/// Rejects control characters because the name lands in email `Subject`
/// headers: a `\r\n` in a header value is header injection, and lettre would
/// otherwise carry whatever an admin typed.
pub fn sanitize(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("app name must not be blank".to_string());
    }
    if trimmed.chars().count() > MAX_APP_NAME_LEN {
        return Err(format!(
            "app name must be at most {MAX_APP_NAME_LEN} characters"
        ));
    }
    if trimmed.chars().any(char::is_control) {
        return Err("app name must not contain control characters".to_string());
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cache is one value for the process, so the tests that write it are
    /// serialized against each other. Without this they race inside the lib
    /// test binary and fail intermittently, which is the honest cost of a
    /// process-global and worth paying here (see the module docs for why the
    /// consumers cannot take a per-read query instead).
    static TEST_GUARD: RwLock<()> = RwLock::new(());

    fn exclusive() -> std::sync::RwLockWriteGuard<'static, ()> {
        TEST_GUARD.write().unwrap_or_else(|e| e.into_inner())
    }

    /// The reason the type is `Option`: "no row" and "a row saying Mokosh"
    /// both render the same string, and only the cache can tell them apart.
    #[test]
    fn an_unset_name_reads_as_the_default() {
        let _g = exclusive();
        set_app_name(None);
        assert_eq!(&*app_name(), DEFAULT_APP_NAME);
    }

    #[test]
    fn a_set_name_is_what_consumers_read_and_can_be_changed_again() {
        let _g = exclusive();
        set_app_name(Some("PSA Systems"));
        assert_eq!(&*app_name(), "PSA Systems");
        set_app_name(Some("PSA Staging"));
        assert_eq!(&*app_name(), "PSA Staging");
        set_app_name(None);
        assert_eq!(&*app_name(), DEFAULT_APP_NAME);
    }

    /// A blank name is the outcome this setting must never produce, so it is
    /// refused at the door rather than rendered.
    #[test]
    fn blank_and_whitespace_only_names_are_refused() {
        assert!(sanitize("").is_err());
        assert!(sanitize("   ").is_err());
        assert!(sanitize("\t\n").is_err());
    }

    /// The subject-header injection case. `\r\n` in a name would otherwise
    /// become a second header line in every mail this deployment sends.
    #[test]
    fn control_characters_are_refused() {
        assert!(sanitize("PSA\r\nBcc: attacker@example.test").is_err());
        assert!(sanitize("PSA\u{0}Systems").is_err());
        assert!(sanitize("PSA\tSystems").is_err());
    }

    #[test]
    fn a_name_is_trimmed_and_length_bounded() {
        assert_eq!(sanitize("  PSA Systems  ").unwrap(), "PSA Systems");
        assert!(sanitize(&"a".repeat(MAX_APP_NAME_LEN)).is_ok());
        assert!(sanitize(&"a".repeat(MAX_APP_NAME_LEN + 1)).is_err());
        // Counted in characters, not bytes, so a multi-byte name is not
        // rejected for being multi-byte.
        assert!(sanitize(&"é".repeat(MAX_APP_NAME_LEN)).is_ok());
    }
}
