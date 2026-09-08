//! The environment provider: read `{NAME}_FILE` compose secrets, never the
//! plain variable.
//!
//! Bunyip's `secret_file_env` (`crates/bunyip-domain/src/config.rs`, BUNYIP-38)
//! is the shape this adopts. A `SMTP_PASSWORD=hunter2` in a compose
//! `environment:` block is visible to `docker inspect` and to every child
//! process; the operator's actual home for a compose deployment is a mounted
//! secret file named by `SMTP_PASSWORD_FILE=/run/secrets/smtp_password`, and
//! this provider reads only that form. Refusing the plain variable is what
//! keeps a leaked `docker inspect` out of an operator's threat model.
//!
//! `is_writable()` is `false`: a process cannot set an env variable for its
//! own next boot, and compose secret files are mounted read-only. That is a
//! property of the provider, not a policy on top of it, so the admin surface
//! that later renders a save form reads the flag and gets a natural 409.

use super::{AppSecretProvider, GovernedSecret};

/// The environment provider. Zero state: every read consults the current
/// process environment directly, and every write is refused by `is_writable`.
pub struct EnvironmentProvider;

impl AppSecretProvider for EnvironmentProvider {
    fn name(&self) -> &'static str {
        "environment"
    }

    /// Read one governed secret from `{NAME}_FILE`, and only from there. An
    /// empty file, an empty path and a missing variable all collapse to
    /// `None`: empty is not a secret (BUNYIP-621), and every provider in
    /// this module agrees on that so the classification cannot report a
    /// blank as held.
    ///
    /// An unreadable path (the variable names a file the process cannot
    /// open) is logged at `error` and read as `None`; the classification
    /// then reports "no provider holds this" honestly rather than a silent
    /// success.
    fn get(&self, secret: GovernedSecret) -> Option<String> {
        let file_var = format!("{}_FILE", secret.name());
        let path = std::env::var(&file_var).ok()?;
        let path = path.trim();
        if path.is_empty() {
            return None;
        }
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let trimmed = contents.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }
            Err(e) => {
                tracing::error!(
                    env_var = %file_var,
                    path = %path,
                    error = %e,
                    "the environment provider cannot read {}; treating it as unheld",
                    file_var
                );
                None
            }
        }
    }

    /// The environment provider is read-only: a process cannot set a variable
    /// for its own next boot, and the compose secret file at `{NAME}_FILE`
    /// is mounted read-only. See the module doc.
    fn is_writable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Serialise env-var mutation across tests: `std::env::set_var` writes
    /// process-global state, and two concurrent `SMTP_PASSWORD_FILE` fixtures
    /// would race. The tests in this module are all env-var-touching, so
    /// they share one lock.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// PMS-988: the provider reads `{NAME}_FILE` ONLY. A plain `SMTP_PASSWORD`
    /// left in the environment for the tenant tier or a manual test must not
    /// register as held here, because the `docker inspect` exposure this
    /// avoidance closes only applies to the plain form.
    #[test]
    fn plain_variable_alone_returns_none() {
        let _guard = env_lock();
        // Set the plain variable; do NOT set the _FILE one.
        std::env::set_var("SMTP_PASSWORD", "leaked-via-docker-inspect");
        std::env::remove_var("SMTP_PASSWORD_FILE");

        assert_eq!(EnvironmentProvider.get(GovernedSecret::SmtpPassword), None);

        std::env::remove_var("SMTP_PASSWORD");
    }

    /// The file the `_FILE` variable names is what the provider reads, with
    /// trimming and empty-is-absent applied.
    #[test]
    fn file_variable_returns_the_file_contents_trimmed() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("smtp_password");
        std::fs::write(&path, "  hunter2\n").expect("write fixture");

        std::env::remove_var("SMTP_PASSWORD");
        std::env::set_var("SMTP_PASSWORD_FILE", &path);
        let value = EnvironmentProvider.get(GovernedSecret::SmtpPassword);
        std::env::remove_var("SMTP_PASSWORD_FILE");

        assert_eq!(value.as_deref(), Some("hunter2"));
    }

    /// An empty file, and a path pointing at nothing, both read as unheld.
    #[test]
    fn empty_and_missing_file_read_as_unheld() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = dir.path().join("empty");
        std::fs::File::create(&empty).unwrap().flush().unwrap();

        std::env::set_var("SMTP_PASSWORD_FILE", &empty);
        assert_eq!(EnvironmentProvider.get(GovernedSecret::SmtpPassword), None);

        // A path the process cannot read: reported at `error`, treated as unheld.
        std::env::set_var("SMTP_PASSWORD_FILE", "/nonexistent/path/that/is/not/there");
        assert_eq!(EnvironmentProvider.get(GovernedSecret::SmtpPassword), None);

        std::env::remove_var("SMTP_PASSWORD_FILE");
    }

    #[test]
    fn environment_provider_is_read_only() {
        assert!(!EnvironmentProvider.is_writable());
        assert_eq!(EnvironmentProvider.name(), "environment");
    }
}
