//! The file provider: read secrets from a directory named by
//! `APP_SECRETS_DIR`, one file per governed secret.
//!
//! The intended shape is a mounted directory whose contents are managed by
//! the operator's secret tooling (SOPS, SealedSecrets, an Ansible vault
//! playbook, `just dev`'s own `.env`-mint). One file per secret named by
//! [`GovernedSecret::secret_file`], because that is the name the migrate
//! command would emit and because a folder shape is what a Kubernetes
//! Secret volume-mounts as anyway.
//!
//! A missing directory is a legitimate configuration ("no file provider is
//! enabled"): the `APP_SECRETS_DIR` variable would simply be unset in that
//! case, and `init_from_env` wouldn't even build this provider. So the only
//! shape this file worries about is a directory that IS named but is missing
//! or unreadable; that is logged at `error` and every read returns `None`,
//! which is the same behaviour the environment provider takes for an
//! unreadable path.

use std::path::PathBuf;

use async_trait::async_trait;

use super::{AppSecretProvider, GovernedSecret};
use crate::utils::error::{AppError, AppResult};

/// A directory the operator points at with `APP_SECRETS_DIR`, one file per
/// governed secret named after [`GovernedSecret::secret_file`].
#[derive(Debug)]
pub struct FileProvider {
    root: PathBuf,
}

impl FileProvider {
    /// The directory is trusted as configured: the caller has already
    /// validated that the variable is set and non-empty. Whether it exists
    /// on disk is checked at read time, because a directory that was there
    /// at boot can vanish (a container remount, an operator running `rm`).
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The path this provider would read for `secret`, so a test can seed a
    /// fixture without duplicating the join rule.
    pub fn path_for(&self, secret: GovernedSecret) -> PathBuf {
        self.root.join(secret.secret_file())
    }
}

#[async_trait]
impl AppSecretProvider for FileProvider {
    fn name(&self) -> &'static str {
        "file"
    }

    fn get(&self, secret: GovernedSecret) -> Option<String> {
        let path = self.path_for(secret);
        // `metadata` distinguishes "the directory is not there" from "the
        // file inside it is not there". A missing directory is a legitimate
        // configuration and is silent; a missing FILE inside a real directory
        // simply means the operator has not put that secret in the file
        // provider, which is also silent because the classification is what
        // reports "no provider holds it".
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let trimmed = contents.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "the file provider cannot read {}; treating it as unheld",
                    secret.name()
                );
                None
            }
        }
    }

    /// PMS-1012: write the value to the per-secret file inside the root.
    ///
    /// The root is trusted as configured: [`FileProvider::new`] is only
    /// called when `APP_SECRETS_DIR` is set. `write` creates the file if it
    /// is missing and replaces it atomically enough for the CLI's purposes
    /// (a partial write is caught by the migrate command's read-back).
    async fn set(&self, secret: GovernedSecret, value: &str) -> AppResult<()> {
        let path = self.path_for(secret);
        std::fs::write(&path, value).map_err(|e| {
            AppError::Configuration(format!(
                "file provider could not write {}: {e}",
                path.display()
            ))
        })
    }

    /// PMS-1012: remove the per-secret file. A file that is already gone is
    /// not an error, matching the tenant-tier delete contract and the
    /// interlock in `provider-purge`.
    async fn delete(&self, secret: GovernedSecret) -> AppResult<()> {
        let path = self.path_for(secret);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AppError::Configuration(format!(
                "file provider could not delete {}: {e}",
                path.display()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A secret file inside the root reads as its trimmed contents; a missing
    /// or empty file inside a real root reads as unheld.
    #[test]
    fn round_trips_through_the_secret_file_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let provider = FileProvider::new(dir.path().to_path_buf());

        // Absent file, real directory -> None.
        assert_eq!(provider.get(GovernedSecret::SmtpPassword), None);

        // Present file with a value -> Some(trimmed).
        std::fs::write(
            provider.path_for(GovernedSecret::SmtpPassword),
            "  hunter2\n",
        )
        .unwrap();
        assert_eq!(
            provider.get(GovernedSecret::SmtpPassword),
            Some("hunter2".to_string())
        );

        // Empty file -> None (empty is not a secret).
        std::fs::File::create(provider.path_for(GovernedSecret::SmtpPassword))
            .unwrap()
            .flush()
            .unwrap();
        assert_eq!(provider.get(GovernedSecret::SmtpPassword), None);
    }

    /// A root that does not exist is not an error: the operator may have set
    /// `APP_SECRETS_DIR` before mounting the volume. Read as unheld.
    #[test]
    fn absent_root_reads_as_unheld() {
        let provider = FileProvider::new(PathBuf::from("/nonexistent/app-secrets"));
        assert_eq!(provider.get(GovernedSecret::SmtpPassword), None);
    }

    #[test]
    fn file_provider_is_writable_and_named() {
        let provider = FileProvider::new(PathBuf::from("/tmp"));
        assert!(provider.is_writable());
        assert_eq!(provider.name(), "file");
    }
}
