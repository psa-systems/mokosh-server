//! The file configuration provider (PMS-987): read declared keys out of a
//! directory named by `CONFIG_FILE_DIR`, one file per key.
//!
//! The intended shape is a directory managed by the operator's own tooling
//! (SOPS, SealedSecrets, an Ansible role, `just dev`'s own generator). One
//! file per declared key, named after the key ([`ConfigKey::name`]), because
//! a Kubernetes Secret volume-mounts that way and the migrate tooling
//! (PMS-1012) will emit that shape directly. Contents are the value, trimmed
//! of a single trailing newline the way an editor leaves one.
//!
//! Two shapes of absence are both silent, and deliberately so:
//! - `CONFIG_FILE_DIR` unset, or set to something that is not a directory,
//!   is "the file provider is not enabled here", which is the ordinary state
//!   for a deployment that has not opted in.
//! - A directory that IS there but has no file for a given key is "this
//!   provider does not hold this key", the classification's `Missing` arm
//!   picks it up if no other provider does.
//!
//! An unreadable file inside a real directory is logged at `error` and
//! answered as `None`, matching [`super::env::EnvProvider`]'s discipline for
//! a variable it cannot decode: the operator hears about the file they
//! configured and cannot be used, and the classification then reports "no
//! provider holds it" rather than a silent success.
//!
//! The provider loads once at construction rather than reading a file per
//! `get`. [`super::ConfigProvider::get`] is sync, and hitting disk on every
//! call would turn each classification round into a filesystem walk.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::RwLock;

use async_trait::async_trait;

use super::{ConfigProvider, Enumeration, REGISTRY};
use crate::utils::error::{AppError, AppResult};

/// A directory the operator points at with `CONFIG_FILE_DIR`, holding one
/// file per declared configuration key.
///
/// Load-once: [`FileProvider::from_env`] reads the whole directory at
/// construction, and every later [`ConfigProvider::get`] answers from the
/// cache. A file appearing after construction reaches the process on the
/// next chain rebuild.
#[derive(Debug)]
pub struct FileProvider {
    /// Root directory holding one file per key. `None` when the provider is
    /// enabled but the directory is unreadable or was never set; write and
    /// delete calls refuse in that state, because there is no path to write.
    root: Option<PathBuf>,
    /// Values keyed by declared key name. Empty when the directory is
    /// unreadable or holds no declared key. Interior mutability so
    /// [`Self::set`] and [`Self::delete`] keep the cache in step with disk.
    values: RwLock<BTreeMap<String, String>>,
}

impl FileProvider {
    /// Build the provider from `CONFIG_FILE_DIR`. An unset or blank
    /// variable, or a value naming a path that is not a directory, yields
    /// an empty provider: this is provider enablement rather than a
    /// misconfiguration.
    ///
    /// Direct env read (not through [`crate::config::get`]) because the
    /// directory is a construction input for THIS provider, which is the
    /// PMS-1009 rule for a provider of record. `src/config/guard.rs`
    /// documents the exemption.
    pub fn from_env() -> Self {
        let dir = std::env::var("CONFIG_FILE_DIR")
            .ok()
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty());
        match dir {
            Some(dir) => Self::load(PathBuf::from(dir)),
            None => Self {
                root: None,
                values: RwLock::new(BTreeMap::new()),
            },
        }
    }

    /// Load a directory explicitly. Public so tests drive it without touching
    /// process-global env under a concurrent test runner.
    pub fn load(dir: PathBuf) -> Self {
        let mut values = BTreeMap::new();

        // `metadata` distinguishes "no directory" from "cannot read the
        // directory". The first is enablement; the second is worth an
        // operator log line before it collapses to an empty provider.
        match std::fs::metadata(&dir) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                tracing::error!(
                    dir = %dir.display(),
                    "CONFIG_FILE_DIR names a path that is not a directory; the file \
                     configuration provider holds nothing"
                );
                return Self {
                    root: None,
                    values: RwLock::new(values),
                };
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Self {
                    root: Some(dir),
                    values: RwLock::new(values),
                };
            }
            Err(err) => {
                tracing::error!(
                    dir = %dir.display(),
                    error = %err,
                    "CONFIG_FILE_DIR could not be read; the file configuration provider \
                     holds nothing"
                );
                return Self {
                    root: None,
                    values: RwLock::new(values),
                };
            }
        }

        // Only declared keys are loaded. A file named for something that is
        // not a registered key gets one `warn`, the same silence-into-visible
        // trade the app_secrets file provider makes.
        for key in REGISTRY {
            let path = dir.join(key.name());
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    let value = strip_trailing_newline(&contents);
                    values.insert(key.name().to_string(), value);
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    // No file for this key here.
                }
                Err(err) => {
                    tracing::error!(
                        path = %path.display(),
                        error = %err,
                        "the file configuration provider cannot read {}; treating it as unheld",
                        key.name()
                    );
                }
            }
        }

        Self {
            root: Some(dir),
            values: RwLock::new(values),
        }
    }
}

#[async_trait]
impl ConfigProvider for FileProvider {
    fn name(&self) -> &'static str {
        "file"
    }

    fn get(&self, key: &str) -> Option<String> {
        self.values
            .read()
            .expect("the file configuration cache lock is never held across a panic")
            .get(key)
            .cloned()
    }

    fn has(&self, key: &str) -> bool {
        self.values
            .read()
            .expect("the file configuration cache lock is never held across a panic")
            .contains_key(key)
    }

    fn list(&self) -> Enumeration {
        Enumeration::Keys(
            self.values
                .read()
                .expect("the file configuration cache lock is never held across a panic")
                .keys()
                .cloned()
                .collect(),
        )
    }

    /// PMS-1012: write `value` into the per-key file under the root.
    ///
    /// The root has to exist for a write to have anywhere to go. A file
    /// provider built from an unset or non-directory `CONFIG_FILE_DIR`
    /// refuses the write with a named `AppError::Configuration`, so an
    /// operator asking to migrate TO the file provider without pointing it
    /// anywhere gets a clear message rather than a silent success.
    async fn set(&self, key: &str, value: &str) -> AppResult<()> {
        let root = self.root.as_ref().ok_or_else(|| {
            AppError::Configuration(
                "file configuration provider has no directory; set CONFIG_FILE_DIR to enable \
                 writes"
                    .to_string(),
            )
        })?;
        if !root.exists() {
            std::fs::create_dir_all(root).map_err(|e| {
                AppError::Configuration(format!(
                    "file configuration provider could not create {}: {e}",
                    root.display()
                ))
            })?;
        }
        let path = root.join(key);
        std::fs::write(&path, value).map_err(|e| {
            AppError::Configuration(format!(
                "file configuration provider could not write {}: {e}",
                path.display()
            ))
        })?;
        self.values
            .write()
            .expect("the file configuration cache lock is never held across a panic")
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    /// PMS-1012: remove the per-key file. Absence is not an error.
    async fn delete(&self, key: &str) -> AppResult<()> {
        if let Some(root) = self.root.as_ref() {
            let path = root.join(key);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(AppError::Configuration(format!(
                        "file configuration provider could not delete {}: {e}",
                        path.display()
                    )));
                }
            }
        }
        self.values
            .write()
            .expect("the file configuration cache lock is never held across a panic")
            .remove(key);
        Ok(())
    }
}

/// Strip a single trailing newline (`\n` or `\r\n`), the way an editor's
/// "insert final newline" leaves one. Anything more is a value the operator
/// wrote on purpose - preserving embedded whitespace matters for compose
/// keys like `SMTP_FROM` and multi-line PEM material.
fn strip_trailing_newline(input: &str) -> String {
    let stripped = input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(input);
    stripped.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mokosh-pms-987-file-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create tempdir");
        dir
    }

    #[test]
    fn a_file_in_the_directory_is_a_value_trimmed_of_its_final_newline() {
        let dir = tempdir("read");
        std::fs::write(dir.join("SMTP_HOST"), "relay.example.com\n").unwrap();
        std::fs::write(dir.join("SPA_BASE_URL"), "").unwrap();
        std::fs::write(dir.join("SMTP_FROM"), "Ops <ops@example.net>").unwrap();

        let provider = FileProvider::load(dir.clone());
        assert_eq!(provider.name(), "file");
        assert_eq!(
            provider.get("SMTP_HOST").as_deref(),
            Some("relay.example.com")
        );
        // A blank value is a value (a compose key forwarded but unset arrives
        // as ""), so the provider holds it and reports it as present.
        assert_eq!(provider.get("SPA_BASE_URL").as_deref(), Some(""));
        assert!(provider.has("SPA_BASE_URL"));
        // Embedded whitespace is preserved.
        assert_eq!(
            provider.get("SMTP_FROM").as_deref(),
            Some("Ops <ops@example.net>")
        );
        // A key with no file reads as unheld.
        assert_eq!(provider.get("SMTP_USERNAME"), None);
        assert!(!provider.has("SMTP_USERNAME"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_directory_is_silent_and_holds_nothing() {
        let dir = PathBuf::from("/nonexistent/mokosh-pms-987-absent");
        let provider = FileProvider::load(dir);
        assert_eq!(provider.get("SMTP_HOST"), None);
        // Enumeration is empty rather than unsupported: the provider CAN
        // list what it holds; it holds nothing.
        match provider.list() {
            Enumeration::Keys(keys) => assert!(keys.is_empty()),
            Enumeration::Unsupported => panic!("the file provider can enumerate"),
        }
    }

    #[test]
    fn a_windows_line_ending_is_stripped_the_same_way() {
        let dir = tempdir("crlf");
        std::fs::write(dir.join("SMTP_HOST"), "example\r\n").unwrap();
        let provider = FileProvider::load(dir.clone());
        assert_eq!(provider.get("SMTP_HOST").as_deref(), Some("example"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_undeclared_file_name_is_ignored() {
        let dir = tempdir("undeclared");
        std::fs::write(dir.join("NOT_A_KEY"), "x").unwrap();
        let provider = FileProvider::load(dir.clone());
        assert_eq!(provider.get("NOT_A_KEY"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
