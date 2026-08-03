//! Dev-environment Infisical bootstrap.
//!
//! Calls [`bootstrap_infisical`] against an already-running Infisical
//! instance (typically the `dev-mokosh-infisical` container) and persists
//! the resulting `INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID`,
//! `INFISICAL_CLIENT_SECRET` and `INFISICAL_ENVIRONMENT` values into a
//! `.env`-style file so the dev stack picks them up on restart.

use std::fs;
use std::path::{Path, PathBuf};

use tracing::info;

use crate::infisical::{bootstrap_infisical, BootstrapInput, BootstrapOutput};
use crate::utils::error::AppError;

/// Inputs to the dev bootstrap flow. Maps closely onto the CLI flags so the
/// subcommand handler can build this directly.
#[derive(Debug, Clone)]
pub struct DevBootstrapConfig {
    /// Base URL of the Infisical instance to bootstrap.
    pub url: String,
    /// Path to the `.env` file to update with the resulting credentials.
    pub env_file: PathBuf,
    /// Admin user details and project/identity names, fed straight into
    /// [`bootstrap_infisical`].
    pub input: BootstrapInput,
}

/// Run the dev bootstrap. Returns the same output as
/// [`bootstrap_infisical`], so the caller can also print it for the user.
pub async fn run_dev_bootstrap(config: DevBootstrapConfig) -> Result<BootstrapOutput, AppError> {
    info!(
        "Bootstrapping Infisical at {} (writing creds to {})",
        config.url,
        config.env_file.display()
    );

    let output = bootstrap_infisical(&config.url, &config.input).await?;

    // Deliberately do NOT write INFISICAL_BASE_URL: the URL used here is
    // how the host CLI reaches Infisical (e.g. `http://localhost:28002`),
    // which is not the URL the Mokosh service inside the compose network
    // uses (`http://infisical:8080`). The correct in-network URL is carried
    // in the generated `.env` (from `.env.example`); we only fill in the
    // secret-bearing fields the user could not pre-populate.
    //
    // Admin email and password are persisted as a dev convenience so the
    // operator can later log into Infisical's web UI without re-supplying
    // them. `.env` is gitignored. This is *not* a pattern to use in
    // production; for prod, treat the admin password as one-shot and store
    // it in a real secret store.
    upsert_env_file(
        &config.env_file,
        &[
            ("INFISICAL_PROJECT_ID", output.project_id.as_str()),
            ("INFISICAL_CLIENT_ID", output.client_id.as_str()),
            ("INFISICAL_CLIENT_SECRET", output.client_secret.as_str()),
            ("INFISICAL_ENVIRONMENT", output.environment.as_str()),
            ("INFISICAL_ADMIN_EMAIL", config.input.admin_email.as_str()),
            (
                "INFISICAL_ADMIN_PASSWORD",
                config.input.admin_password.as_str(),
            ),
        ],
    )?;

    Ok(output)
}

/// Replace any existing matching `KEY=...` lines in `path` with the new
/// values, append missing keys at the end, preserve everything else
/// (comments, blank lines, unrelated assignments) verbatim.
///
/// Creates the file if it doesn't exist. The file gets a trailing newline
/// either way.
fn upsert_env_file(path: &Path, updates: &[(&str, &str)]) -> Result<(), AppError> {
    let existing = if path.exists() {
        fs::read_to_string(path)
            .map_err(|e| AppError::Internal(format!("Failed to read {}: {}", path.display(), e)))?
    } else {
        String::new()
    };

    let mut lines: Vec<String> = existing.lines().map(|s| s.to_string()).collect();
    let mut updated = vec![false; updates.len()];

    for line in lines.iter_mut() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(eq) = trimmed.find('=') else {
            continue;
        };
        let key = &trimmed[..eq];
        for (idx, (k, v)) in updates.iter().enumerate() {
            if !updated[idx] && key == *k {
                *line = format!("{}={}", k, v);
                updated[idx] = true;
                break;
            }
        }
    }

    for (idx, (k, v)) in updates.iter().enumerate() {
        if !updated[idx] {
            lines.push(format!("{}={}", k, v));
        }
    }

    let mut content = lines.join("\n");
    if !content.ends_with('\n') {
        content.push('\n');
    }
    fs::write(path, content)
        .map_err(|e| AppError::Internal(format!("Failed to write {}: {}", path.display(), e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn creates_new_file_when_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".env");
        upsert_env_file(&path, &[("FOO", "bar"), ("BAZ", "qux")]).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "FOO=bar\nBAZ=qux\n");
    }

    #[test]
    fn replaces_existing_keys_in_place() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".env");
        fs::write(
            &path,
            "# Header comment\nFOO=old\n\nOTHER=keep\nBAZ=stale\n",
        )
        .unwrap();
        upsert_env_file(&path, &[("FOO", "new"), ("BAZ", "fresh")]).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(
            content,
            "# Header comment\nFOO=new\n\nOTHER=keep\nBAZ=fresh\n"
        );
    }

    #[test]
    fn appends_keys_not_present() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".env");
        fs::write(&path, "FOO=existing\n").unwrap();
        upsert_env_file(&path, &[("BAR", "added")]).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "FOO=existing\nBAR=added\n");
    }

    #[test]
    fn ignores_commented_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".env");
        fs::write(&path, "# FOO=commented-out\nBAR=other\n").unwrap();
        upsert_env_file(&path, &[("FOO", "real")]).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "# FOO=commented-out\nBAR=other\nFOO=real\n");
    }

    #[test]
    fn preserves_value_with_equals_signs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".env");
        upsert_env_file(&path, &[("URL", "postgres://user:p=ssw=rd@host:5432/db")]).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "URL=postgres://user:p=ssw=rd@host:5432/db\n");
    }
}
