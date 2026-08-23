//! Mokosh Server - library
//!
//! Axum-based REST API for Mokosh Server.

pub mod api;
pub mod cli;
pub mod db;
pub mod infisical;
pub mod modules;
pub mod scheduler;
pub mod utils;
pub mod version;
pub mod version_check;

pub use db::Database;
pub use modules::auth::{AuthState, CurrentUser};
pub use utils::error::{AppError, AppResult};
pub use version::VersionInfo;

#[cfg(test)]
mod repo_hygiene {
    /// Build output and local scratch, never tracked. Everything else under the
    /// manifest directory is repository content and is scanned.
    const SKIP_DIRS: &[&str] = &[
        ".auth",
        ".claude",
        ".git",
        ".idea",
        "For AI",
        "blob-report",
        "data",
        "gen",
        "logs",
        "node_modules",
        "playwright-report",
        "secrets",
        "target",
        "test-results",
        "tmp",
    ];

    /// The client repository is `mokosh-apps`; its former name resolves to
    /// nothing. Three doc audits reported the same stale set before PMS-856
    /// swept it, so the ban is enforced here rather than restated in prose. The
    /// needle is assembled at runtime so this file is not itself a hit.
    #[test]
    fn the_former_client_repo_name_stays_gone() {
        let needle = format!("mokosh-{}", "clients");
        let mut hits: Vec<std::path::PathBuf> = Vec::new();
        let mut pending = vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))];

        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("read repository directory") {
                let entry = entry.expect("read directory entry");
                let kind = entry.file_type().expect("read directory entry type");
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();

                if kind.is_dir() {
                    if !SKIP_DIRS.contains(&name.as_str()) {
                        pending.push(path);
                    }
                    continue;
                }
                // Symlinks are skipped (nothing tracked here is one) and so are
                // the gitignored dotenv files, whose values are local config.
                if !kind.is_file() || (name.starts_with(".env") && name != ".env.example") {
                    continue;
                }

                let bytes = std::fs::read(&path).expect("read repository file");
                if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                    hits.push(path);
                }
            }
        }

        hits.sort();
        assert!(
            hits.is_empty(),
            "the client repository is named mokosh-apps; these files still name \
             the one it replaced: {hits:?}"
        );
    }
}
