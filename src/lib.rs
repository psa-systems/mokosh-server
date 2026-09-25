//! Mokosh Server - library
//!
//! Axum-based REST API for Mokosh Server.

pub mod api;
pub mod app_secrets;
pub mod cli;
pub mod config;
pub mod db;
pub mod infisical;
pub mod modules;
pub mod pdf;
pub mod providers;
pub mod scheduler;
pub mod secrets;
pub mod storage;
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
    ///
    /// PMS-1304: `mokosh-apps` is not build output - it is the SPA repository
    /// checked out beside this one by `check.yml` so `check-route-consumers.nu`
    /// can compare mounted routes against SPA callers. The runner places it
    /// under `../mokosh-apps` but Actions can materialise the relative path
    /// inside `GITHUB_WORKSPACE` (this manifest dir) as `./mokosh-apps`, at
    /// which point every hygiene scan below descends into another repo's
    /// tree. That is what turned a green `check-web` recipe into a red
    /// `the_former_client_repo_name_stays_gone` on every PR that touched
    /// nothing here at all, so `mokosh-apps` is skipped exactly as the other
    /// non-source directories are.
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
        "mokosh-apps",
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

    /// PMS-1254: a database-backed integration test is `#[mokosh_test]`.
    ///
    /// The attribute clones each test's database from one migrated template
    /// instead of applying all 243 migrations into it, which is the whole
    /// saving. A single case left on the old attribute would quietly take the
    /// slow path AND, because it migrates a database of its own, prove nothing
    /// about the template the rest ran against, so the ban is enforced here
    /// rather than left to the conversion having been complete on the day.
    ///
    /// Only the ATTRIBUTE is banned. The two crates under `crates/mokosh-test*`
    /// explain at length what they replaced and are not scanned, and prose
    /// elsewhere naming the old attribute is history rather than a call site.
    ///
    /// The needle is assembled at runtime so this file is not itself a hit.
    #[test]
    fn every_database_backed_test_takes_the_template_attribute() {
        let needle = format!("#[sq{}::test", "lx");
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
        let mut hits: Vec<String> = Vec::new();
        let mut pending = vec![dir];

        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("read the integration test directory") {
                let entry = entry.expect("read directory entry");
                let path = entry.path();
                if entry.file_type().expect("read entry type").is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("read an integration test");
                for (number, line) in source.lines().enumerate() {
                    if line.contains(&needle) {
                        hits.push(format!("{}:{}", path.display(), number + 1));
                    }
                }
            }
        }

        hits.sort();
        assert!(
            hits.is_empty(),
            "a database-backed test is #[mokosh_test], which clones the \
             migrated template (PMS-1254); these still migrate a database of \
             their own: {hits:#?}"
        );
    }

    /// PMS-1394: the supported and unsupported test profiles are complements.
    ///
    /// `.config/nextest.toml` splits the Postgres-backed suite in two: the `ci`
    /// profile is what every pull request runs, and `unsupported` is what
    /// `integration-unsupported.yml` runs weekly. The split is expressed as a
    /// `default-filter` on each, and the two are only a split as long as they
    /// are exact complements. Edit one and forget the other and a suite falls
    /// into NEITHER, which is the one failure mode with no signal at all: no
    /// job fails, no case is reported, and the coverage is simply gone.
    ///
    /// So this reads the two filters back and requires that one is the other
    /// with `not ` in front. It is a text comparison on purpose: parsing
    /// nextest's filter language here would be a second implementation of it,
    /// and the convention that keeps the check meaningful is that the pair is
    /// written as `X` and `not X` rather than as two expressions that happen to
    /// mean the same thing.
    #[test]
    fn the_supported_and_unsupported_test_profiles_are_complements() {
        let config = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(".config")
                .join("nextest.toml"),
        )
        .expect("read .config/nextest.toml");

        let filter_for = |profile: &str| -> String {
            let header = format!("[profile.{profile}]");
            let start = config
                .find(&header)
                .unwrap_or_else(|| panic!("no {header} in .config/nextest.toml"));
            let body = &config[start + header.len()..];
            // Stop at the next table so a filter cannot be read out of a
            // neighbouring profile.
            let end = body
                .find(
                    "
[",
                )
                .unwrap_or(body.len());
            body[..end]
                .lines()
                .find_map(|line| line.trim().strip_prefix("default-filter"))
                .map(|rest| {
                    rest.trim_start_matches([' ', '='])
                        .trim()
                        .trim_matches('\'')
                        .trim_matches('"')
                        .to_string()
                })
                .unwrap_or_else(|| panic!("[profile.{profile}] declares no default-filter"))
        };

        let supported = filter_for("ci");
        let unsupported = filter_for("unsupported");
        assert_eq!(
            supported,
            format!("not {unsupported}"),
            "the `ci` and `unsupported` default-filters are not complements, so a              suite can be in neither and run nowhere: ci = {supported:?},              unsupported = {unsupported:?}"
        );
    }

    /// PMS-1010: a selectable implementation is a PROVIDER, and the two words
    /// it replaced do not come back.
    ///
    /// One concept had three names before that issue - the code said store, the
    /// architecture said provider, and the tracker said backend - and a reader
    /// could not tell whether they were three concepts. Restating the rule in
    /// prose is what let the split survive three modules, so it is enforced
    /// here: every item declared under `src/secrets/` and `src/storage/` has to
    /// be named for the word that won.
    ///
    /// Only DECLARATIONS are checked, so `SECRET_BACKEND` and `STORAGE_BACKEND`
    /// stay exactly as they are. They are operator-facing, and renaming them
    /// would break every existing deployment for a vocabulary change. Prose is
    /// not checked either: "an S3-compatible object store" is what that product
    /// is called.
    ///
    /// The needles are assembled rather than written, because this file would
    /// otherwise be a hit on itself.
    #[test]
    fn the_provider_seams_declare_no_store_and_no_backend() {
        let retired = [format!("st{}", "ore"), format!("back{}", "end")];
        // Everything that introduces a name a reader has to learn.
        const KEYWORDS: &[&str] = &[
            "mod ", "struct ", "enum ", "trait ", "type ", "fn ", "union ", "const ", "static ",
        ];

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut hits: Vec<String> = Vec::new();
        let mut pending = vec![root.join("src/secrets"), root.join("src/storage")];

        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("read a provider module directory") {
                let entry = entry.expect("read directory entry");
                let path = entry.path();
                if entry.file_type().expect("read entry type").is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let relative = path
                    .strip_prefix(root)
                    .expect("path came from this walk")
                    .to_string_lossy()
                    .replace('\\', "/");
                let source = std::fs::read_to_string(&path).expect("read a provider source file");

                for line in source.lines() {
                    let code = line.trim_start();
                    if code.starts_with("//") {
                        continue;
                    }
                    for keyword in KEYWORDS {
                        let Some(rest) = code.split(keyword).nth(1) else {
                            continue;
                        };
                        let declared: String = rest
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect::<String>()
                            .to_ascii_lowercase();
                        if retired.iter().any(|word| declared.contains(word.as_str())) {
                            hits.push(format!("{relative}: {}", code.trim_end()));
                        }
                    }
                }
            }
        }

        hits.sort();
        hits.dedup();
        assert!(
            hits.is_empty(),
            "a selectable implementation is a provider (PMS-1010); these \
             declarations still use the words it replaced: {hits:#?}"
        );
    }
}
