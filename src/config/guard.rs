//! The single-read-path guard (PMS-982).
//!
//! A configuration read anywhere in `src/` outside [`crate::config`] and the
//! entry points named below fails `cargo test --lib`. This is the half that
//! makes the seam real: `resolve_secret` already existed in `main.rs` and the
//! reads went around it, so the rule is enforced rather than remembered.
//!
//! It is a test in the crate rather than a new guard script and CI step,
//! matching what the repository already does for a rule of this shape
//! (`utils::net::tests::exactly_one_definition_in_the_crate`,
//! `repo_hygiene::the_former_client_repo_name_stays_gone`,
//! `billing::routes::finance_gate`).

/// A file that may read the environment directly, and why.
pub struct EntryPoint {
    /// Path relative to the crate root, with `/` separators.
    pub path: &'static str,
    /// Why this file cannot go through the provider. One stated reason per
    /// entry, matching the convention in `scripts/check-env-example.nu`.
    pub reason: &'static str,
}

/// The reads that go around the provider, each with its reason.
///
/// Two kinds only. A **bootstrap entry point** runs before an application
/// exists to configure (the host-side CLI, the role provisioner). A **provider
/// of record** is the one reader of its own selection variable, and a provider
/// cannot be built out of a value served by the thing it is being built for.
///
/// This is NOT a list of reads waiting to be migrated. There is no such list:
/// PMS-982 landed the seam and every read together, and the guard's own
/// `MIGRATED_READS` is empty with a test saying so.
pub const ENTRY_POINTS: &[EntryPoint] = &[
    EntryPoint {
        path: "src/bin/mokosh-bootstrap.rs",
        reason: "host-side one-shot CLI; it runs before, and outside, the server process that \
                 would resolve configuration, and reads .env.infisical directly",
    },
    EntryPoint {
        path: "src/cli/mod.rs",
        reason: "the same operator subcommands folded into the server binary (PMS-494), \
                 dispatched before a port is bound or a provider is chosen",
    },
    EntryPoint {
        path: "src/cli/providers.rs",
        reason: "the provider-status / provider-migrate / provider-purge subcommands (PMS-1012) \
                 read SECRET_BACKEND and INFISICAL_ADDRESS directly, the same way \
                 src/app_secrets/mod.rs and src/config/mod.rs do: they build providers ahead of \
                 any read path, so the machinery a provider is chosen and constructed FROM \
                 cannot itself be provider-served",
    },
    EntryPoint {
        path: "src/cli/verify.rs",
        reason: "the verify-providers subcommand (PMS-1013 follow-up) reproduces main's boot \
                 wiring for every capability, so it reads DATABASE_URL, MOKOSH_APP_DATABASE_URL \
                 and ENCRYPTION_KEY at construction the same way src/cli/providers.rs does: it \
                 is BUILDING the shared state a provider is chosen from",
    },
    EntryPoint {
        path: "src/db/provision.rs",
        reason: "self-provisions the split database roles from MOKOSH_ADMIN_DATABASE_URL before \
                 the pools exist (PMS-489), so it runs ahead of anything a provider needs",
    },
    EntryPoint {
        path: "src/secrets/mod.rs",
        reason: "the one reader of SECRET_BACKEND for the tenant tier: provider enablement is \
                 bootstrap configuration, and configuration that says where to find configuration \
                 cannot live inside what it locates",
    },
    EntryPoint {
        path: "src/app_secrets/mod.rs",
        reason: "the one reader of SECRET_BACKEND for the application tier (PMS-988), separate \
                 from the tenant tier's reader because the two tiers accept different provider \
                 sets and each is the entry point for its own tier's selection",
    },
    EntryPoint {
        path: "src/app_secrets/env.rs",
        reason: "the {NAME}_FILE compose-secret variables the app-tier environment provider \
                 reads are computed from GovernedSecret::name() (PMS-988), so they are not \
                 declared configuration keys; the environment provider is what a config-served \
                 declaration would have been built out of, so it reads env directly for the \
                 same reason SECRET_BACKEND does",
    },
    EntryPoint {
        path: "src/secrets/infisical.rs",
        reason: "the Infisical machine identity and address a secret provider is BUILT from; a \
                 provider cannot be constructed out of values served by itself",
    },
    EntryPoint {
        path: "src/storage/mod.rs",
        reason: "the one reader of STORAGE_BACKEND and of ATTACHMENT_DIR (PMS-910), the root a \
                 storage provider is built from, for the same reason as SECRET_BACKEND",
    },
    EntryPoint {
        path: "src/storage/s3.rs",
        reason: "the endpoint, bucket and credential an S3 provider is built from (PMS-958), \
                 read at construction like Infisical's",
    },
    EntryPoint {
        path: "src/utils/deployment.rs",
        reason: "MOKOSH_DEPLOYMENT_MODE supplies the DEFAULT PROVIDER per capability \
                 (PMS-1011), configuration itself included, so it is configuration that locates \
                 configuration and cannot be served by what it locates. Whether provider \
                 selection should itself come from a provider is PMS-987's question",
    },
    EntryPoint {
        path: "src/config/file.rs",
        reason: "the file configuration provider (PMS-987) reads CONFIG_FILE_DIR at \
                 construction; a provider cannot be built from a value served by itself, \
                 which is why CONFIG_FILE_DIR is a bootstrap key",
    },
    EntryPoint {
        path: "src/config/bunyip.rs",
        reason: "the Bunyip configuration provider (PMS-987) reads BUNYIP_CONFIG_URL, \
                 BUNYIP_CONFIG_CLIENT_ID and BUNYIP_CONFIG_CLIENT_SECRET at construction; \
                 the machine credential a provider authenticates with cannot be served by \
                 what it authenticates for",
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Reads that were migrated onto the provider and are exempt anyway.
    ///
    /// EMPTY, and it stays empty. PMS-982 deliberately landed the seam and
    /// every read in one change rather than shipping an allowlist that empties
    /// later, because an allowlist that empties later is one that does not.
    /// Adding an entry here means writing down why a feature reads
    /// configuration the provider cannot see, which is the conversation this
    /// guard exists to force. The shape is
    /// `billing::routes::finance_gate::UNGATED`'s, for the same reason.
    const MIGRATED_READS: &[&str] = &[];

    fn crate_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Every `.rs` file under `src/`, as a `/`-separated path relative to the
    /// crate root.
    fn source_files() -> Vec<String> {
        let root = crate_root();
        let mut files = Vec::new();
        let mut pending = vec![root.join("src")];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("read source directory") {
                let path = entry.expect("read directory entry").path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(relative(&root, &path));
                }
            }
        }
        // `read_dir` order is filesystem-dependent; sort so a failure names the
        // same list every run.
        files.sort();
        files
    }

    fn relative(root: &Path, path: &Path) -> String {
        path.strip_prefix(root)
            .expect("a source file lives under the crate root")
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// The needle, assembled at run time so this file is not itself a hit. It
    /// matches the read forms only: `env::set_var` and `env::remove_var` do
    /// not contain it, because mutating the environment is what a test does
    /// before calling `crate::config::refresh`.
    fn needle() -> String {
        format!("env::{}", "var")
    }

    /// The acceptance criterion in executable form: a configuration read added
    /// outside the provider and `ENTRY_POINTS` fails the build.
    #[test]
    fn every_env_read_goes_through_the_provider() {
        let needle = needle();
        let root = crate_root();
        let mut offenders: Vec<String> = Vec::new();
        let mut entry_point_reads = 0usize;

        for file in source_files() {
            let source = std::fs::read_to_string(root.join(&file)).expect("read source file");
            if !source.contains(&needle) {
                continue;
            }
            // ENTRY_POINTS is checked BEFORE the `src/config/` blanket skip
            // so a sub-module inside the provider can be a documented entry
            // point rather than being lost in the prefix (PMS-987 sub-provider
            // files). The blanket skip below then covers `mod.rs`, `env.rs`
            // and any other read that legitimately lives beside the seam
            // itself.
            if ENTRY_POINTS.iter().any(|entry| entry.path == file) {
                entry_point_reads += 1;
                continue;
            }
            // The provider itself, and the registry beside it, are where the
            // reads are supposed to be.
            if file.starts_with("src/config/") {
                continue;
            }
            if MIGRATED_READS.contains(&file.as_str()) {
                continue;
            }
            offenders.push(file);
        }

        assert!(
            offenders.is_empty(),
            "these files read the environment directly instead of through \
             crate::config::get: {offenders:?}. Declare the key in \
             src/config/registry.rs and read it with crate::config::get, or add \
             the file to config::guard::ENTRY_POINTS with the reason it cannot"
        );
        assert_eq!(
            entry_point_reads,
            ENTRY_POINTS.len(),
            "an ENTRY_POINTS entry no longer reads the environment, so it is stale \
             documentation of a read that moved; drop it"
        );
    }

    /// An entry that names a file that does not exist permits nothing and
    /// documents nothing, and it silently re-permits the bypass if a file with
    /// that path comes back.
    #[test]
    fn every_entry_point_names_a_real_file_and_states_a_reason() {
        let root = crate_root();
        for entry in ENTRY_POINTS {
            assert!(
                root.join(entry.path).is_file(),
                "{} is in ENTRY_POINTS but does not exist",
                entry.path
            );
            assert!(
                entry.reason.len() > 30,
                "{} needs a stated reason, not a placeholder",
                entry.path
            );
        }
    }

    /// The deployment mode is named explicitly, because it is the one entry
    /// that is neither a host-side CLI nor a provider of record: it is what
    /// chooses the providers, configuration's included.
    #[test]
    fn the_deployment_mode_is_an_entry_point_with_its_reason() {
        let entry = ENTRY_POINTS
            .iter()
            .find(|e| e.path == "src/utils/deployment.rs")
            .expect("MOKOSH_DEPLOYMENT_MODE must be an entry point");
        assert!(
            entry.reason.contains("MOKOSH_DEPLOYMENT_MODE"),
            "{}",
            entry.reason
        );
        assert!(entry.reason.contains("PMS-1011"), "{}", entry.reason);
    }

    /// And the migrated-read allowlist stays empty until somebody argues
    /// otherwise, the way `finance_gate::UNGATED` does.
    #[test]
    fn there_is_no_allowlist_of_migrated_reads() {
        assert!(
            MIGRATED_READS.is_empty(),
            "the seam shipped with no allowlist of migrated reads; one was added \
             without this test being revisited: {MIGRATED_READS:?}"
        );
    }
}
