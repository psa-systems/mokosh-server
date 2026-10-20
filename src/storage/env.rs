//! PMS-1317: the storage variables an operator sets.
//!
//! Every storage setting is `STORAGE_`-prefixed. Before PMS-1317 they were
//! `ATTACHMENT_DIR`, `STORAGE_BACKEND` and six bare `S3_*`; the rename landed
//! together with a one-release alias grace period so a deployment whose
//! compose file lived in another repository could migrate independently.
//!
//! PMS-1443: the alias grace is over. Setting an old name no longer silently
//! supplies a value — the server refuses to boot and the error names the
//! replacement so the operator can edit the compose file. The `deprecated`
//! field on [`StorageVar`] is kept because `check_boot_env` reads it to
//! build the refusal message; `resolve` only ever consults `var.name`.

/// A storage setting: the name to use, and the name that used to be used.
///
/// `deprecated: None` marks a setting that never had an older name, so the
/// table stays the whole list of storage variables rather than only the renamed
/// ones - which is what makes it answer "what does storage read" for an
/// operator, and what `provider-status` reports from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageVar {
    pub name: &'static str,
    pub deprecated: Option<&'static str>,
    /// One line for `provider-status` and `.env.example`, so the description
    /// an operator reads and the one the code carries are the same string.
    pub summary: &'static str,
    /// Whether the value is a credential. A credential is reported as set or
    /// unset and never printed, the rule `GovernedSecret` already follows.
    pub secret: bool,
}

/// Which provider serves stored objects.
pub const PROVIDER: StorageVar = StorageVar {
    name: "STORAGE_PROVIDER",
    deprecated: Some("STORAGE_BACKEND"),
    summary: "which provider stores objects: local or s3",
    secret: false,
};

/// The root every stored object hangs off, for the local provider.
pub const ROOT: StorageVar = StorageVar {
    name: "STORAGE_ROOT",
    deprecated: Some("ATTACHMENT_DIR"),
    summary: "filesystem root for the local provider; every stored object hangs off it",
    secret: false,
};

pub const S3_ENDPOINT: StorageVar = StorageVar {
    name: "STORAGE_S3_ENDPOINT",
    deprecated: Some("S3_ENDPOINT"),
    summary: "S3-compatible endpoint, required when the provider is s3",
    secret: false,
};

pub const S3_BUCKET: StorageVar = StorageVar {
    name: "STORAGE_S3_BUCKET",
    deprecated: Some("S3_BUCKET"),
    summary: "bucket stored objects are written to",
    secret: false,
};

pub const S3_REGION: StorageVar = StorageVar {
    name: "STORAGE_S3_REGION",
    deprecated: Some("S3_REGION"),
    summary: "region named in the signature; defaults to us-east-1",
    secret: false,
};

pub const S3_PATH_STYLE: StorageVar = StorageVar {
    name: "STORAGE_S3_PATH_STYLE",
    deprecated: Some("S3_PATH_STYLE"),
    summary: "true for {host}/{bucket}/{key}, false for {bucket}.{host}/{key}",
    secret: false,
};

pub const S3_ACCESS_KEY_ID: StorageVar = StorageVar {
    name: "STORAGE_S3_ACCESS_KEY_ID",
    deprecated: Some("S3_ACCESS_KEY_ID"),
    summary: "access key id for the bucket",
    secret: true,
};

pub const S3_SECRET_ACCESS_KEY: StorageVar = StorageVar {
    name: "STORAGE_S3_SECRET_ACCESS_KEY",
    deprecated: Some("S3_SECRET_ACCESS_KEY"),
    summary: "secret access key for the bucket",
    secret: true,
};

/// Every storage variable, in the order `.env.example` and `provider-status`
/// list them: the two that apply whatever the provider is, then the S3 block.
pub const ALL: &[StorageVar] = &[
    PROVIDER,
    ROOT,
    S3_ENDPOINT,
    S3_BUCKET,
    S3_REGION,
    S3_PATH_STYLE,
    S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY,
];

/// The aliases, for the release that deletes them.
pub fn deprecated() -> impl Iterator<Item = (&'static str, &'static str)> {
    ALL.iter()
        .filter_map(|var| var.deprecated.map(|old| (old, var.name)))
}

/// Which name supplied a value. PMS-1443 removed the `Deprecated` variant
/// because the alias is no longer a value source; a deprecated name set in
/// the environment refuses boot in `check_boot_env` and is never resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuppliedBy {
    Unset,
    Current,
}

/// Resolve one setting from a lookup. PMS-1443 removed the alias
/// fallback: a value only comes back when the current `STORAGE_`-prefixed
/// name supplies one. A forwarded-but-unset variable arrives as `""`
/// (PMS-836), so blank is unset here as it is everywhere else and the
/// value is trimmed before it is judged.
///
/// Takes a lookup rather than reading the process environment, so the rule
/// can be tested under a concurrent runner without `set_var` — the shape
/// `S3Config::parse` already uses, and the reason both of them are testable
/// at all.
pub fn resolve(
    var: StorageVar,
    lookup: impl Fn(&str) -> Option<String>,
) -> (Option<String>, SuppliedBy) {
    let read = |name: &str| {
        lookup(name)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    match read(var.name) {
        Some(value) => (Some(value), SuppliedBy::Current),
        None => (None, SuppliedBy::Unset),
    }
}

/// Read from the process environment. The deprecated-alias branch is gone;
/// see [`check_boot_env`] for the hard-fail that catches a deployment
/// still forwarding one.
pub fn from_env(var: StorageVar) -> Option<String> {
    resolve(var, |name| std::env::var(name).ok()).0
}

/// Which name supplied this setting in the process environment, for the
/// `provider-status` report. Never returns the VALUE, so a credential cannot
/// reach a report through it.
pub fn supplied_by(var: StorageVar) -> SuppliedBy {
    resolve(var, |name| std::env::var(name).ok()).1
}

/// PMS-1443: boot-time check. If any deprecated storage name is set in
/// the environment, return a human-readable refusal naming every
/// (old -> new) pair the operator needs to edit in the compose file.
/// Called from `main` before any storage config is read; the server
/// refuses to boot rather than silently using the old name.
///
/// Takes a lookup for the same reason `resolve` does: tests set the
/// environment through a lookup rather than `std::env::set_var`, which
/// is not safe under a concurrent test runner.
pub fn check_boot_env(lookup: impl Fn(&str) -> Option<String>) -> Result<(), String> {
    let read = |name: &str| {
        lookup(name)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let offenders: Vec<(&'static str, &'static str)> = deprecated()
        .filter(|(old, _)| read(old).is_some())
        .collect();
    if offenders.is_empty() {
        return Ok(());
    }
    let mut msg = String::from(
        "PMS-1443: the following environment variables are no longer accepted \
         and the server refuses to boot. Rename each in your compose file:\n",
    );
    for (old, new) in offenders {
        msg.push_str(&format!("  - {old} -> {new}\n"));
    }
    msg.push_str("The one-release alias grace period ended with PMS-1443; the new names have been accepted since v0.14.0.");
    Err(msg)
}

/// Boot-time check against the process environment. See [`check_boot_env`].
pub fn check_boot_env_from_process() -> Result<(), String> {
    check_boot_env(|name| std::env::var(name).ok())
}

// PMS-1443: `warn_once` was the "keep working, log once" helper for the
// alias grace period. The aliases are gone; the OnceLock/Mutex/HashSet
// imports went with it.

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn the_current_name_is_read() {
        let (value, by) = resolve(ROOT, lookup(&[("STORAGE_ROOT", "/data/attachments")]));
        assert_eq!(value.as_deref(), Some("/data/attachments"));
        assert_eq!(by, SuppliedBy::Current);
    }

    /// PMS-1443: the deprecated name no longer supplies a value. A compose
    /// file that still forwards it reads as unset here; the hard-fail is
    /// in `check_boot_env`.
    #[test]
    fn the_deprecated_name_does_not_supply_a_value() {
        let (value, by) = resolve(ROOT, lookup(&[("ATTACHMENT_DIR", "/data/attachments")]));
        assert_eq!(value, None);
        assert_eq!(by, SuppliedBy::Unset);
    }

    #[test]
    fn the_current_name_is_read_regardless_of_a_deprecated_sibling() {
        let (value, by) = resolve(
            ROOT,
            lookup(&[("STORAGE_ROOT", "/new"), ("ATTACHMENT_DIR", "/old")]),
        );
        assert_eq!(value.as_deref(), Some("/new"));
        assert_eq!(by, SuppliedBy::Current);
    }

    #[test]
    fn neither_set_is_unset_and_not_an_empty_string() {
        let (value, by) = resolve(ROOT, lookup(&[]));
        assert_eq!(value, None);
        assert_eq!(by, SuppliedBy::Unset);

        let (value, by) = resolve(
            ROOT,
            lookup(&[("STORAGE_ROOT", ""), ("ATTACHMENT_DIR", "")]),
        );
        assert_eq!(value, None);
        assert_eq!(by, SuppliedBy::Unset);
    }

    /// PMS-1443: a deprecated name set in the environment refuses the
    /// boot and names the current replacement so the operator can edit
    /// the compose file.
    #[test]
    fn check_boot_env_fails_loudly_on_a_deprecated_name() {
        let err = check_boot_env(lookup(&[("ATTACHMENT_DIR", "/data/attachments")]))
            .expect_err("ATTACHMENT_DIR set must refuse boot");
        assert!(err.contains("ATTACHMENT_DIR"), "{err}");
        assert!(err.contains("STORAGE_ROOT"), "{err}");
        assert!(err.contains("PMS-1443"), "{err}");
    }

    #[test]
    fn check_boot_env_passes_when_nothing_deprecated_is_set() {
        check_boot_env(lookup(&[("STORAGE_ROOT", "/data")])).expect("new names only must pass");
    }

    #[test]
    fn check_boot_env_lists_every_deprecated_name_set_at_once() {
        let err = check_boot_env(lookup(&[
            ("ATTACHMENT_DIR", "/data"),
            ("S3_ENDPOINT", "https://s3.example"),
        ]))
        .expect_err("multiple deprecated names must all surface");
        assert!(err.contains("ATTACHMENT_DIR"), "{err}");
        assert!(err.contains("S3_ENDPOINT"), "{err}");
    }

    /// Blank is ignored on the boot check too; a compose file forwarding
    /// `ATTACHMENT_DIR: ${ATTACHMENT_DIR:-}` on a host that never set it
    /// must not refuse boot.
    #[test]
    fn check_boot_env_treats_blank_as_unset() {
        check_boot_env(lookup(&[("ATTACHMENT_DIR", "   ")])).expect("blank is unset");
    }

    #[test]
    fn a_value_is_trimmed() {
        let (value, _) = resolve(ROOT, lookup(&[("STORAGE_ROOT", "  /data  ")]));
        assert_eq!(value.as_deref(), Some("/data"));
    }

    /// Every variable carries the prefix, which is the point of the issue, and
    /// no deprecated name does - an alias that is itself `STORAGE_`-prefixed
    /// would mean a rename nobody needs to act on was announced as one.
    #[test]
    fn every_variable_is_prefixed_and_no_alias_is() {
        for var in ALL {
            assert!(
                var.name.starts_with("STORAGE_"),
                "{} is a storage variable without the prefix",
                var.name
            );
            assert!(
                !var.summary.is_empty(),
                "{} has no summary, so provider-status cannot explain it",
                var.name
            );
            if let Some(old) = var.deprecated {
                assert!(
                    !old.starts_with("STORAGE_") || old == "STORAGE_BACKEND",
                    "{old} is already prefixed; it does not need an alias"
                );
                assert_ne!(old, var.name, "{} aliases itself", var.name);
            }
        }
    }

    /// A name appearing twice, in either column, would make resolution depend
    /// on iteration order.
    #[test]
    fn no_name_is_used_twice() {
        let mut names: Vec<&str> = ALL
            .iter()
            .flat_map(|var| std::iter::once(var.name).chain(var.deprecated))
            .collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "a storage variable name is duplicated");
    }

    /// The two credentials are marked as such, because the report prints every
    /// other value and must never print these.
    #[test]
    fn the_credentials_are_the_two_s3_keys() {
        let secrets: Vec<&str> = ALL
            .iter()
            .filter(|var| var.secret)
            .map(|var| var.name)
            .collect();
        assert_eq!(
            secrets,
            vec!["STORAGE_S3_ACCESS_KEY_ID", "STORAGE_S3_SECRET_ACCESS_KEY"]
        );
    }
}
