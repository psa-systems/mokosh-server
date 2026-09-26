//! PMS-1317: the storage variables an operator sets, and the older names that
//! still work.
//!
//! Every storage setting is `STORAGE_`-prefixed. Before this they were
//! `ATTACHMENT_DIR`, `STORAGE_BACKEND` and six bare `S3_*`, which is three
//! naming schemes for one subsystem and is why David went through the staging
//! compose looking for where storage is configured and did not find it.
//! `ATTACHMENT_DIR` was the sharpest of them: it names one of the four things
//! stored under that root (ticket attachments, KB images, tenant logos, issued
//! documents), so an operator reading it has no reason to think it decides
//! where the others go.
//!
//! # Why the old names keep working
//!
//! A deployment sets these in a compose file that lives in another repository,
//! so the rename and the compose change cannot land in the same commit. A hard
//! rename would mean the first deploy after this release reads no root, falls
//! back to the compiled-in default, and serves 404s for every file still on the
//! volume - a data-loss-shaped outage caused by a vocabulary change. So each
//! old name stays accepted as a DEPRECATED ALIAS and says so in the log once,
//! naming both itself and its replacement, and the alias is what makes this
//! deployable in either order.
//!
//! The aliases come out one release after every deployment's compose has moved.
//! [`DEPRECATED`] is the list to delete, and `provider-status` reports which
//! NAME actually supplied each value, so "has staging moved yet" is a question
//! with an answer rather than a guess.
//!
//! # The rule when both are set
//!
//! The new name wins and the old one is ignored in silence beyond the usual
//! deprecation line. An operator who has set both has already started the
//! migration, and preferring the old name would make the new one look broken;
//! failing on the pair would turn a half-finished migration into an outage,
//! which is the thing the alias exists to prevent.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

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

/// Which name supplied a value, which is the question an operator migrating a
/// compose file actually has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuppliedBy {
    /// Nothing set either name.
    Unset,
    /// The `STORAGE_`-prefixed name.
    Current,
    /// The older name. Still honoured, and reported so the migration can be
    /// finished.
    Deprecated,
}

/// Resolve one setting: the current name, else the deprecated alias.
///
/// Takes a lookup rather than reading the process environment, so the rule can
/// be tested under a concurrent runner without `set_var` - the shape
/// `S3Config::parse` already uses, and the reason both of them are testable at
/// all.
///
/// A forwarded-but-unset variable arrives as `""` (PMS-836), so blank is unset
/// here as it is everywhere else, and a value is trimmed before it is judged.
/// That matters more than it looks: a compose file that forwards
/// `STORAGE_ROOT: ${STORAGE_ROOT:-}` on a host that has not set it would
/// otherwise shadow a perfectly good `ATTACHMENT_DIR` with an empty string,
/// which is precisely the half-migrated state the alias exists to survive.
pub fn resolve(
    var: StorageVar,
    lookup: impl Fn(&str) -> Option<String>,
) -> (Option<String>, SuppliedBy) {
    let read = |name: &str| {
        lookup(name)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    if let Some(value) = read(var.name) {
        return (Some(value), SuppliedBy::Current);
    }
    match var.deprecated.and_then(read) {
        Some(value) => (Some(value), SuppliedBy::Deprecated),
        None => (None, SuppliedBy::Unset),
    }
}

/// Resolve from the process environment, warning once per deprecated name.
///
/// Once per NAME rather than once per call: `StorageConfig::from_env` is also
/// `Default::default()`, so a caller that constructs one per request would
/// otherwise put a deprecation line in the log on every request and teach
/// whoever reads it to filter deprecation lines out.
pub fn from_env(var: StorageVar) -> Option<String> {
    let (value, supplied_by) = resolve(var, |name| std::env::var(name).ok());
    if supplied_by == SuppliedBy::Deprecated {
        warn_once(var);
    }
    value
}

/// Which name supplied this setting in the process environment, for the
/// `provider-status` report. Never returns the VALUE, so a credential cannot
/// reach a report through it.
pub fn supplied_by(var: StorageVar) -> SuppliedBy {
    resolve(var, |name| std::env::var(name).ok()).1
}

fn warn_once(var: StorageVar) {
    static SEEN: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    let Ok(mut seen) = seen.lock() else {
        return;
    };
    let Some(old) = var.deprecated else {
        return;
    };
    if seen.insert(old) {
        tracing::warn!(
            deprecated = old,
            replacement = var.name,
            "{old} is deprecated and will be removed a release after every deployment has moved; \
             set {} instead",
            var.name
        );
    }
}

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

    /// The property the whole alias exists for: a deployment whose compose file
    /// has not moved yet keeps its root.
    #[test]
    fn the_deprecated_name_still_works() {
        let (value, by) = resolve(ROOT, lookup(&[("ATTACHMENT_DIR", "/data/attachments")]));
        assert_eq!(value.as_deref(), Some("/data/attachments"));
        assert_eq!(
            by,
            SuppliedBy::Deprecated,
            "the caller has to be able to tell, or the deprecation is unreportable"
        );
    }

    #[test]
    fn the_current_name_wins_when_both_are_set() {
        let (value, by) = resolve(
            ROOT,
            lookup(&[("STORAGE_ROOT", "/new"), ("ATTACHMENT_DIR", "/old")]),
        );
        assert_eq!(value.as_deref(), Some("/new"));
        assert_eq!(by, SuppliedBy::Current);
    }

    /// A compose file that forwards the new name on a host that has not set it
    /// hands over `""`. Treating that as a value would shadow a working
    /// deprecated setting with nothing, which is the half-migrated state this
    /// is supposed to survive rather than the one it creates.
    #[test]
    fn a_blank_current_name_does_not_shadow_the_deprecated_one() {
        let (value, by) = resolve(
            ROOT,
            lookup(&[("STORAGE_ROOT", "   "), ("ATTACHMENT_DIR", "/old")]),
        );
        assert_eq!(value.as_deref(), Some("/old"));
        assert_eq!(by, SuppliedBy::Deprecated);
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
