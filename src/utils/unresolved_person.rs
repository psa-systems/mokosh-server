//! PMS-1477: the one place a server response logs that it could not resolve a
//! person's name for an id it was asked to resolve.
//!
//! A row whose id is `None` has nothing to resolve and is not logged; a row
//! whose id is `Some` but whose name came back empty is a failed lookup, and
//! per `docs/invariants/error-visibility.md` section 2 that is INFO, not WARN
//! or ERROR, because a lookup that found nothing is not a tried-and-failed
//! attempt. [`log_unresolved_person_names`] logs once per call (so a list
//! endpoint logs once per response, not once per row) and never logs an email
//! or a display name, only the id: an id is not a secret, a name and an email
//! are.

use uuid::Uuid;

/// Cap on how many ids a single log line carries, so a page with hundreds of
/// unresolved rows still produces one bounded line.
const MAX_IDS_LOGGED: usize = 10;

/// Logs once, at INFO, that `surface` returned `ids.len()` person ids it could
/// not resolve to a name. No-op when `ids` is empty, so every call site can
/// call this unconditionally after filtering rows down to the unresolved ones.
pub fn log_unresolved_person_names(surface: &str, ids: &[Uuid]) {
    if ids.is_empty() {
        return;
    }
    let shown = &ids[..ids.len().min(MAX_IDS_LOGGED)];
    tracing::info!(
        surface,
        count = ids.len(),
        ids = ?shown,
        "unresolved person name"
    );
}
