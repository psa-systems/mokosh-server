//! PMS-1211 (PSA-70): the Google Contacts implementation of
//! [`ContactSyncProvider`].
//!
//! Phase 1 is the seam only. The People API client - the field mask, the
//! pagination, `syncToken` handling and the `410 EXPIRED_SYNC_TOKEN` fallback -
//! is PMS-1213, and the OAuth that produces a usable token is PMS-1212.
//!
//! Until then every method REFUSES. It would be less code to answer with an
//! empty list, and that is exactly the wrong shape: "no contacts" is a
//! legitimate answer from a real account, so an unfinished provider that
//! returns one reports a successful sync of nothing and the first person to
//! notice is an admin wondering where their contacts went.

use async_trait::async_trait;

use super::provider::{ContactSyncProvider, SourceChanges, SourceGroup};
use crate::utils::error::{AppError, AppResult};

/// A tenant's Google Contacts connection.
pub struct GoogleContactsProvider {
    _private: (),
}

impl GoogleContactsProvider {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// The one refusal, so both methods say the same thing.
    fn not_yet<T>(&self) -> AppResult<T> {
        Err(AppError::Configuration(
            "The Google Contacts client is not implemented yet (PMS-1213). No sync has run."
                .to_string(),
        ))
    }
}

impl Default for GoogleContactsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ContactSyncProvider for GoogleContactsProvider {
    fn id(&self) -> &'static str {
        "google"
    }

    async fn list_groups(&self) -> AppResult<Vec<SourceGroup>> {
        self.not_yet()
    }

    async fn changes_since(&self, _sync_token: Option<&str>) -> AppResult<SourceChanges> {
        self.not_yet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stub refuses rather than answering "nothing changed".
    ///
    /// An empty `SourceChanges` is a legitimate answer from a real account, so
    /// a stub that returns one would report a successful sync of nothing and
    /// look identical to a working integration with an empty address book.
    #[tokio::test]
    async fn the_unfinished_client_refuses_rather_than_reporting_an_empty_account() {
        let provider = GoogleContactsProvider::new();
        for message in [
            provider.list_groups().await.err().map(|e| e.to_string()),
            provider
                .changes_since(None)
                .await
                .err()
                .map(|e| e.to_string()),
        ] {
            let message = message.expect("the stub must refuse, not answer emptily");
            assert!(message.contains("not implemented yet"), "{message}");
        }
    }

    /// The discriminator it reports is the one the column stores.
    #[test]
    fn it_reports_the_stored_discriminator() {
        assert_eq!(GoogleContactsProvider::new().id(), "google");
        assert!(super::super::provider::is_supported("google"));
    }
}
