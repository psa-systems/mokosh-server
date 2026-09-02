//! PMS-871: at-rest encryption for the legacy-path TOTP shared secret.
//!
//! `users.mfa_secret` used to hold the raw base32 secret, so anyone who could
//! read the table (a `pg_dump`, a logical backup, a replica, a SQL read
//! primitive) could mint valid second factors for every user in every tenant.
//! The column now holds the AES-256-GCM ciphertext produced by
//! [`crate::utils::crypto::encrypt`] under the same `ENCRYPTION_KEY` the
//! payment-gateway configs use (PMS-40 / PMS-342) - it is a shared secret, so
//! it must be recoverable and cannot be hashed the way the password is.
//!
//! Rows enrolled before the change are still plaintext and no SQL migration
//! can re-encrypt them (a migration has no access to the key), so a read
//! classifies the stored value and the caller rewrites a legacy one encrypted
//! on the next successful verification. That keeps every enrolled user working
//! with no forced re-enrolment.

use crate::utils::crypto::{decrypt, encrypt};
use crate::utils::error::{AppError, AppResult};

/// Longest a stored plaintext secret can be: `base32_encode` of the 20-byte
/// RFC 6238 secret is exactly 32 characters, and nothing else ever wrote this
/// column. The shortest ciphertext this module can produce is 40 characters
/// (base64 of a 12-byte nonce plus the 16-byte GCM tag, even for an empty
/// plaintext), so the two shapes cannot overlap on length alone.
/// `ciphertext_never_looks_like_plaintext` pins that gap.
const MAX_PLAINTEXT_LEN: usize = 32;

/// A classified `users.mfa_secret` column value, carrying the base32 secret
/// either way. The variant is what tells the caller whether the row still owes
/// an in-place upgrade.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StoredMfaSecret {
    /// PMS-871 ciphertext, already decrypted to the base32 secret.
    Encrypted(String),
    /// Pre-PMS-871 plaintext, to be rewritten encrypted by the caller once the
    /// code it presented has verified.
    LegacyPlaintext(String),
}

impl StoredMfaSecret {
    /// The base32 shared secret, whichever shape it was stored in.
    pub(crate) fn secret_b32(&self) -> &str {
        match self {
            Self::Encrypted(s) | Self::LegacyPlaintext(s) => s,
        }
    }

    /// True while the row is still plaintext on disk.
    pub(crate) fn needs_upgrade(&self) -> bool {
        matches!(self, Self::LegacyPlaintext(_))
    }
}

/// Encrypt a base32 secret for storage in `users.mfa_secret`.
pub(crate) fn seal(secret_b32: &str, key: &[u8; 32]) -> AppResult<String> {
    encrypt(secret_b32, key)
}

/// Classify and, when encrypted, decrypt a `users.mfa_secret` column value.
///
/// The plaintext test runs FIRST and is a positive shape check, not a fallback
/// from a failed decrypt: falling back on decrypt failure would turn a wrong
/// `ENCRYPTION_KEY` into "this row is plaintext", hand the verifier 60 bytes of
/// base64 decoded as if it were base32, and report a misconfigured deployment
/// as a wrong code. A ciphertext that will not decrypt is an error here, loudly.
pub(crate) fn open(stored: &str, key: &[u8; 32]) -> AppResult<StoredMfaSecret> {
    if is_plaintext_shape(stored) {
        return Ok(StoredMfaSecret::LegacyPlaintext(stored.to_string()));
    }
    let secret_b32 = decrypt(stored, key).map_err(|e| {
        tracing::error!(
            error = %e,
            "stored MFA secret did not decrypt; ENCRYPTION_KEY may have changed since enrolment"
        );
        AppError::Internal("stored MFA secret is corrupt".to_string())
    })?;
    Ok(StoredMfaSecret::Encrypted(secret_b32))
}

/// Whether a stored value is a pre-PMS-871 plaintext base32 secret: short
/// enough that no ciphertext could be that length, and drawn only from the
/// RFC 4648 base32 alphabet `base32_decode` accepts.
fn is_plaintext_shape(stored: &str) -> bool {
    let body = stored.trim_end_matches('=');
    !body.is_empty()
        && body.len() <= MAX_PLAINTEXT_LEN
        && body
            .bytes()
            .all(|b| b.is_ascii_alphabetic() || (b'2'..=b'7').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::totp::{base32_encode, generate_secret};

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn seal_then_open_round_trips() {
        let secret_b32 = base32_encode(&generate_secret());
        let sealed = seal(&secret_b32, &KEY).unwrap();
        assert_ne!(sealed, secret_b32, "the stored value is not the secret");
        let opened = open(&sealed, &KEY).unwrap();
        assert_eq!(opened, StoredMfaSecret::Encrypted(secret_b32.clone()));
        assert_eq!(opened.secret_b32(), secret_b32);
        assert!(!opened.needs_upgrade());
    }

    #[test]
    fn plaintext_row_is_classified_as_legacy() {
        let secret_b32 = base32_encode(&generate_secret());
        let opened = open(&secret_b32, &KEY).unwrap();
        assert_eq!(opened.secret_b32(), secret_b32);
        assert!(opened.needs_upgrade(), "a plaintext row owes an upgrade");
    }

    /// The whole in-place-upgrade scheme rests on the two shapes being
    /// distinguishable, so pin it over many secrets rather than one: every
    /// ciphertext must be long enough that the plaintext test cannot claim it.
    #[test]
    fn ciphertext_never_looks_like_plaintext() {
        for _ in 0..256 {
            let secret_b32 = base32_encode(&generate_secret());
            assert!(is_plaintext_shape(&secret_b32));
            let sealed = seal(&secret_b32, &KEY).unwrap();
            assert!(
                !is_plaintext_shape(&sealed),
                "ciphertext {sealed} was misread as a plaintext secret"
            );
        }
    }

    /// A ciphertext that will not decrypt fails loudly instead of being retried
    /// as plaintext. This is the wrong-`ENCRYPTION_KEY` case.
    #[test]
    fn undecryptable_ciphertext_is_an_error() {
        let sealed = seal(&base32_encode(&generate_secret()), &KEY).unwrap();
        let err = open(&sealed, &[9u8; 32]).unwrap_err();
        assert!(
            matches!(err, AppError::Internal(_)),
            "wrong key must error, got {err:?}"
        );
    }
}
