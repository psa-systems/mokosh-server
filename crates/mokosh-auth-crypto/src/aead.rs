//! AES-256-GCM at-rest encryption with versioned keys for zero-downtime
//! rotation. Used for TOTP shared secrets and (phase-2) BYO-SSO upstream
//! client secrets.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("unknown key version: {0}")]
    UnknownKeyVersion(u16),
    #[error("decryption failed")]
    Decrypt,
}

/// On-disk / in-DB ciphertext. The `version` field selects which key in
/// the [`EncryptionKeySet`] decrypts it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub version: u16,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Two-key set: a current key for new writes and an optional previous
/// key for reading data still encrypted under the old key during a
/// rotation window.
pub struct EncryptionKeySet {
    current_version: u16,
    current: Aes256Gcm,
    previous: Option<(u16, Aes256Gcm)>,
}

impl EncryptionKeySet {
    /// Build a key set from raw 32-byte keys.
    pub fn new(
        current_version: u16,
        current_key: &[u8; 32],
        previous: Option<(u16, &[u8; 32])>,
    ) -> Self {
        let current = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(current_key));
        let previous = previous.map(|(v, k)| (v, Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(k))));
        Self {
            current_version,
            current,
            previous,
        }
    }

    pub fn current_version(&self) -> u16 {
        self.current_version
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedBlob, AeadError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = self
            .current
            .encrypt(&nonce, plaintext)
            .map_err(|_| AeadError::Decrypt)?;
        Ok(EncryptedBlob {
            version: self.current_version,
            nonce: nonce.to_vec(),
            ciphertext: ct,
        })
    }

    pub fn decrypt(&self, blob: &EncryptedBlob) -> Result<Zeroizing<Vec<u8>>, AeadError> {
        let cipher = if blob.version == self.current_version {
            &self.current
        } else if let Some((v, c)) = &self.previous {
            if *v == blob.version {
                c
            } else {
                return Err(AeadError::UnknownKeyVersion(blob.version));
            }
        } else {
            return Err(AeadError::UnknownKeyVersion(blob.version));
        };
        let nonce = Nonce::from_slice(&blob.nonce);
        let plain = cipher
            .decrypt(nonce, blob.ciphertext.as_slice())
            .map_err(|_| AeadError::Decrypt)?;
        Ok(Zeroizing::new(plain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_current_key() {
        let key = [42u8; 32];
        let set = EncryptionKeySet::new(1, &key, None);
        let blob = set.encrypt(b"hello").unwrap();
        let plain = set.decrypt(&blob).unwrap();
        assert_eq!(&plain[..], b"hello");
    }

    #[test]
    fn previous_key_decrypts_old_blob() {
        let old = [1u8; 32];
        let new = [2u8; 32];
        let writer = EncryptionKeySet::new(1, &old, None);
        let blob = writer.encrypt(b"legacy").unwrap();
        let reader = EncryptionKeySet::new(2, &new, Some((1, &old)));
        let plain = reader.decrypt(&blob).unwrap();
        assert_eq!(&plain[..], b"legacy");
    }

    #[test]
    fn unknown_version_rejected() {
        let key = [0u8; 32];
        let set = EncryptionKeySet::new(1, &key, None);
        let mut blob = set.encrypt(b"x").unwrap();
        blob.version = 99;
        assert!(matches!(
            set.decrypt(&blob),
            Err(AeadError::UnknownKeyVersion(99))
        ));
    }
}
