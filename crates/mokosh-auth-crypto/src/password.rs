//! Argon2id password hashing.
//!
//! Parameters per OWASP 2024 guidance: 64 MiB, 3 iterations, 4 lanes.
//! The same primitives are used to hash OAuth client_secret values for
//! confidential clients.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

fn hasher() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 3, 4, None).expect("static argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("hash error: {0}")]
    Hash(String),
    #[error("invalid stored hash")]
    InvalidStored,
}

/// Hash a plaintext password (or client secret). Returns a PHC string
/// that includes algorithm, version, parameters, salt, and hash.
pub fn hash_password(plain: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PasswordError::Hash(e.to_string()))
}

/// Verify a plaintext password against a stored PHC hash.
///
/// Returns `false` (not Err) for malformed stored hashes; the caller
/// should treat both as authentication failure.
pub fn verify_password(plain: &str, stored_phc: &str) -> bool {
    match PasswordHash::new(stored_phc) {
        Ok(parsed) => hasher().verify_password(plain.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hash_password("Sup3rL0ngPass!").unwrap();
        assert!(verify_password("Sup3rL0ngPass!", &h));
        assert!(!verify_password("wrong-password", &h));
    }

    #[test]
    fn malformed_hash_rejects() {
        assert!(!verify_password("anything", "$argon2id$v=19$bogus"));
    }
}
