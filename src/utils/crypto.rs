//! Cryptographic utilities for encryption and hashing

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;

use crate::utils::error::{AppError, AppResult};

/// Length of the encryption nonce
const NONCE_LENGTH: usize = 12;

/// Encrypt a string value using AES-256-GCM
///
/// Returns a base64-encoded string containing the nonce and ciphertext
pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> AppResult<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Internal(format!("Encryption key error: {}", e)))?;

    // Generate a random nonce
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| AppError::Internal(format!("Encryption error: {}", e)))?;

    // Combine nonce and ciphertext
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);

    // Base64 encode
    Ok(BASE64.encode(combined))
}

/// Decrypt a base64-encoded ciphertext
pub fn decrypt(encrypted: &str, key: &[u8; 32]) -> AppResult<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| AppError::Internal(format!("Encryption key error: {}", e)))?;

    // Base64 decode
    let combined = BASE64
        .decode(encrypted)
        .map_err(|e| AppError::Internal(format!("Base64 decode error: {}", e)))?;

    if combined.len() < NONCE_LENGTH {
        return Err(AppError::Internal("Invalid encrypted data".to_string()));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LENGTH);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AppError::Internal(format!("Decryption error: {}", e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| AppError::Internal(format!("UTF-8 decode error: {}", e)))
}

/// Parse an encryption key supplied as either 32 raw bytes or 64 hex
/// characters.
///
/// PMS-188: a 32-character key is now always treated as 32 raw bytes. The
/// previous code special-cased length 32 and copied the *bytes* of what
/// might be a hex string, so an operator who supplied a 32-char hex string
/// got a key that differed from their intent. A 32-char hex string is
/// ambiguous (is it raw bytes or half a hex key?), so it is rejected: hex
/// keys must be the unambiguous 64-char form, which is hex-decoded.
pub fn parse_encryption_key(key_hex: &str) -> AppResult<[u8; 32]> {
    // 64 hex characters: hex-decode to 32 bytes.
    if key_hex.len() == 64 {
        let mut key = [0u8; 32];
        for (i, chunk) in key_hex.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).map_err(|_| {
                AppError::Configuration("Invalid encryption key format".to_string())
            })?;
            key[i] = u8::from_str_radix(hex_str, 16).map_err(|_| {
                AppError::Configuration("Invalid encryption key format".to_string())
            })?;
        }
        return Ok(key);
    }

    // 32 characters: only accept as raw bytes when it is unambiguously NOT a
    // hex string. An all-hex 32-char value is ambiguous (it could be a
    // mistyped 16-byte hex key or a 32-byte raw passphrase) and is rejected so
    // it is never silently taken as raw bytes against operator intent.
    if key_hex.len() == 32 {
        if key_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AppError::Configuration(format!(
                "Encryption key is an ambiguous 32-character hex-looking string; \
                 supply 32 raw bytes or a full 64-character hex key (got {} characters)",
                key_hex.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(key_hex.as_bytes());
        return Ok(key);
    }

    Err(AppError::Configuration(format!(
        "Encryption key must be 32 raw bytes or 64 hex characters, got {} characters",
        key_hex.len()
    )))
}

/// Generate a random token (for password resets, API keys, etc.)
pub fn generate_token(length: usize) -> String {
    use rand::distr::Alphanumeric;
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Generate a secure random API key
pub fn generate_api_key() -> String {
    format!("psa_{}", generate_token(40))
}

/// mokosh-contact-login prompt 003: 16-char Crockford base32 slug used
/// as `companies.portal_slug`. 80 bits of entropy so a targeted
/// attacker cannot enumerate portals. Excludes visually confusable
/// characters (I, L, O, U).
///
/// The contact portal URL shape is `msp.<apex>/portal/{slug}/*` (no
/// per-tenant wildcard subdomain), so the slug is the ONLY thing
/// standing between an attacker and the login page. All sensitive
/// endpoints gate on capability + session; a leaked slug only reveals
/// the login form.
pub fn generate_portal_slug() -> String {
    use rand::seq::IndexedRandom;
    // 32 chars: Crockford base32 minus I / L / O / U.
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut rng = rand::rng();
    (0..16)
        .map(|_| *ALPHABET.choose(&mut rng).expect("non-empty alphabet") as char)
        .collect()
}

/// mokosh-contact-login prompt 011 (PMS-928): random 9-digit numeric
/// Portal ID used as `companies.portal_id`. Range `[100_000_000,
/// 1_000_000_000)` (inclusive lower, exclusive upper) so the value is
/// always renderable as exactly nine digits ("dictable over the phone")
/// and never overflows into 10-digit territory.
///
/// 10^9 = 1B ids; at 10M Companies birthday-paradox collision is under
/// 1%. `ContactService::grant_portal_access` retries UNIQUE-constraint
/// bounces up to 5 times, so a collision is quietly recovered rather
/// than surfacing as a create-Company failure.
pub fn generate_portal_id() -> i64 {
    rand::rng().random_range(100_000_000..1_000_000_000)
}

/// Generate a short numeric code (for MFA, etc.)
pub fn generate_numeric_code(length: usize) -> String {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| char::from_digit(rng.random_range(0..10), 10).unwrap())
        .collect()
}

/// Hash a password using Argon2id
#[cfg(feature = "server")]
pub fn hash_password(password: &str) -> AppResult<String> {
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hashing error: {}", e)))?;

    Ok(hash.to_string())
}

/// Verify a password against a hash
#[cfg(feature = "server")]
pub fn verify_password(password: &str, hash: &str) -> AppResult<bool> {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash: {}", e)))?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AppError::Internal(format!(
            "Password verification error: {}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32]; // Test key
        let plaintext = "Hello, World!";

        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_parse_key_64_hex_is_decoded() {
        // 64 hex chars -> 32 decoded bytes (not the raw ASCII of the string).
        let key = parse_encryption_key(&"00".repeat(32)).unwrap();
        assert_eq!(key, [0u8; 32]);
        let key = parse_encryption_key(&"ff".repeat(32)).unwrap();
        assert_eq!(key, [0xffu8; 32]);
    }

    #[test]
    fn test_parse_key_32_raw_bytes_ok() {
        // 32 chars containing non-hex characters is unambiguously raw.
        let raw = "32-byte-key-for-dev-only-change!";
        assert_eq!(raw.len(), 32);
        let key = parse_encryption_key(raw).unwrap();
        assert_eq!(&key, raw.as_bytes());
    }

    #[test]
    fn test_parse_key_ambiguous_32_hex_rejected() {
        // 32 all-hex chars is ambiguous and must be rejected, not taken raw.
        assert!(parse_encryption_key(&"a".repeat(32)).is_err());
    }

    #[test]
    fn test_parse_key_wrong_length_reports_length() {
        let err = parse_encryption_key("short").unwrap_err();
        assert!(err.to_string().contains('5'), "error was: {err}");
    }

    #[test]
    fn test_generate_token() {
        let token = generate_token(32);
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_generate_api_key() {
        let key = generate_api_key();
        assert!(key.starts_with("psa_"));
        assert_eq!(key.len(), 44);
    }

    #[test]
    fn test_generate_numeric_code() {
        let code = generate_numeric_code(6);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn portal_slug_shape() {
        // mokosh-contact-login prompt 003: pin the length, alphabet,
        // and collision rate of the slug generator.
        let slug = generate_portal_slug();
        assert_eq!(slug.len(), 16, "portal slug must be 16 chars");
        const ALLOWED: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        assert!(
            slug.chars().all(|c| ALLOWED.contains(c)),
            "portal slug must use Crockford base32 minus I/L/O/U, got {slug:?}"
        );
        // Collision smoke-test: 10_000 slugs should all be unique. 80
        // bits of entropy makes an actual collision astronomically
        // unlikely; a duplicate here would flag a broken RNG.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let s = generate_portal_slug();
            assert!(seen.insert(s), "portal slug collision in 10k samples");
        }
    }

    #[test]
    fn portal_id_stays_in_9_digit_range() {
        // mokosh-contact-login prompt 011 (PMS-928): every generated
        // Portal ID sits inside the [100_000_000, 1_000_000_000)
        // window so it always renders as exactly 9 digits. 10k
        // samples is the same shape the slug generator's test uses;
        // a stray value here flags a broken RNG or an off-by-one
        // range change.
        for _ in 0..10_000 {
            let id = generate_portal_id();
            assert!(
                (100_000_000..1_000_000_000).contains(&id),
                "portal_id out of range: {id}"
            );
        }
    }

    #[test]
    fn portal_id_shows_reasonable_uniqueness() {
        // mokosh-contact-login prompt 011 (PMS-928): birthday-paradox
        // sanity check. 5k samples over a 900M-value space expect
        // <=~14 collisions on average; assert we stay above 4990
        // uniques so a collapsed RNG (constant, tiny range) trips
        // the test but a healthy RNG never flakes.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5_000 {
            seen.insert(generate_portal_id());
        }
        assert!(
            seen.len() >= 4990,
            "portal_id uniqueness collapsed: only {} unique in 5k samples",
            seen.len()
        );
    }

    #[cfg(feature = "server")]
    #[test]
    fn test_password_hash_verify() {
        let password = "secure_password_123";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }
}
