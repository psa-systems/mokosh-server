//! Recovery codes: 80 bits of randomness, base32-encoded, formatted as
//! `XXXXXXXX-XXXXXXXX`. SHA-256 hash for at-rest storage.

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::totp::base32_encode;

pub const RECOVERY_CODE_COUNT: usize = 10;
pub const RECOVERY_CODE_BYTES: usize = 10;

/// Generate one code. 10 random bytes => 16 base32 chars (80 bits exactly,
/// no padding); we keep all 16 and split 8-8 for readability. Retaining the
/// full 16 chars preserves the 80 bits of entropy (PMS-188: the previous
/// code kept only the first 10 chars, delivering just 50 bits despite the
/// 80-bit comment).
pub fn generate_code() -> String {
    let mut bytes = [0u8; RECOVERY_CODE_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    let raw = base32_encode(&bytes);
    format!("{}-{}", &raw[..8], &raw[8..])
}

pub fn generate_set() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT).map(|_| generate_code()).collect()
}

/// Strip whitespace and hyphens, uppercase. Used by both generation and
/// verification so `"abcde-fghij"`, `"ABCDE-FGHIJ"`, `"abcdefghij"`, and
/// `"abc de-fg hij"` all canonicalize to the same byte string.
pub fn canonicalize(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

/// SHA-256 of the canonical form. 80 bits of input entropy is well past
/// the offline-grinding threshold so SHA-256 is sufficient; argon2 is
/// not warranted here.
pub fn hash_code(code: &str) -> [u8; 32] {
    let canonical = canonicalize(code);
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_code_matches_format() {
        let c = generate_code();
        // 16 base32 chars + 1 hyphen, split 8-8, so the full 80 bits is kept.
        assert_eq!(c.len(), 17);
        assert_eq!(c.chars().nth(8), Some('-'));
        let body = c.replace('-', "");
        assert_eq!(body.len(), 16);
        assert!(
            body.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')),
            "unexpected chars in {c}"
        );
    }

    #[test]
    fn generate_set_count() {
        assert_eq!(generate_set().len(), RECOVERY_CODE_COUNT);
    }

    #[test]
    fn hash_code_is_canonical() {
        let a = hash_code("ABCDE-FGHIJ");
        let b = hash_code("abcde-fghij");
        let c = hash_code("abcdefghij");
        let d = hash_code("ab cde-fg hij");
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a, d);
    }

    #[test]
    fn hash_code_differs_per_code() {
        assert_ne!(hash_code("ABCDE-FGHIJ"), hash_code("ABCDE-FGHIK"));
    }
}
