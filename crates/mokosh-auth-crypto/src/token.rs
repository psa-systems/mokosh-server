//! Token primitives: CSPRNG opaque tokens, SHA-256 hashing for storage,
//! PKCE S256 challenge derivation, constant-time byte comparison.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// 32 random bytes, base64url-encoded with no padding (43 chars). Used
/// for authorization codes, refresh tokens, magic links, password reset
/// tokens, and OP session ids.
pub fn generate_opaque_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 over the raw token. Storage layers persist the hash; the raw
/// token never touches the database.
pub fn hash_opaque_token(raw: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    h.finalize().into()
}

/// Compute the PKCE S256 code_challenge from a code_verifier.
pub fn pkce_s256_challenge(verifier: &str) -> String {
    let mut h = Sha256::new();
    h.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(h.finalize())
}

/// Constant-time byte comparison. Use this on hashes (never on raw secrets
/// directly: hash first).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_tokens_are_distinct_and_decodable() {
        let a = generate_opaque_token();
        let b = generate_opaque_token();
        assert_ne!(a, b);
        let decoded = URL_SAFE_NO_PAD.decode(a.as_bytes()).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn pkce_known_vector() {
        // RFC 7636 Appendix B
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256_challenge(verifier), expected);
    }
}
