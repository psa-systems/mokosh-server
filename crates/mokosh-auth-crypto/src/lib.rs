//! Mokosh auth: cryptographic primitives.
//!
//! Wraps every secret-handling primitive (Ed25519 signing, Argon2id,
//! AES-256-GCM, CSPRNG token generation, constant-time comparison) behind
//! typed APIs so that callers cannot misuse them.

pub mod aead;
pub mod keys;
pub mod password;
pub mod token;

pub use aead::{EncryptedBlob, EncryptionKeySet};
pub use keys::{KeyError, OidcKeySet};
pub use password::{hash_password, verify_password};
pub use token::{ct_eq, generate_opaque_token, hash_opaque_token, pkce_s256_challenge};
