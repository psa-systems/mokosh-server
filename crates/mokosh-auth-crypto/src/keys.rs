//! Ed25519 (EdDSA) signing-key management for OIDC.
//!
//! At startup we load:
//!  - one active private key (PKCS#8 PEM), used for signing
//!  - all public keys from a directory (one `<kid>.pub.pem` per key),
//!    used for verification AND served from `/.well-known/jwks.json`
//!
//! Old public keys can remain in the directory until tokens signed by
//! them have all expired. This is the zero-downtime rotation strategy.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid private key PEM: {0}")]
    InvalidPrivatePem(String),
    #[error("invalid public key PEM in {path}: {msg}")]
    InvalidPublicPem { path: PathBuf, msg: String },
    #[error("active kid `{0}` not found in public keys directory")]
    MissingActive(String),
    #[error("no public keys found in {0}")]
    EmptyKeyDir(PathBuf),
    #[error("jwt library error: {0}")]
    Jwt(String),
}

#[derive(Clone, Serialize)]
pub struct EdJwk {
    pub kty: &'static str,
    pub crv: &'static str,
    #[serde(rename = "use")]
    pub key_use: &'static str,
    pub kid: String,
    pub alg: &'static str,
    pub x: String, // base64url, no padding, of the raw 32-byte public key
}

#[derive(Clone, Serialize)]
pub struct Jwks {
    pub keys: Vec<EdJwk>,
}

/// Loaded Ed25519 key material plus a pre-built JWKS document.
pub struct OidcKeySet {
    active_kid: String,
    encoding_key: EncodingKey,
    decoding_keys: HashMap<String, DecodingKey>,
    jwks_cache: serde_json::Value,
}

impl OidcKeySet {
    /// Load keys from disk.
    ///
    /// `private_key_path` must be a PKCS#8 PEM containing the Ed25519
    /// private key whose corresponding public key has kid == `active_kid`.
    /// `public_keys_dir` must contain a file `<active_kid>.pub.pem` and
    /// may contain additional `<kid>.pub.pem` files for keys we still
    /// need to verify (rotation overlap).
    pub fn load(
        private_key_path: impl AsRef<Path>,
        active_kid: impl Into<String>,
        public_keys_dir: impl AsRef<Path>,
    ) -> Result<Self, KeyError> {
        let active_kid = active_kid.into();
        let priv_pem = std::fs::read(&private_key_path)?;

        // jsonwebtoken's EdDSA support takes the PKCS#8 PEM bytes directly.
        let encoding_key =
            EncodingKey::from_ed_pem(&priv_pem).map_err(|e| KeyError::Jwt(e.to_string()))?;

        // Sanity check the private key parses with ed25519-dalek too;
        // this catches malformed PEMs early with a clearer error.
        let priv_pem_str = std::str::from_utf8(&priv_pem)
            .map_err(|_| KeyError::InvalidPrivatePem("not utf-8".into()))?;
        SigningKey::from_pkcs8_pem(priv_pem_str)
            .map_err(|e| KeyError::InvalidPrivatePem(e.to_string()))?;

        // Walk the public keys directory.
        let dir = public_keys_dir.as_ref().to_path_buf();
        let mut decoding_keys: HashMap<String, DecodingKey> = HashMap::new();
        let mut jwks_entries: Vec<EdJwk> = Vec::new();

        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let kid = match name.strip_suffix(".pub.pem") {
                Some(k) => k.to_string(),
                None => continue,
            };
            let pem_bytes = std::fs::read(&path)?;
            let pem_str =
                std::str::from_utf8(&pem_bytes).map_err(|_| KeyError::InvalidPublicPem {
                    path: path.clone(),
                    msg: "not utf-8".into(),
                })?;

            // jsonwebtoken DecodingKey for verification.
            let dk =
                DecodingKey::from_ed_pem(&pem_bytes).map_err(|e| KeyError::InvalidPublicPem {
                    path: path.clone(),
                    msg: e.to_string(),
                })?;

            // ed25519-dalek VerifyingKey to extract raw 32-byte `x` for JWKS.
            let vk = VerifyingKey::from_public_key_pem(pem_str).map_err(|e| {
                KeyError::InvalidPublicPem {
                    path: path.clone(),
                    msg: e.to_string(),
                }
            })?;
            let x_b64 = URL_SAFE_NO_PAD.encode(vk.to_bytes());

            decoding_keys.insert(kid.clone(), dk);
            jwks_entries.push(EdJwk {
                kty: "OKP",
                crv: "Ed25519",
                key_use: "sig",
                kid,
                alg: "EdDSA",
                x: x_b64,
            });
        }

        if jwks_entries.is_empty() {
            return Err(KeyError::EmptyKeyDir(dir));
        }
        if !decoding_keys.contains_key(&active_kid) {
            return Err(KeyError::MissingActive(active_kid));
        }

        // Sort for stable JWKS output (helps caching at relying parties).
        jwks_entries.sort_by(|a, b| a.kid.cmp(&b.kid));

        let jwks = Jwks { keys: jwks_entries };
        let jwks_cache = serde_json::to_value(&jwks).expect("jwks serializable");

        Ok(Self {
            active_kid,
            encoding_key,
            decoding_keys,
            jwks_cache,
        })
    }

    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }

    pub fn encoding_key(&self) -> &EncodingKey {
        &self.encoding_key
    }

    pub fn decoding_key(&self, kid: &str) -> Option<&DecodingKey> {
        self.decoding_keys.get(kid)
    }

    /// Pre-built JWKS document, suitable for serving as the body of
    /// `GET /.well-known/jwks.json`.
    pub fn jwks(&self) -> &serde_json::Value {
        &self.jwks_cache
    }
}
