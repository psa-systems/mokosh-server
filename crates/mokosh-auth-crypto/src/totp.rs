//! RFC 6238 TOTP. Six-digit codes over a 30-second step, HMAC-SHA1 over
//! a 20-byte shared secret. The algorithm/digits/period choices are the
//! ones every authenticator app accepts as defaults.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;

pub const TOTP_STEP_SECS: i64 = 30;
pub const TOTP_DIGITS: u32 = 6;
pub const TOTP_SECRET_BYTES: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("invalid base32 input")]
    Base32,
}

/// Generate a fresh 20-byte (160-bit) secret.
pub fn generate_secret() -> [u8; TOTP_SECRET_BYTES] {
    let mut s = [0u8; TOTP_SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// RFC 4648 base32, uppercase, no padding. We hand-roll because the only
/// callers are this module and the recovery-code module; pulling another
/// crate for two functions is not worth it.
pub fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        buf = (buf << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Result<Vec<u8>, TotpError> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in s.chars().filter(|c| !c.is_ascii_whitespace() && *c != '=') {
        let v: u32 = match c.to_ascii_uppercase() {
            'A'..='Z' => (c.to_ascii_uppercase() as u32) - ('A' as u32),
            '2'..='7' => 26 + (c as u32) - ('2' as u32),
            _ => return Err(TotpError::Base32),
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Build the canonical `otpauth://` provisioning URI per the Google Auth
/// spec. `label` is typically `"Mokosh:alice@example.com"`. The URI is
/// what gets encoded into the QR.
pub fn provisioning_uri(secret_b32: &str, label: &str, issuer: &str) -> String {
    let label_enc = urlencode(label);
    let issuer_enc = urlencode(issuer);
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={d}&period={p}",
        label = label_enc,
        secret = secret_b32,
        issuer = issuer_enc,
        d = TOTP_DIGITS,
        p = TOTP_STEP_SECS,
    )
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// RFC 4226 HOTP / RFC 6238 TOTP step function. `t` is the step number
/// (i.e. unix_seconds / 30).
fn step(secret: &[u8], t: i64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&t.to_be_bytes());
    let hmac = mac.finalize().into_bytes();
    // Dynamic truncation: take the low 4 bits of the last byte as offset,
    // then read 4 bytes starting there.
    let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
    let bin = ((hmac[offset] as u32 & 0x7f) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | (hmac[offset + 3] as u32);
    bin % 10u32.pow(TOTP_DIGITS)
}

/// Format the value the way authenticator apps display it: zero-padded
/// to `TOTP_DIGITS` digits.
fn format_code(value: u32) -> String {
    format!("{:0width$}", value, width = TOTP_DIGITS as usize)
}

/// Verify `code` against `secret` allowing `+-window` steps of clock
/// skew. Returns the matched step on success so the caller can use it
/// for anti-replay.
pub fn verify(secret: &[u8], code: &str, now: DateTime<Utc>, window: i64) -> Option<i64> {
    let code = code.trim();
    if code.len() != TOTP_DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let t = now.timestamp() / TOTP_STEP_SECS;
    for delta in -window..=window {
        if format_code(step(secret, t + delta)) == code {
            return Some(t + delta);
        }
    }
    None
}

/// Helper for tests + tooling: emit the code for `(secret, now)`.
pub fn code_at(secret: &[u8], now: DateTime<Utc>) -> String {
    let t = now.timestamp() / TOTP_STEP_SECS;
    format_code(step(secret, t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn base32_round_trip() {
        let bytes: &[u8] = &[0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3];
        let encoded = base32_encode(bytes);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(&decoded[..], bytes);
    }

    #[test]
    fn base32_decode_ignores_case_and_padding() {
        let bytes: &[u8] = &[1, 2, 3, 4];
        let upper = base32_encode(bytes);
        let lower = upper.to_ascii_lowercase();
        assert_eq!(base32_decode(&lower).unwrap(), bytes);
        let padded = format!("{}===", upper);
        assert_eq!(base32_decode(&padded).unwrap(), bytes);
    }

    #[test]
    fn verify_accepts_current_step() {
        let secret = [0x77; 20];
        let now = Utc.timestamp_opt(1_000_000_000, 0).unwrap();
        let c = code_at(&secret, now);
        assert_eq!(verify(&secret, &c, now, 1), Some(1_000_000_000 / 30));
    }

    #[test]
    fn verify_tolerates_pm1() {
        let secret = [0xab; 20];
        let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let t = now.timestamp() / 30;
        let prev = format_code(step(&secret, t - 1));
        let next = format_code(step(&secret, t + 1));
        assert_eq!(verify(&secret, &prev, now, 1), Some(t - 1));
        assert_eq!(verify(&secret, &next, now, 1), Some(t + 1));
    }

    #[test]
    fn verify_rejects_pm2() {
        let secret = [0xab; 20];
        let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let t = now.timestamp() / 30;
        let two_back = format_code(step(&secret, t - 2));
        assert_eq!(verify(&secret, &two_back, now, 1), None);
    }

    #[test]
    fn verify_rejects_malformed() {
        let secret = [0; 20];
        let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        assert_eq!(verify(&secret, "", now, 1), None);
        assert_eq!(verify(&secret, "12345", now, 1), None);
        assert_eq!(verify(&secret, "1234567", now, 1), None);
        assert_eq!(verify(&secret, "abcdef", now, 1), None);
    }

    /// RFC 6238 appendix B test vector (SHA-1 over "12345678901234567890").
    #[test]
    fn rfc6238_vector() {
        let secret = b"12345678901234567890";
        // T = 59 seconds => step 1
        let t = Utc.timestamp_opt(59, 0).unwrap();
        assert_eq!(code_at(secret, t), "287082");
        // T = 1111111109 seconds => step 37037036
        let t = Utc.timestamp_opt(1_111_111_109, 0).unwrap();
        assert_eq!(code_at(secret, t), "081804");
    }
}
