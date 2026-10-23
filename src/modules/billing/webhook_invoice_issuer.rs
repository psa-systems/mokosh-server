//! MAPPS-1099 Phase 3 scaffolds: signed webhook verifiers for the Xero
//! and QuickBooks event streams.
//!
//! Xero and QuickBooks both deliver account-change events (invoice
//! paid, invoice voided, invoice amended) as signed POSTs. Phase 3b
//! wires the actual event handling (map the external invoice id back
//! to a local row via `invoices.external_invoice_id`, update status
//! from the payload, write an audit entry); this PR lands the
//! signature verifiers alone so the next step is adding routes against
//! a library it already carries, not building both at once.
//!
//! Both schemes verify as HMAC-SHA256 over the raw request body,
//! base64-encoded, compared constant-time. The signing key is the
//! installation's own webhook secret, written to `SecretKind::Integration`
//! during OAuth consent in the Phase 2c reconnect flow.
//!
//! Nothing mounts routes yet; the signatures of these helpers match
//! the shape every provider webhook in `src/modules/billing/webhook.rs`
//! already uses (`verify_and_parse_webhook` on `PaymentProvider`), so
//! Phase 3b's receiver code calls these verifiers directly without
//! re-shaping them.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Verify a Xero webhook delivery.
///
/// Xero sends the `x-xero-signature` header carrying `base64(hmac_sha256(body, webhook_signing_key))`.
/// A tampered body (or a wrong key) fails the HMAC compare; a well-known-false
/// return is the only outcome besides a well-known-true, so the caller cannot
/// confuse a key mismatch with an outage. Comparison is constant-time to deny
/// a timing side channel on signature-length prefixes.
pub fn verify_xero_signature(body: &[u8], signature_header: &str, signing_key: &[u8]) -> bool {
    verify_hmac_sha256_base64(body, signature_header.trim(), signing_key)
}

/// Verify a QuickBooks webhook delivery.
///
/// QuickBooks sends the `intuit-signature` header carrying
/// `base64(hmac_sha256(body, verifier_token))`. Same shape as Xero's
/// verifier; the only difference is the header the HTTP handler reads
/// it from. Kept as a dedicated fn for the same reason
/// `provider::stripe::verify_and_parse_webhook` is dedicated: the
/// callers downstream dispatch on the provider, and one named fn per
/// provider keeps the dispatch straight when a header name changes.
pub fn verify_quickbooks_signature(
    body: &[u8],
    signature_header: &str,
    verifier_token: &[u8],
) -> bool {
    verify_hmac_sha256_base64(body, signature_header.trim(), verifier_token)
}

/// Shared HMAC-SHA256 + base64 verifier used by both providers. Private
/// because it names no provider: a caller that wants to add a third
/// provider on this scheme goes through [`verify_xero_signature`] or
/// [`verify_quickbooks_signature`] by analogy, so the provider list
/// stays in the module interface and not scattered through callers.
fn verify_hmac_sha256_base64(body: &[u8], signature_b64: &str, key: &[u8]) -> bool {
    let Ok(expected_bytes) = BASE64_STANDARD.decode(signature_b64) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(body);
    // `verify_slice` runs the constant-time compare the Hmac crate
    // documents is the right primitive here; we never read the raw
    // computed bytes out of `mac` and compare with `==`.
    mac.verify_slice(&expected_bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-good HMAC-SHA256 round-trip. Signs a body with a key, then
    /// verifies the base64 signature it produces; a tiny body mutation
    /// turns the verifier false. This is the invariant Phase 3b's event
    /// handling leans on: a tampered payload cannot reach the
    /// local-row update path.
    #[test]
    fn xero_verifier_accepts_a_signature_produced_with_the_same_key() {
        let body = b"{\"events\":[]}";
        let key = b"secret-xero-webhook-key-at-least-32-bytes";
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(body);
        let sig = BASE64_STANDARD.encode(mac.finalize().into_bytes());

        assert!(verify_xero_signature(body, &sig, key));

        let tampered = b"{\"events\":[1]}";
        assert!(
            !verify_xero_signature(tampered, &sig, key),
            "a body mutation must fail the verifier"
        );

        let wrong_key = b"not-the-key";
        assert!(
            !verify_xero_signature(body, &sig, wrong_key),
            "a key mismatch must fail the verifier"
        );
    }

    #[test]
    fn quickbooks_verifier_accepts_a_signature_produced_with_the_same_token() {
        let body = b"{\"eventNotifications\":[]}";
        let token = b"quickbooks-verifier-token";
        let mut mac = HmacSha256::new_from_slice(token).unwrap();
        mac.update(body);
        let sig = BASE64_STANDARD.encode(mac.finalize().into_bytes());

        assert!(verify_quickbooks_signature(body, &sig, token));

        let tampered = b"{\"eventNotifications\":[{}]}";
        assert!(
            !verify_quickbooks_signature(tampered, &sig, token),
            "a body mutation must fail the verifier"
        );
    }

    #[test]
    fn a_malformed_base64_signature_fails_the_verifier_rather_than_erroring_out() {
        let body = b"{}";
        let key = b"k";
        assert!(!verify_xero_signature(body, "@@not-base64@@", key));
        assert!(!verify_quickbooks_signature(body, "@@not-base64@@", key));
    }

    #[test]
    fn an_empty_body_still_verifies_with_a_matching_signature() {
        let body: &[u8] = b"";
        let key = b"edge-case-key";
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(body);
        let sig = BASE64_STANDARD.encode(mac.finalize().into_bytes());
        assert!(verify_xero_signature(body, &sig, key));
        assert!(verify_quickbooks_signature(body, &sig, key));
    }

    /// The verifiers tolerate the leading / trailing whitespace a proxy
    /// sometimes adds on a header, so a valid signature does not fail
    /// over a transport quirk. Matching the Stripe-signature verifier's
    /// `trim()` posture (provider::stripe).
    #[test]
    fn leading_whitespace_on_the_header_is_tolerated() {
        let body = b"{}";
        let key = b"k";
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(body);
        let sig = BASE64_STANDARD.encode(mac.finalize().into_bytes());
        let padded = format!(" {sig}  ");
        assert!(verify_xero_signature(body, &padded, key));
    }
}
