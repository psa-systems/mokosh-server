//! Request-body text normalization (PMS-924).
//!
//! [`sanitize_invisible`] is re-exported from `mokosh-types` so the server, the
//! shared DTO validators and the WASM client all use one definition (the same
//! shape as `validation::validate_slug`, PMS-898). The rest of this module is
//! the HTTP half: a middleware that applies it to every JSON request body
//! before deserialization, so no handler has to opt in and a route added later
//! cannot forget to.

pub use mokosh_types::text::sanitize_invisible;

/// Request-body field names whose value the sanitizer must NOT touch, matched
/// exactly against the ASCII-lowercased JSON key at any depth. The whole
/// subtree under a matching key is skipped, which is what covers the nested
/// payment-gateway `config` blob (`{"config":{"secret_key":...}}`).
///
/// A password, token, API key, webhook secret or recovery code is compared byte
/// for byte against something stored elsewhere, and may legitimately contain a
/// no-break space or a format character. Rewriting one turns a correct
/// credential into a failed login with nothing in the logs to explain it, so
/// this is the one place where "sanitize everything" is wrong.
///
/// Deliberately NOT here, because on the request side each names user-facing
/// text rather than a credential:
///
/// - `key`: the only request DTO field with this name is
///   `UpsertTenantSettingRequest::key`, a settings key the user types. The
///   `key` in `CreateApiKeyResponse` is response-only and never parsed here.
/// - `username`: the credential-vault and SMTP username are login identifiers a
///   person retypes, and a stray trailing space in one is the bug, not the data.
///
/// Kept sorted and unique so the lookup can binary-search;
/// `the_secret_field_list_is_sorted_and_unique` fails the build otherwise.
pub const SECRET_FIELD_NAMES: &[&str] = &[
    "access_token",
    "api_key",
    "api_keys",
    "api_secret",
    "approval_code",
    "backup_code",
    "backup_codes",
    "client_secret",
    "code",
    "confirm_password",
    "current_password",
    "mfa_code",
    "mfa_secret",
    "new_password",
    "old_password",
    "otp",
    "otp_code",
    "password",
    "password_hash",
    "portal_password",
    "portal_password_hash",
    "private_key",
    "recovery_code",
    "recovery_codes",
    "refresh_token",
    "reset_token",
    "secret",
    "secret_key",
    "signature",
    "signing_secret",
    "token",
    "token_hash",
    "totp_code",
    "totp_secret",
    "webhook_secret",
];

/// True when `key` names a credential whose bytes must reach the handler
/// untouched. Matching is exact on the ASCII-lowercased key: a substring rule
/// would also swallow fields like `password_policy_description`.
pub fn is_secret_field(key: &str) -> bool {
    SECRET_FIELD_NAMES
        .binary_search(&key.to_ascii_lowercase().as_str())
        .is_ok()
}

/// Sanitize every string in a parsed JSON tree in place, skipping the subtree
/// under any [`SECRET_FIELD_NAMES`] key. Returns `true` when anything changed,
/// so the caller can forward the original bytes untouched when nothing did.
///
/// Object keys are sanitized as well as values: a key carrying a zero width
/// space is the same silent-mismatch bug one level up.
///
/// "Changed" is decided by comparing bytes, not by matching the `Cow` variant
/// [`sanitize_invisible`] returns: a value needing only a trim comes back
/// borrowed and is still a different value.
///
/// Recursion is bounded by `serde_json`'s own 128-level nesting limit, which
/// rejects a deeper document at parse time before this ever runs.
pub fn sanitize_json_tree(value: &mut serde_json::Value) -> bool {
    use serde_json::Value;
    let mut changed = false;
    match value {
        Value::String(s) => {
            let clean = sanitize_invisible(s);
            let replacement = (clean.as_bytes() != s.as_bytes()).then(|| clean.into_owned());
            if let Some(clean) = replacement {
                *s = clean;
                changed = true;
            }
        }
        Value::Array(items) => {
            for item in items {
                changed |= sanitize_json_tree(item);
            }
        }
        Value::Object(map) => {
            let taken = std::mem::take(map);
            let mut rebuilt = serde_json::Map::with_capacity(taken.len());
            for (key, mut item) in taken {
                if !is_secret_field(&key) {
                    changed |= sanitize_json_tree(&mut item);
                }
                let clean = sanitize_invisible(&key);
                if clean.as_bytes() == key.as_bytes() {
                    drop(clean);
                    rebuilt.insert(key, item);
                } else {
                    changed = true;
                    rebuilt.insert(clean.into_owned(), item);
                }
            }
            *map = rebuilt;
        }
        _ => {}
    }
    changed
}

#[cfg(feature = "server")]
pub use server_impl::sanitize_json_body;

#[cfg(feature = "server")]
mod server_impl {
    use super::sanitize_json_tree;
    use crate::utils::error::AppError;
    use axum::body::{Body, Bytes};
    use axum::extract::Request;
    use axum::http::{header, HeaderValue};
    use axum::middleware::Next;
    use axum::response::{IntoResponse, Response};

    /// Largest JSON body the sanitizer buffers, matching the largest the server
    /// accepts anywhere (`data_transfer::IMPORT_MAX_BYTES`, 25 MB). A body that
    /// declares more via `Content-Length` is forwarded untouched rather than
    /// buffered, so the route's own `DefaultBodyLimit` stays the single
    /// authority on what is accepted and the sanitizer never holds bytes it
    /// would only reject.
    const MAX_SANITIZED_JSON_BYTES: usize = 25 * 1024 * 1024;

    /// Request paths the sanitizer must not rewrite, matched as a prefix
    /// against the full (pre-nesting) path.
    ///
    /// Each authenticates itself with an HMAC computed over the raw request
    /// bytes, so rewriting a single byte turns a valid signature into a 401
    /// (the same trap PMS-195 documents inside the RMM handler). The bodies are
    /// machine-generated payloads from Stripe, Bunyip and RMM agents, not text
    /// a person typed, so there is nothing here for the sanitizer to fix.
    const RAW_BODY_PATHS: &[&str] = &[
        "/api/v1/bunyip/",
        "/api/v1/rmm/alerts",
        "/api/v1/stripe/",
        // PMS-969: not an HMAC, but the same bargain. PayPal verifies a
        // delivery by being sent the body back and comparing it to what it
        // delivered, so a byte rewritten here is a FAILURE there.
        "/api/v1/paypal/",
    ];

    /// True for a `Content-Type` axum's `Json` extractor would accept:
    /// `application/json` or any `application/...+json`. Anything else
    /// (multipart uploads, attachment bodies, raw email payloads, form
    /// encodings) is forwarded byte-identical and is never buffered.
    fn is_json_content_type(value: &str) -> bool {
        // `split` always yields at least one item, so the `unwrap_or` is a
        // formality rather than a dropped failure.
        let essence = value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let Some(subtype) = essence.strip_prefix("application/") else {
            return false;
        };
        subtype == "json" || subtype.ends_with("+json")
    }

    /// Read a request header as a string, logging and reporting absence when
    /// the value is not visible ASCII.
    ///
    /// Deliberate suppression: a header this layer cannot read means it does
    /// not sanitize, and the request is forwarded byte-identical to the
    /// extractor that rejects it with the canonical 415 / 400. Nothing
    /// downstream reads the `None` as "header was absent and all is well" -
    /// both call sites treat it as "do not touch this body". `debug`, not
    /// `warn`, because the value is attacker-supplied and the real rejection is
    /// logged and returned one layer in.
    fn header_str(
        headers: &axum::http::HeaderMap,
        name: axum::http::header::HeaderName,
    ) -> Option<&str> {
        let raw = headers.get(&name)?;
        match raw.to_str() {
            Ok(value) => Some(value),
            Err(err) => {
                tracing::debug!(
                    header = %name,
                    error = %err,
                    "request header is not visible ASCII; forwarding the body unsanitized",
                );
                None
            }
        }
    }

    /// Strip invisible characters from every string in a JSON request body
    /// before any extractor sees it (PMS-924).
    ///
    /// Mounted once, innermost of the outer router's layers, so it sees the
    /// full un-nested path and covers the PSA, public, portal and webhook
    /// subtrees in one place. A per-handler `SanitizedJson<T>` extractor would
    /// have to be remembered on all 157 `Json<T>` handlers and on every route
    /// added afterwards; that is the failure mode this exists to remove.
    ///
    /// Pass-through cases, all byte-identical: a non-JSON content type, a
    /// signature-verified path in [`RAW_BODY_PATHS`], a body larger than
    /// [`MAX_SANITIZED_JSON_BYTES`], a body that is not valid JSON (the `Json`
    /// extractor owns that 400), and a body that is already clean.
    pub async fn sanitize_json_body(request: Request, next: Next) -> Response {
        let path = request.uri().path();
        if RAW_BODY_PATHS.iter().any(|p| path.starts_with(p)) {
            return next.run(request).await;
        }
        let is_json =
            header_str(request.headers(), header::CONTENT_TYPE).is_some_and(is_json_content_type);
        if !is_json {
            return next.run(request).await;
        }
        // A Content-Length that is absent or does not parse reads as "unknown",
        // which falls through to the `to_bytes` cap below. That is the
        // conservative direction (the cap still bounds what is buffered), and
        // hyper has already rejected a malformed value before this runs.
        let declared_len = header_str(request.headers(), header::CONTENT_LENGTH).and_then(|v| {
            v.parse::<usize>()
                .inspect_err(|err| {
                    tracing::debug!(value = %v, error = %err, "unparseable Content-Length");
                })
                .ok()
        });
        if declared_len.is_some_and(|len| len > MAX_SANITIZED_JSON_BYTES) {
            return next.run(request).await;
        }

        let (mut parts, body) = request.into_parts();
        let path = parts.uri.path().to_owned();
        let bytes = match axum::body::to_bytes(body, MAX_SANITIZED_JSON_BYTES).await {
            Ok(bytes) => bytes,
            Err(err) => {
                // Loud, not silent: the body is gone, so the request cannot be
                // forwarded and the caller gets the reason with the status.
                tracing::warn!(
                    %path,
                    error = %err,
                    "could not buffer JSON request body for invisible-character sanitization",
                );
                return AppError::PayloadTooLarge(
                    "The request body could not be read.".to_string(),
                )
                .into_response();
            }
        };

        let sanitized = sanitize_bytes(&bytes, &path);
        let len = sanitized.len();
        if len != bytes.len() {
            // `DefaultBodyLimit` reads `Content-Length` as a fast path, so a
            // stale value here would reject a body that is now smaller.
            parts
                .headers
                .insert(header::CONTENT_LENGTH, HeaderValue::from(len));
        }
        next.run(Request::from_parts(parts, Body::from(sanitized)))
            .await
    }

    /// Parse, sanitize and re-serialize `bytes`, or hand them back unchanged.
    /// Split out from the middleware so the unit tests below can drive it
    /// without standing up a router.
    fn sanitize_bytes(bytes: &Bytes, path: &str) -> Bytes {
        if bytes.is_empty() {
            return bytes.clone();
        }
        let mut value: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(err) => {
                // Not an error to report here: forwarding the original bytes
                // lets the `Json` extractor reject them with the canonical
                // envelope, which is the response the caller should see.
                tracing::debug!(
                    %path,
                    error = %err,
                    "request body is not valid JSON; forwarding unsanitized",
                );
                return bytes.clone();
            }
        };
        if !sanitize_json_tree(&mut value) {
            return bytes.clone();
        }
        match serde_json::to_vec(&value) {
            Ok(out) => Bytes::from(out),
            Err(err) => {
                // Re-serializing a `Value` that just came out of the parser
                // cannot fail in practice; if it ever does, the original body
                // is still valid and the request is better served than dropped.
                tracing::error!(
                    %path,
                    error = %err,
                    "could not re-serialize sanitized JSON body; forwarding the original",
                );
                bytes.clone()
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn sanitize(json: &str) -> String {
            let out = sanitize_bytes(&Bytes::from(json.to_owned()), "/test");
            String::from_utf8(out.to_vec()).expect("sanitized body is UTF-8")
        }

        #[test]
        fn json_content_types_are_recognized() {
            for accepted in [
                "application/json",
                "application/json; charset=utf-8",
                "Application/JSON",
                "application/merge-patch+json",
            ] {
                assert!(is_json_content_type(accepted), "{accepted:?}");
            }
            for rejected in [
                "multipart/form-data; boundary=x",
                "application/octet-stream",
                "text/plain",
                "message/rfc822",
                "application/x-www-form-urlencoded",
                "",
            ] {
                assert!(!is_json_content_type(rejected), "{rejected:?}");
            }
        }

        #[test]
        fn nested_objects_and_arrays_are_sanitized() {
            let out = sanitize(
                "{\"name\":\"Acme\u{200b}\",\
                 \"sites\":[{\"city\":\"Raleigh \"},\"Durham\u{feff}\"]}",
            );
            let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(parsed["name"], "Acme");
            assert_eq!(parsed["sites"][0]["city"], "Raleigh");
            assert_eq!(parsed["sites"][1], "Durham");
        }

        #[test]
        fn object_keys_are_sanitized_too() {
            let out = sanitize("{\"na\u{200b}me\":\"Acme\"}");
            let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(parsed["name"], "Acme");
        }

        #[test]
        fn secret_fields_are_left_byte_identical() {
            // Every exempt name, nested one level down so the subtree skip is
            // exercised as well as the top-level match.
            for field in super::super::SECRET_FIELD_NAMES {
                let body = format!("{{\"config\":{{\"{field}\":\"p\u{200b}a\u{00a0}ss \"}}}}");
                let out = sanitize(&body);
                let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
                assert_eq!(
                    parsed["config"][field], "p\u{200b}a\u{00a0}ss ",
                    "{field} must not be rewritten"
                );
            }
        }

        #[test]
        fn a_secret_key_matches_case_insensitively() {
            let out = sanitize("{\"Password\":\"p\u{200b}ass \"}");
            let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(parsed["Password"], "p\u{200b}ass ");
        }

        #[test]
        fn a_clean_body_is_forwarded_byte_identical() {
            let body = r#"{"b":"Acme","a":[1,2,{"c":null}],  "d": true}"#;
            assert_eq!(sanitize(body), body);
        }

        #[test]
        fn an_invalid_json_body_is_forwarded_untouched() {
            let body = "{not json at all";
            assert_eq!(sanitize(body), body);
            assert_eq!(sanitize(""), "");
        }

        #[test]
        fn non_string_scalars_are_untouched() {
            let body = r#"{"n":1.5,"b":false,"z":null}"#;
            assert_eq!(sanitize(body), body);
        }

        /// A body that changed is re-serialized from the parsed tree, so every
        /// number in it makes a round trip. Money and hours fields bind to
        /// `DECIMAL` columns, and a rewrite that shifted one would be a far
        /// worse bug than the invisible character it was fixing.
        #[test]
        fn numbers_survive_the_rewrite_textually() {
            let out = sanitize(
                "{\"name\":\"Acme\u{200b}\",\"amount\":1234.56,\"hours\":0.25,\
                 \"qty\":3,\"rate\":8.2500,\"neg\":-99.99,\"big\":9999999999.99}",
            );
            let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(parsed["name"], "Acme", "the body really was rewritten");
            assert_eq!(parsed["amount"].to_string(), "1234.56");
            assert_eq!(parsed["hours"].to_string(), "0.25");
            assert_eq!(parsed["qty"].to_string(), "3");
            assert_eq!(parsed["neg"].to_string(), "-99.99");
            assert_eq!(parsed["big"].to_string(), "9999999999.99");
            // `8.2500` is an f64 in `serde_json` with or without this layer, so
            // it comes back in its shortest round-tripping form. Pinned so a
            // future change to the number representation is a failing test
            // rather than a silent shift in a stored rate.
            assert_eq!(parsed["rate"].to_string(), "8.25");
        }

        #[test]
        fn the_reported_phone_number_is_repaired() {
            let out = sanitize("{\"phone\":\"919-397-4144\u{200b}\"}");
            let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(parsed["phone"], "919-397-4144");
        }

        #[test]
        fn every_signature_verified_path_is_exempt() {
            // Guards the four verify-over-raw-bytes receivers. If a fifth is
            // added without a `RAW_BODY_PATHS` entry, its verification starts
            // failing; this at least pins the four that exist.
            for path in [
                "/api/v1/stripe/webhooks/00000000-0000-0000-0000-000000000001",
                "/api/v1/paypal/webhooks/00000000-0000-0000-0000-000000000001",
                "/api/v1/bunyip/webhooks/account-deleted",
                "/api/v1/rmm/alerts",
            ] {
                assert!(
                    RAW_BODY_PATHS.iter().any(|p| path.starts_with(p)),
                    "{path} must bypass the sanitizer"
                );
            }
            assert!(
                !RAW_BODY_PATHS
                    .iter()
                    .any(|p| "/api/v1/rmm/connections".starts_with(p)),
                "the rest of the RMM surface must still be sanitized",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_field_list_is_sorted_and_unique() {
        let mut sorted = SECRET_FIELD_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted, SECRET_FIELD_NAMES,
            "SECRET_FIELD_NAMES must stay sorted and unique: is_secret_field binary-searches it",
        );
    }

    #[test]
    fn secret_fields_are_recognized_and_ordinary_ones_are_not() {
        for secret in ["password", "New_Password", "WEBHOOK_SECRET", "token"] {
            assert!(is_secret_field(secret), "{secret} should be exempt");
        }
        for ordinary in [
            "name",
            "description",
            "subject",
            "phone",
            "key",
            "username",
            "password_policy_description",
            "postal_code",
            "tokens",
        ] {
            assert!(!is_secret_field(ordinary), "{ordinary} should be sanitized");
        }
    }
}
