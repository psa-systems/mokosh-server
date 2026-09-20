//! A `Json<T>` extractor that reuses the sanitizer's parse instead of paying
//! for it twice (PMS-1243).
//!
//! [`sanitize_json_body`](crate::utils::text::sanitize_json_body) already
//! parses every JSON request body once, to sanitize it, and (on a body it
//! parsed successfully) stashes the resulting [`serde_json::Value`] as a
//! request extension. This `Json<T>` reads that extension and deserializes
//! `T` from the already-parsed tree via [`serde_json::from_value`] rather
//! than re-buffering and re-parsing the raw body the way `axum::Json<T>`
//! would. A request the middleware left untouched (a non-JSON content type,
//! a signature-verified webhook path, an unparseable body) carries no
//! extension, so extraction falls back to `axum::Json<T>` unchanged.
//!
//! Drop-in replacement: same extraction behavior (`FromRequest`, last
//! position only), same response behavior (`IntoResponse` serializes `T` the
//! way `axum::Json` does), so every route swaps its `axum::Json` import for
//! this one and nothing else about the handler changes.

use axum::extract::{FromRequest, OptionalFromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// The parsed request body [`sanitize_json_body`](crate::utils::text::sanitize_json_body)
/// leaves in the request extensions for [`Json`] to consume instead of
/// re-parsing the raw bytes.
#[derive(Clone)]
pub(crate) struct ParsedJsonBody(pub serde_json::Value);

/// Call counters proving the PMS-1243 acceptance criterion: a well-formed
/// JSON body is parsed by [`serde_json`] exactly once per request. Test-only,
/// so production pays nothing for them.
#[cfg(test)]
pub(crate) mod parse_counters {
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::{Mutex, MutexGuard};

    /// Incremented once per full-body `serde_json` parse inside
    /// [`sanitize_json_body`](crate::utils::text::sanitize_json_body) (the
    /// middleware's `parse_and_sanitize`). A well-formed JSON POST should
    /// trip this exactly once.
    pub static MIDDLEWARE_PARSES: AtomicUsize = AtomicUsize::new(0);

    /// Incremented when [`super::Json`]'s fallback path re-parses the raw
    /// body via `axum::Json`, which only happens when no
    /// [`super::ParsedJsonBody`] extension was cached. Should stay zero for a
    /// request the middleware already sanitized.
    pub static FALLBACK_PARSES: AtomicUsize = AtomicUsize::new(0);

    /// These counters are process-wide statics, and cargo runs tests
    /// concurrently by default; every test that reads them (directly, or
    /// through [`super::super::text`]'s `sanitize_bytes`, which also drives
    /// `parse_and_sanitize`) must hold this lock for the span it cares about
    /// the counts, not just around the individual increments. A
    /// `tokio::sync::Mutex`, not `std::sync::Mutex`, because the callers in
    /// `json::tests` hold the guard across an `.await`.
    static LOCK: Mutex<()> = Mutex::const_new(());

    pub async fn lock() -> MutexGuard<'static, ()> {
        LOCK.lock().await
    }

    /// For the synchronous `#[test]` functions in `text::server_impl::tests`,
    /// which have no runtime to `.await` on.
    pub fn blocking_lock() -> MutexGuard<'static, ()> {
        LOCK.blocking_lock()
    }
}

/// Drop-in replacement for `axum::Json<T>`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

/// Mirrors `axum::extract::rejection::JsonRejection`'s status/body shape for
/// the one error case it does not cover: deserializing `T` out of a tree the
/// sanitizer already parsed.
pub enum JsonRejection {
    Axum(axum::extract::rejection::JsonRejection),
    Deserialize(serde_json::Error),
}

impl IntoResponse for JsonRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Axum(rejection) => rejection.into_response(),
            Self::Deserialize(err) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Failed to deserialize the JSON body into the target type: {err}"),
            )
                .into_response(),
        }
    }
}

impl<T, S> FromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = JsonRejection;

    async fn from_request(mut req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if let Some(ParsedJsonBody(value)) = req.extensions_mut().remove::<ParsedJsonBody>() {
            return serde_json::from_value(value)
                .map(Json)
                .map_err(JsonRejection::Deserialize);
        }
        #[cfg(test)]
        parse_counters::FALLBACK_PARSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        <axum::Json<T> as FromRequest<S>>::from_request(req, state)
            .await
            .map(|axum::Json(value)| Json(value))
            .map_err(JsonRejection::Axum)
    }
}

/// Backs `Option<Json<T>>` (a handler that treats a missing body as
/// optional), matching `axum::Json`'s own `OptionalFromRequest`: `None` only
/// when the request carries no `Content-Type` at all.
impl<T, S> OptionalFromRequest<S> for Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = JsonRejection;

    async fn from_request(mut req: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
        if let Some(ParsedJsonBody(value)) = req.extensions_mut().remove::<ParsedJsonBody>() {
            return serde_json::from_value(value)
                .map(|v| Some(Json(v)))
                .map_err(JsonRejection::Deserialize);
        }
        #[cfg(test)]
        parse_counters::FALLBACK_PARSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        <axum::Json<T> as OptionalFromRequest<S>>::from_request(req, state)
            .await
            .map(|opt| opt.map(|axum::Json(value)| Json(value)))
            .map_err(JsonRejection::Axum)
    }
}

impl<T> IntoResponse for Json<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

impl<T> std::ops::Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> From<T> for Json<T> {
    fn from(inner: T) -> Self {
        Json(inner)
    }
}

/// PMS-1243 acceptance-criteria tests. These drive [`Json`] through the real
/// [`sanitize_json_body`](crate::utils::text::sanitize_json_body) middleware
/// with an in-process router (`tower::ServiceExt::oneshot`), no database
/// needed, and read the outcome off [`parse_counters`] rather than asserting
/// on internals.
#[cfg(test)]
mod tests {
    use super::parse_counters;
    use super::Json;
    use axum::body::{Body, Bytes};
    use axum::http::{Request, StatusCode};
    use axum::middleware::from_fn;
    use axum::routing::post;
    use axum::Router;
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;

    fn reset_counters() {
        parse_counters::MIDDLEWARE_PARSES.store(0, Ordering::Relaxed);
        parse_counters::FALLBACK_PARSES.store(0, Ordering::Relaxed);
    }

    async fn echo(Json(value): Json<serde_json::Value>) -> StatusCode {
        let _ = value;
        StatusCode::OK
    }

    fn app() -> Router {
        Router::new()
            .route("/echo", post(echo))
            .layer(from_fn(crate::utils::text::sanitize_json_body))
    }

    /// Acceptance criterion 1: a well-formed JSON POST performs exactly one
    /// `serde_json` parse (the middleware's), and the extractor's
    /// re-parsing fallback is never taken.
    #[tokio::test]
    async fn a_well_formed_json_body_is_parsed_exactly_once() {
        let _guard = parse_counters::lock().await;
        reset_counters();
        let body = serde_json::json!({"name": "Acme"}).to_string();
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(parse_counters::MIDDLEWARE_PARSES.load(Ordering::Relaxed), 1);
        assert_eq!(parse_counters::FALLBACK_PARSES.load(Ordering::Relaxed), 0);
    }

    /// Acceptance criterion 2: a 24 MB JSON array of one-character strings,
    /// under the sanitizer's 25 MB cap, still performs exactly one full-body
    /// parse, the same single buffer the pre-PMS-1243 middleware already
    /// held (no second, re-serialized copy and no second parse downstream).
    #[tokio::test]
    async fn a_24mb_json_array_is_parsed_exactly_once() {
        let _guard = parse_counters::lock().await;
        reset_counters();
        let items = vec!["a"; 6_300_000];
        let body = serde_json::to_string(&items).unwrap();
        assert!(
            body.len() > 24 * 1024 * 1024 && body.len() < 25 * 1024 * 1024,
            "test body ({} bytes) must sit inside the sanitizer's 25 MB cap",
            body.len()
        );
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(parse_counters::MIDDLEWARE_PARSES.load(Ordering::Relaxed), 1);
        assert_eq!(parse_counters::FALLBACK_PARSES.load(Ordering::Relaxed), 0);
    }

    /// Acceptance criterion 3: a chunked body with no `Content-Length` is
    /// still bounded by `MAX_SANITIZED_JSON_BYTES` at the `to_bytes` call,
    /// unchanged by PMS-1243. `Body::from_stream` produces exactly that
    /// shape: no known length, delivered as chunks.
    #[tokio::test]
    async fn a_chunked_body_with_no_content_length_is_still_capped() {
        let _guard = parse_counters::lock().await;
        reset_counters();
        let chunk = Bytes::from(vec![b'a'; 1024 * 1024]);
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            std::iter::repeat_with(|| Ok(chunk.clone()))
                .take(26)
                .collect();
        let body = Body::from_stream(tokio_stream::iter(chunks));
        let request = Request::builder()
            .method("POST")
            .uri("/echo")
            .header("content-type", "application/json")
            .body(body)
            .unwrap();
        assert!(
            request
                .headers()
                .get(axum::http::header::CONTENT_LENGTH)
                .is_none(),
            "the test body must carry no Content-Length for this to exercise the chunked path",
        );
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // The cap is enforced by `to_bytes` before any parse is attempted.
        assert_eq!(parse_counters::MIDDLEWARE_PARSES.load(Ordering::Relaxed), 0);
        assert_eq!(parse_counters::FALLBACK_PARSES.load(Ordering::Relaxed), 0);
    }
}
