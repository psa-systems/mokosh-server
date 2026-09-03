//! PMS-958: the S3-compatible provider behind [`ObjectProvider`].
//!
//! No client crate. The trait needs five operations (`PUT`, `GET`, `HEAD`,
//! `DELETE`, and a `PUT` with `x-amz-copy-source` for the atomic `rename`), no
//! listing, no multipart (the largest object is a 25 MiB ticket attachment
//! against a 5 GB single-PUT limit) and no XML to parse. What that costs is one
//! signing algorithm, SigV4, which is specified to the byte and has published
//! test vectors; the [`sigv4`] module below is checked against two of them.
//! `aws-sdk-s3` would add roughly fifty crates and its own HTTP stack beside
//! the `reqwest` already here, `rust-s3` fewer but still its own client and XML
//! and time crates, and either lands in the PMS-781 dependency layer for every
//! cold build.
//!
//! S3-COMPATIBLE rather than AWS, which is why `S3_ENDPOINT` is required and
//! path-style addressing (`{endpoint}/{bucket}/{key}`) is the default: that is
//! the form MinIO, R2 and Backblaze all serve. `S3_PATH_STYLE=false` selects
//! virtual-hosted (`{bucket}.{host}/{key}`) for a deployment that wants it.
//!
//! The object key is [`ObjectKey::relative_path`] joined with `/`, so the
//! tenant scoping this crate pins for the local layout is the same string on
//! the wire here, and the same two-tenants-cannot-collide assertions hold.
//!
//! Credentials are operator env, per the rule PMS-912 settled: a credential
//! that belongs to the deployment lives beside `INFISICAL_CLIENT_SECRET` and
//! `SMTP_PASSWORD`, and only a credential that belongs to a tenant goes in the
//! `SecretProvider`. Storage is per deployment. A per-tenant bucket later is a
//! lookup of `(bucket, credentials)` by tenant in front of these same five
//! requests, because the key already carries the tenant.
//!
//! The endpoint is deliberately NOT screened by `utils::net::guard_outbound_url`:
//! it comes from operator env, like `INFISICAL_ADDRESS` and the Stripe API
//! base, and an object store on a private network is the normal case rather
//! than the SSRF that guard exists to refuse.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, Method, Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio_stream::StreamExt;
use tokio_util::io::StreamReader;
use url::Url;

use super::{ObjectKey, ObjectProvider, ObjectReader};
use crate::utils::error::{AppError, AppResult};

/// The hash of an empty body, which every request without one carries as
/// `x-amz-content-sha256`.
const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Where the objects go and how to sign for them.
#[derive(Clone)]
pub struct S3Config {
    pub endpoint: Url,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// `{endpoint}/{bucket}/{key}` when true, `{bucket}.{host}/{key}` when
    /// false.
    pub path_style: bool,
}

/// By hand, so the secret never reaches a log line through `{:?}`.
impl fmt::Debug for S3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint.as_str())
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("path_style", &self.path_style)
            .finish()
    }
}

impl S3Config {
    /// The ONE reader of the `S3_*` variables, the way `StorageConfig::from_env`
    /// is the only reader of `ATTACHMENT_DIR`.
    pub fn from_env() -> AppResult<Self> {
        Self::parse(|name| std::env::var(name).ok())
    }

    /// The rule itself, over a lookup rather than the process environment so
    /// it can be tested under a concurrent runner without `set_var`.
    ///
    /// A forwarded-but-unset variable arrives as `""` (PMS-836), so blank is
    /// unset throughout. The endpoint, bucket and both halves of the credential
    /// are required, because `STORAGE_BACKEND=s3` with any of them missing is
    /// an operator who asked for S3 and would otherwise get a 500 on the first
    /// upload; the region defaults to `us-east-1`, which is what every
    /// S3-compatible store outside AWS expects to see in the signature.
    pub fn parse(var: impl Fn(&str) -> Option<String>) -> AppResult<Self> {
        let get = |name: &str| {
            var(name)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let required = |name: &str| {
            get(name).ok_or_else(|| {
                AppError::Configuration(format!("STORAGE_BACKEND=s3 requires {name} to be set"))
            })
        };

        let raw_endpoint = required("S3_ENDPOINT")?;
        let endpoint = Url::parse(&raw_endpoint).map_err(|e| {
            AppError::Configuration(format!("S3_ENDPOINT {raw_endpoint:?} is not a URL: {e}"))
        })?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
            return Err(AppError::Configuration(format!(
                "S3_ENDPOINT {raw_endpoint:?} must be an http or https URL with a host"
            )));
        }
        if endpoint.query().is_some() || endpoint.fragment().is_some() {
            return Err(AppError::Configuration(format!(
                "S3_ENDPOINT {raw_endpoint:?} must not carry a query or a fragment"
            )));
        }

        let bucket = required("S3_BUCKET")?;
        validate_bucket_name(&bucket)?;

        let path_style = match get("S3_PATH_STYLE").as_deref() {
            None => true,
            Some("true" | "1" | "yes") => true,
            Some("false" | "0" | "no") => false,
            Some(other) => {
                return Err(AppError::Configuration(format!(
                    "S3_PATH_STYLE {other:?} is not a boolean; expected true or false"
                )))
            }
        };

        Ok(Self {
            endpoint,
            bucket,
            region: get("S3_REGION").unwrap_or_else(|| "us-east-1".to_string()),
            access_key_id: required("S3_ACCESS_KEY_ID")?,
            secret_access_key: required("S3_SECRET_ACCESS_KEY")?,
            path_style,
        })
    }
}

/// The bucket name is the one operator string that lands in a URL path or a
/// hostname, so it is held to the S3 naming rules rather than escaped: an
/// allowlist, like `validate_segment` for the logo extension.
fn validate_bucket_name(bucket: &str) -> AppResult<()> {
    let ok = (3..=63).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && !bucket.starts_with(['-', '.'])
        && !bucket.ends_with(['-', '.'])
        && !bucket.contains("..");
    if !ok {
        return Err(AppError::Configuration(format!(
            "S3_BUCKET {bucket:?} is not a valid bucket name"
        )));
    }
    Ok(())
}

/// The S3-compatible provider.
pub struct S3Provider {
    config: S3Config,
    http: Client,
}

impl fmt::Debug for S3Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Provider")
            .field("config", &self.config)
            .finish()
    }
}

impl S3Provider {
    pub fn new(config: S3Config) -> AppResult<Self> {
        let http = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            // Generous, because a `put` carries a whole attachment in one
            // request and a slow link to a remote bucket is a real deployment;
            // bounded, because a request that never returns would hold the
            // upload handler forever.
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| AppError::Configuration(format!("could not build the S3 client: {e}")))?;
        Ok(Self { config, http })
    }

    pub fn from_env() -> AppResult<Self> {
        Self::new(S3Config::from_env()?)
    }

    pub fn config(&self) -> &S3Config {
        &self.config
    }

    /// The key on the wire: the same relative path the local provider uses and
    /// the ledger records, with `/` between the segments whatever the host OS.
    pub fn object_key(key: &ObjectKey) -> AppResult<String> {
        let path = key.relative_path()?;
        let segments: Vec<&str> = path
            .iter()
            .map(|s| {
                s.to_str()
                    .ok_or_else(|| AppError::Internal("object key is not UTF-8".to_string()))
            })
            .collect::<AppResult<_>>()?;
        Ok(segments.join("/"))
    }

    /// The URL and the `host` header for an object, or for the bucket itself
    /// when `object_key` is `None`.
    fn url_for(&self, object_key: Option<&str>) -> AppResult<(Url, String)> {
        let mut url = self.config.endpoint.clone();
        let base = url.path().trim_end_matches('/').to_string();
        let mut segments: Vec<String> = Vec::new();
        if self.config.path_style {
            segments.push(self.config.bucket.clone());
        } else {
            let host = url
                .host_str()
                .ok_or_else(|| AppError::Configuration("S3_ENDPOINT has no host".to_string()))?;
            let virtual_host = format!("{}.{host}", self.config.bucket);
            url.set_host(Some(&virtual_host)).map_err(|e| {
                AppError::Configuration(format!("cannot form a virtual-hosted S3 URL: {e}"))
            })?;
        }
        if let Some(object_key) = object_key {
            segments.extend(object_key.split('/').map(sigv4::uri_encode));
        }
        let path = if segments.is_empty() {
            format!("{base}/")
        } else {
            format!("{base}/{}", segments.join("/"))
        };
        url.set_path(&path);
        let host_header = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        };
        Ok((url, host_header))
    }

    /// One signed request. Every operation on the trait is a call to this.
    async fn request(
        &self,
        method: Method,
        object_key: Option<&str>,
        extra_headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> AppResult<Response> {
        let (url, host) = self.url_for(object_key)?;
        let payload_hash = if body.is_empty() {
            EMPTY_PAYLOAD_SHA256.to_string()
        } else {
            hex(&Sha256::digest(&body))
        };
        let now = chrono::Utc::now();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();

        let mut headers: Vec<(String, String)> = vec![
            ("host".to_string(), host),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), timestamp.clone()),
        ];
        headers.extend(
            extra_headers
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.clone())),
        );

        let authorization = sigv4::authorization_header(&sigv4::SigningInput {
            method: method.as_str(),
            canonical_uri: url.path(),
            canonical_query: url.query().unwrap_or_default(),
            headers: &headers,
            payload_hash: &payload_hash,
            timestamp: &timestamp,
            region: &self.config.region,
            service: "s3",
            access_key_id: &self.config.access_key_id,
            secret_access_key: &self.config.secret_access_key,
        });

        let mut request = self.http.request(method, url);
        for (name, value) in headers.iter().filter(|(name, _)| name != "host") {
            request = request.header(name.as_str(), value.as_str());
        }
        request = request.header("authorization", authorization);
        if !body.is_empty() {
            request = request.body(body);
        }
        request
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("S3 request failed: {e}")))
    }

    /// Create the bucket if it is not there.
    ///
    /// For a test harness and a first run against a fresh MinIO, which starts
    /// with no buckets at all. The server never calls this: a production
    /// bucket is provisioned with the credentials and the policy an operator
    /// chose, not by the application at boot with whatever rights it happens
    /// to hold. A bucket the caller already owns is not an error.
    pub async fn ensure_bucket(&self) -> AppResult<()> {
        let response = self.request(Method::PUT, None, &[], Vec::new()).await?;
        match response.status() {
            StatusCode::OK | StatusCode::CONFLICT => Ok(()),
            status => Err(unexpected("create bucket", status, response).await),
        }
    }
}

async fn unexpected(op: &str, status: StatusCode, response: Response) -> AppError {
    let body = response.text().await.unwrap_or_default();
    let snippet: String = body.chars().take(300).collect();
    AppError::Internal(format!("S3 {op} returned {status}: {snippet}"))
}

#[async_trait]
impl ObjectProvider for S3Provider {
    async fn put(&self, key: &ObjectKey, bytes: &[u8]) -> AppResult<()> {
        let object_key = Self::object_key(key)?;
        let response = self
            .request(Method::PUT, Some(&object_key), &[], bytes.to_vec())
            .await?;
        match response.status() {
            StatusCode::OK => Ok(()),
            status => Err(unexpected("put", status, response).await),
        }
    }

    async fn read(&self, key: &ObjectKey) -> AppResult<Vec<u8>> {
        let object_key = Self::object_key(key)?;
        let response = self
            .request(Method::GET, Some(&object_key), &[], Vec::new())
            .await?;
        match response.status() {
            StatusCode::OK => response
                .bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| AppError::Internal(format!("S3 read failed: {e}"))),
            // The local provider answers a missing file with `NotFound`, and
            // two callers lean on that to fall back to the legacy KB path.
            StatusCode::NOT_FOUND => Err(AppError::NotFound("object not found".to_string())),
            status => Err(unexpected("get", status, response).await),
        }
    }

    async fn open(&self, key: &ObjectKey) -> AppResult<ObjectReader> {
        let object_key = Self::object_key(key)?;
        let response = self
            .request(Method::GET, Some(&object_key), &[], Vec::new())
            .await?;
        match response.status() {
            StatusCode::OK => {
                let stream = response
                    .bytes_stream()
                    .map(|chunk| chunk.map_err(std::io::Error::other));
                Ok(Box::pin(StreamReader::new(stream)))
            }
            StatusCode::NOT_FOUND => Err(AppError::Internal("object blob missing".to_string())),
            status => Err(unexpected("get", status, response).await),
        }
    }

    async fn delete(&self, key: &ObjectKey) -> AppResult<()> {
        let object_key = Self::object_key(key)?;
        let response = self
            .request(Method::DELETE, Some(&object_key), &[], Vec::new())
            .await?;
        match response.status() {
            // Best-effort, like the local provider: a missing object says the
            // same thing as a deleted one.
            StatusCode::NO_CONTENT | StatusCode::OK | StatusCode::NOT_FOUND => Ok(()),
            status => Err(unexpected("delete", status, response).await),
        }
    }

    async fn exists(&self, key: &ObjectKey) -> AppResult<bool> {
        let object_key = Self::object_key(key)?;
        let response = self
            .request(Method::HEAD, Some(&object_key), &[], Vec::new())
            .await?;
        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            status => Err(unexpected("head", status, response).await),
        }
    }

    /// Server-side copy, then delete the source.
    ///
    /// The copy is the atomic half, which is what the trait promises: the
    /// destination either holds the whole object or nothing, because S3 does
    /// not expose a partially written object. The delete can still fail after
    /// a successful copy, and that leaves a complete duplicate at the source
    /// rather than a truncated object at the destination; the PMS-960 mover
    /// checks the destination first, so a retry reports the object moved and
    /// the duplicate is litter, never a wrong answer.
    ///
    /// A copy that fails is reported in the status line for a missing source
    /// and, for anything else, may come back as `200 OK` with an `<Error>`
    /// document in the body: a documented S3 behaviour for a copy that started
    /// and then failed, so the body is checked and not just the status.
    async fn rename(&self, from: &ObjectKey, to: &ObjectKey) -> AppResult<()> {
        let source_key = Self::object_key(from)?;
        let destination_key = Self::object_key(to)?;
        let copy_source = format!(
            "/{}/{}",
            self.config.bucket,
            source_key
                .split('/')
                .map(sigv4::uri_encode)
                .collect::<Vec<_>>()
                .join("/")
        );
        let response = self
            .request(
                Method::PUT,
                Some(&destination_key),
                &[("x-amz-copy-source", copy_source)],
                Vec::new(),
            )
            .await?;
        match response.status() {
            StatusCode::OK => {
                let body = response
                    .text()
                    .await
                    .map_err(|e| AppError::Internal(format!("S3 copy failed: {e}")))?;
                if body.contains("<Error>") {
                    let snippet: String = body.chars().take(300).collect();
                    return Err(AppError::Internal(format!(
                        "could not move object: copy failed after starting: {snippet}"
                    )));
                }
            }
            StatusCode::NOT_FOUND => {
                return Err(AppError::Internal(
                    "could not move object: source is not there".to_string(),
                ))
            }
            status => return Err(unexpected("copy", status, response).await),
        }
        let response = self
            .request(Method::DELETE, Some(&source_key), &[], Vec::new())
            .await?;
        match response.status() {
            StatusCode::NO_CONTENT | StatusCode::OK => Ok(()),
            status => Err(unexpected("delete after copy", status, response).await),
        }
    }

    fn location(&self, key: &ObjectKey) -> AppResult<String> {
        Ok(format!(
            "s3://{}/{}",
            self.config.bucket,
            Self::object_key(key)?
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// AWS Signature Version 4, as much of it as S3 needs.
///
/// Header-based signing, single-chunk payload, no query signing, no session
/// token. S3 differs from every other AWS service in one place worth naming:
/// the canonical URI is encoded ONCE, not twice, which is why the object key
/// is encoded when the URL is built and then taken from the URL as it is.
pub(crate) mod sigv4 {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    /// Everything the signature is over. Header names must already be
    /// lowercase; the function sorts them and trims their values as the
    /// specification requires.
    pub(crate) struct SigningInput<'a> {
        pub method: &'a str,
        pub canonical_uri: &'a str,
        pub canonical_query: &'a str,
        pub headers: &'a [(String, String)],
        pub payload_hash: &'a str,
        /// `YYYYMMDDTHHMMSSZ`.
        pub timestamp: &'a str,
        pub region: &'a str,
        pub service: &'a str,
        pub access_key_id: &'a str,
        pub secret_access_key: &'a str,
    }

    /// RFC 3986 unreserved characters stay; everything else is `%XX`. The
    /// encoding S3 expects for a path segment and for `x-amz-copy-source`.
    pub(crate) fn uri_encode(segment: &str) -> String {
        let mut out = String::with_capacity(segment.len());
        for byte in segment.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char)
                }
                other => out.push_str(&format!("%{other:02X}")),
            }
        }
        out
    }

    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Whitespace inside a header value is collapsed to single spaces and
    /// trimmed, per the canonical-headers rule.
    fn canonical_value(value: &str) -> String {
        value.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    pub(crate) fn authorization_header(input: &SigningInput<'_>) -> String {
        let mut headers: Vec<(&str, String)> = input
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), canonical_value(value)))
            .collect();
        headers.sort_by(|a, b| a.0.cmp(b.0));

        let canonical_headers: String = headers
            .iter()
            .map(|(name, value)| format!("{name}:{value}\n"))
            .collect();
        let signed_headers = headers
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(";");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            input.method,
            input.canonical_uri,
            input.canonical_query,
            canonical_headers,
            signed_headers,
            input.payload_hash
        );

        let date = &input.timestamp[..8];
        let scope = format!("{date}/{}/{}/aws4_request", input.region, input.service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
            input.timestamp,
            hex(&Sha256::digest(canonical_request.as_bytes()))
        );

        let k_date = hmac(
            format!("AWS4{}", input.secret_access_key).as_bytes(),
            date.as_bytes(),
        );
        let k_region = hmac(&k_date, input.region.as_bytes());
        let k_service = hmac(&k_region, input.service.as_bytes());
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()));

        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            input.access_key_id
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        /// `get-vanilla` from the AWS SigV4 test suite: the smallest published
        /// vector, and the one every implementation checks first.
        #[test]
        fn matches_the_aws_get_vanilla_vector() {
            let headers = vec![
                ("host".to_string(), "example.amazonaws.com".to_string()),
                ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
            ];
            let auth = authorization_header(&SigningInput {
                method: "GET",
                canonical_uri: "/",
                canonical_query: "",
                headers: &headers,
                payload_hash: EMPTY,
                timestamp: "20150830T123600Z",
                region: "us-east-1",
                service: "service",
                access_key_id: "AKIDEXAMPLE",
                secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            });
            assert_eq!(
                auth,
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
                 SignedHeaders=host;x-amz-date, \
                 Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
            );
        }

        /// The GET Object example from the S3 REST authentication guide, which
        /// is the vector that exercises `x-amz-content-sha256` and an extra
        /// signed header, and whose service is `s3`.
        #[test]
        fn matches_the_s3_get_object_example() {
            let headers = vec![
                (
                    "host".to_string(),
                    "examplebucket.s3.amazonaws.com".to_string(),
                ),
                ("range".to_string(), "bytes=0-9".to_string()),
                ("x-amz-content-sha256".to_string(), EMPTY.to_string()),
                ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
            ];
            let auth = authorization_header(&SigningInput {
                method: "GET",
                canonical_uri: "/test.txt",
                canonical_query: "",
                headers: &headers,
                payload_hash: EMPTY,
                timestamp: "20130524T000000Z",
                region: "us-east-1",
                service: "s3",
                access_key_id: "AKIAIOSFODNN7EXAMPLE",
                secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            });
            assert!(
                auth.ends_with(
                    "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
                ),
                "{auth}"
            );
            assert!(auth.contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"));
        }

        #[test]
        fn a_segment_is_encoded_once_and_only_where_needed() {
            assert_eq!(uri_encode("kb-articles"), "kb-articles");
            assert_eq!(
                uri_encode("3333-3333.png~x_y"),
                "3333-3333.png~x_y",
                "unreserved characters stay"
            );
            assert_eq!(uri_encode("a b/c"), "a%20b%2Fc");
            assert_eq!(uri_encode("%"), "%25");
        }

        #[test]
        fn header_values_are_trimmed_and_collapsed() {
            assert_eq!(canonical_value("  a   b \t c  "), "a b c");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    const TENANT: Uuid = Uuid::from_u128(0x1111_1111_1111_4111_8111_1111_1111_1111);
    const OTHER: Uuid = Uuid::from_u128(0x2222_2222_2222_4222_8222_2222_2222_2222);
    const OBJECT: Uuid = Uuid::from_u128(0x3333_3333_3333_4333_8333_3333_3333_3333);
    const DIGEST: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    fn vars<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    const FULL: &[(&str, &str)] = &[
        ("S3_ENDPOINT", "http://minio:9000"),
        ("S3_BUCKET", "mokosh"),
        ("S3_ACCESS_KEY_ID", "key"),
        ("S3_SECRET_ACCESS_KEY", "secret"),
    ];

    fn provider(pairs: &[(&str, &str)]) -> S3Provider {
        S3Provider::new(S3Config::parse(vars(pairs)).expect("config")).expect("client")
    }

    /// The key on the wire is the pinned local layout with `/` between the
    /// segments: the same tenant scoping, tested the same way.
    #[test]
    fn the_key_is_the_local_layout_with_slashes() {
        assert_eq!(
            S3Provider::object_key(&ObjectKey::ticket_attachment(TENANT, OBJECT)).unwrap(),
            format!("{TENANT}/{OBJECT}")
        );
        assert_eq!(
            S3Provider::object_key(&ObjectKey::tenant_logo(TENANT, "png")).unwrap(),
            format!("tenant-logos/{TENANT}.png")
        );
        assert_eq!(
            S3Provider::object_key(&ObjectKey::kb_attachment(TENANT, OBJECT)).unwrap(),
            format!("{TENANT}/kb-articles/{OBJECT}")
        );
        assert_eq!(
            S3Provider::object_key(&ObjectKey::legacy_kb_attachment(TENANT, OBJECT)).unwrap(),
            format!("kb-articles/{OBJECT}")
        );
        assert_eq!(
            S3Provider::object_key(&ObjectKey::financial_document(TENANT, OBJECT)).unwrap(),
            format!("{TENANT}/documents/{OBJECT}")
        );
        assert_eq!(
            S3Provider::object_key(&ObjectKey::branding_logo(TENANT, DIGEST)).unwrap(),
            format!("{TENANT}/branding/{DIGEST}")
        );
    }

    #[test]
    fn two_tenants_cannot_address_the_same_object() {
        for (mine, theirs) in [
            (
                ObjectKey::ticket_attachment(TENANT, OBJECT),
                ObjectKey::ticket_attachment(OTHER, OBJECT),
            ),
            (
                ObjectKey::tenant_logo(TENANT, "png"),
                ObjectKey::tenant_logo(OTHER, "png"),
            ),
            (
                ObjectKey::kb_attachment(TENANT, OBJECT),
                ObjectKey::kb_attachment(OTHER, OBJECT),
            ),
            (
                ObjectKey::financial_document(TENANT, OBJECT),
                ObjectKey::financial_document(OTHER, OBJECT),
            ),
            (
                ObjectKey::branding_logo(TENANT, DIGEST),
                ObjectKey::branding_logo(OTHER, DIGEST),
            ),
        ] {
            assert_ne!(
                S3Provider::object_key(&mine).unwrap(),
                S3Provider::object_key(&theirs).unwrap()
            );
        }
    }

    /// The same refusals the local layout makes, because the key is built by
    /// the same function: a hostile extension never reaches the wire.
    #[test]
    fn a_hostile_extension_is_refused_before_it_becomes_a_key() {
        for hostile in ["../x", "a/b", "", &"a".repeat(17)] {
            assert!(
                S3Provider::object_key(&ObjectKey::tenant_logo(TENANT, hostile)).is_err(),
                "{hostile:?} must be refused"
            );
        }
    }

    #[test]
    fn path_style_puts_the_bucket_in_the_path() {
        let s = provider(FULL);
        let (url, host) = s.url_for(Some("tenant-logos/x.png")).unwrap();
        assert_eq!(url.as_str(), "http://minio:9000/mokosh/tenant-logos/x.png");
        assert_eq!(host, "minio:9000");
        let (bucket_url, _) = s.url_for(None).unwrap();
        assert_eq!(bucket_url.as_str(), "http://minio:9000/mokosh");
    }

    #[test]
    fn virtual_hosted_puts_the_bucket_in_the_host() {
        let mut pairs = FULL.to_vec();
        pairs.push(("S3_PATH_STYLE", "false"));
        pairs[0] = ("S3_ENDPOINT", "https://s3.us-west-2.amazonaws.com");
        let s = provider(&pairs);
        let (url, host) = s.url_for(Some("a/b")).unwrap();
        assert_eq!(
            url.as_str(),
            "https://mokosh.s3.us-west-2.amazonaws.com/a/b"
        );
        assert_eq!(host, "mokosh.s3.us-west-2.amazonaws.com");
        let (bucket_url, _) = s.url_for(None).unwrap();
        assert_eq!(
            bucket_url.as_str(),
            "https://mokosh.s3.us-west-2.amazonaws.com/"
        );
    }

    #[test]
    fn an_endpoint_with_a_path_prefix_keeps_it() {
        let mut pairs = FULL.to_vec();
        pairs[0] = ("S3_ENDPOINT", "https://storage.example/s3/");
        let s = provider(&pairs);
        let (url, _) = s.url_for(Some("a/b")).unwrap();
        assert_eq!(url.as_str(), "https://storage.example/s3/mokosh/a/b");
    }

    #[test]
    fn every_required_variable_is_named_when_missing() {
        for missing in [
            "S3_ENDPOINT",
            "S3_BUCKET",
            "S3_ACCESS_KEY_ID",
            "S3_SECRET_ACCESS_KEY",
        ] {
            let pairs: Vec<(&str, &str)> = FULL
                .iter()
                .copied()
                .filter(|(k, _)| *k != missing)
                .collect();
            let err = S3Config::parse(vars(&pairs)).expect_err("must fail");
            assert!(err.to_string().contains(missing), "{missing}: {err}");
        }
        // Blank is unset (PMS-836): a forwarded-but-empty variable arrives as "".
        let mut pairs = FULL.to_vec();
        pairs[1] = ("S3_BUCKET", "   ");
        let err = S3Config::parse(vars(&pairs)).expect_err("blank is unset");
        assert!(err.to_string().contains("S3_BUCKET"));
    }

    #[test]
    fn defaults_are_path_style_and_us_east_1() {
        let config = S3Config::parse(vars(FULL)).unwrap();
        assert!(config.path_style);
        assert_eq!(config.region, "us-east-1");
    }

    #[test]
    fn a_path_style_value_that_is_not_a_boolean_is_refused() {
        let mut pairs = FULL.to_vec();
        pairs.push(("S3_PATH_STYLE", "maybe"));
        assert!(S3Config::parse(vars(&pairs)).is_err());
    }

    #[test]
    fn an_endpoint_that_is_not_a_plain_http_url_is_refused() {
        for bad in [
            "minio:9000",
            "ftp://minio",
            "http://",
            "http://minio/?x=1",
            "http://minio/#f",
        ] {
            let mut pairs = FULL.to_vec();
            pairs[0] = ("S3_ENDPOINT", bad);
            assert!(
                S3Config::parse(vars(&pairs)).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn a_bucket_name_outside_the_s3_rules_is_refused() {
        for bad in ["ab", "Mokosh", "my_bucket", "-x-", "a..b", &"a".repeat(64)] {
            let mut pairs = FULL.to_vec();
            pairs[1] = ("S3_BUCKET", bad);
            assert!(
                S3Config::parse(vars(&pairs)).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn the_secret_does_not_reach_a_debug_line() {
        let s = provider(FULL);
        let debug = format!("{s:?}");
        assert!(!debug.contains("secret\""), "{debug}");
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("minio:9000"));
    }

    #[test]
    fn the_location_names_the_bucket_and_the_key() {
        let s = provider(FULL);
        assert_eq!(
            s.location(&ObjectKey::ticket_attachment(TENANT, OBJECT))
                .unwrap(),
            format!("s3://mokosh/{TENANT}/{OBJECT}")
        );
    }
}
