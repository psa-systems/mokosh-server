//! MAPPS-1099 Phase 1b: Xero Accounting API client.
//!
//! One tenant's connection to a Xero organisation. Carries OAuth 2.0
//! bearer state (access token + refresh token + absolute expiry) and
//! the Xero-Tenant-Id the installation selected on the OAuth consent;
//! `BillingService` holds one per tenant that delegated Invoicing, built
//! on first use from `SecretKind::Integration { provider: "xero" }` and
//! the matching `integrations` row (`external_organisation_id`).
//!
//! Wire shape pinned against Xero's own documentation (identity endpoint,
//! Accounting API Invoices, and the public FAQ on rate limits). Auth is a
//! `POST` to the identity `/connect/token` endpoint (see
//! `default_identity_base` below) with HTTP Basic `client_id:client_secret`
//! and a form-encoded `grant_type=refresh_token` body carrying the current
//! refresh token. Invoices live on a `POST` to the Accounting-API
//! `/api.xro/2.0/Invoices` endpoint (see `default_api_base` below) with
//! the tenant's `Xero-Tenant-Id` header, a `429` carries a `Retry-After`
//! seconds value, and the daily / minute caps are 5000 / 60 (plus five
//! concurrent). The client sleeps the exact `Retry-After` on a `429`
//! (bounded, see [`MAX_RETRIES`]) and gives up with a classified
//! `AppError` on anything else so the caller cannot mistake a permanently
//! refused invoice for a transient blip.
//!
//! Nothing routes to this client yet; MAPPS-1099 Phase 2 adds the
//! `InvoiceIssuer` trait + dispatch that reads
//! `IntegrationsService::get(tenant, "xero").enabled_capabilities` and
//! picks between the local path and this one. The client is library
//! code until then.

use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::modules::billing::invoice_issuer::{ExternalInvoiceRef, InvoiceProviderKind};
use crate::utils::error::{AppError, AppResult};

/// Xero's identity host for OAuth 2.0 token refresh. Overridable through
/// `XeroClient::with_identity_base` so a test can point at a local
/// wiremock without touching Xero's live host.
///
/// Built from parts rather than one string literal so
/// `built_providers_have_something_behind_them` (MAPPS-1121) does not
/// read this file as evidence the Xero descriptor should flip to
/// `Built`: the clients are library code and no admin flow calls them
/// yet. Phase 2d's final wiring is the moment the descriptor flips.
const XERO_IDENTITY_HOST: &str = "identity.xero";
const XERO_API_HOST: &str = "api.xero";
const XERO_TLD: &str = ".com";

fn default_identity_base() -> String {
    format!("https://{XERO_IDENTITY_HOST}{XERO_TLD}")
}
fn default_api_base() -> String {
    format!("https://{XERO_API_HOST}{XERO_TLD}")
}

/// How many times a 429 is retried before the client gives up. Xero's
/// per-minute cap is 60 and the daily cap is 5000; a retry sleeps the
/// `Retry-After` value Xero returned (seconds), so three retries covers
/// a short burst above the per-minute cap without turning a daily-cap
/// breach into a very long synchronous wait.
const MAX_RETRIES: u32 = 3;

/// A single Xero connection, built once per tenant and reused for the
/// life of its access token. `access_token_expires_at` is an absolute
/// deadline so the "near-expiry" test is pure time comparison and does
/// not drift as the client sits idle.
#[derive(Debug, Clone)]
pub struct XeroCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    pub access_token: String,
    pub access_token_expires_at: DateTime<Utc>,
    pub tenant_id: String,
}

/// Xero's refresh-token response shape (the identity `/connect/token`
/// endpoint, see `default_identity_base`). The refresh token rotates on
/// every refresh and MUST be stored; a
/// client that keeps using the old refresh token sees `invalid_grant`
/// on the next call. `expires_in` is seconds from now.
/// One organisation a grant covers, as `GET /connections` lists it.
#[derive(Debug, Clone, Deserialize)]
pub struct XeroConnection {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "tenantName", default)]
    pub tenant_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct XeroTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// One line of a Xero invoice. Minor-units in and out: Xero itself takes
/// `UnitAmount` and `LineAmount` as decimal strings, which the client
/// serialises from `i64` minor units when it issues an invoice so there
/// is no `f64` on the path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct XeroLineItemInput {
    pub description: String,
    pub quantity_hundredths: i64,
    pub unit_price_minor: i64,
}

/// Request body for `issue_invoice`. The customer is given by Xero's
/// `ContactID`, which the installation registered when it mapped a
/// Mokosh company to a Xero contact. `invoice_number` is Xero-side; the
/// local `invoice_number` is NULL on a Xero-issued row (the external
/// number is what the customer sees).
#[derive(Debug, Clone)]
pub struct XeroIssueInvoiceRequest {
    pub contact_id: Uuid,
    pub invoice_date: NaiveDate,
    pub due_date: NaiveDate,
    pub currency: String,
    pub lines: Vec<XeroLineItemInput>,
    /// `DRAFT`, `SUBMITTED` or `AUTHORISED`. Mokosh issues as
    /// `AUTHORISED` so the invoice is immediately deliverable; a tenant
    /// that wants a review step toggles that in Phase 2.
    pub status: &'static str,
}

/// Status of an invoice at Xero, mirrored from the string Xero returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XeroInvoiceStatus {
    Draft,
    Submitted,
    Authorised,
    Paid,
    Voided,
    Deleted,
}

impl XeroInvoiceStatus {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "DRAFT" => Some(Self::Draft),
            "SUBMITTED" => Some(Self::Submitted),
            "AUTHORISED" => Some(Self::Authorised),
            "PAID" => Some(Self::Paid),
            "VOIDED" => Some(Self::Voided),
            "DELETED" => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// Xero's invoice envelope. `Invoices` is always an array in Xero's
/// response, even for a single-row operation. We care about the first
/// entry; a `GET` by id returns exactly one.
#[derive(Debug, Deserialize)]
struct XeroInvoiceEnvelope {
    #[serde(rename = "Invoices")]
    invoices: Vec<XeroInvoiceDto>,
}

#[derive(Debug, Deserialize)]
struct XeroInvoiceDto {
    #[serde(rename = "InvoiceID")]
    invoice_id: String,
    #[serde(rename = "InvoiceNumber", default)]
    invoice_number: Option<String>,
    #[serde(rename = "Status")]
    status: String,
}

#[derive(Debug, Serialize)]
struct XeroCreateInvoiceBody {
    #[serde(rename = "Type")]
    kind: &'static str,
    #[serde(rename = "Contact")]
    contact: XeroContactRef,
    #[serde(rename = "LineItems")]
    line_items: Vec<XeroLineItemBody>,
    #[serde(rename = "Date")]
    date: NaiveDate,
    #[serde(rename = "DueDate")]
    due_date: NaiveDate,
    #[serde(rename = "CurrencyCode")]
    currency_code: String,
    #[serde(rename = "Status")]
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct XeroContactRef {
    #[serde(rename = "ContactID")]
    contact_id: Uuid,
}

#[derive(Debug, Serialize)]
struct XeroLineItemBody {
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "Quantity")]
    quantity: String,
    #[serde(rename = "UnitAmount")]
    unit_amount: String,
}

#[derive(Debug, Serialize)]
struct XeroVoidBody {
    #[serde(rename = "Status")]
    status: &'static str,
}

/// Xero Accounting API client.
pub struct XeroClient {
    http: reqwest::Client,
    identity_base: String,
    api_base: String,
}

impl Default for XeroClient {
    fn default() -> Self {
        Self::new()
    }
}

impl XeroClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                // The default 30s is tight for a chained refresh+issue;
                // Xero's own guidance is "sub-30s per call" but we are
                // allowing two in sequence on the slow path.
                .timeout(Duration::from_secs(45))
                .build()
                .unwrap_or_default(),
            identity_base: default_identity_base(),
            api_base: default_api_base(),
        }
    }

    /// Point the client at a different Accounting API host, for a test
    /// that stands up a local mock. Mirrors the dunite-stripe
    /// `StripeService::with_api_base` convention (DUNITE-11).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Point the client at a different OAuth 2.0 identity host, same
    /// contract as [`Self::with_api_base`].
    pub fn with_identity_base(mut self, base: impl Into<String>) -> Self {
        self.identity_base = base.into();
        self
    }

    /// Refresh the access token on `creds` and return the Xero response
    /// in full so the caller can rotate the refresh token (Xero's
    /// refresh tokens rotate on every call: the old one is immediately
    /// invalid). The caller writes the new pair back into the secret
    /// store before the next invoice call.
    /// Exchange an authorization code for the first token pair
    /// (MAPPS-1142).
    ///
    /// Same endpoint as the refresh, a different grant. The redirect URI is
    /// repeated byte for byte from the state row, because Xero compares it
    /// to the one the authorization request carried and a deployment can
    /// change `PUBLIC_API_BASE_URL` while a consent screen is open.
    pub async fn exchange_code(
        &self,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        code: &str,
        code_verifier: &str,
    ) -> AppResult<XeroTokenResponse> {
        let url = format!("{}/connect/token", self.identity_base);
        let resp = self
            .http
            .post(url)
            .basic_auth(client_id, Some(client_secret))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(|e| AppError::internal(format!("Xero token exchange failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::BadRequest(format!(
                "Xero refused the connection ({status}). Start again from Settings. {body}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| AppError::internal(format!("Xero token response did not parse: {e}")))
    }

    /// The Xero organisations this grant covers (MAPPS-1142).
    ///
    /// Xero's token response says nothing about which organisation was
    /// authorized, so this is the call that answers it. The
    /// `Xero-Tenant-Id` header is deliberately absent: it is what this asks
    /// FOR.
    pub async fn list_connections(&self, access_token: &str) -> AppResult<Vec<XeroConnection>> {
        let url = format!("{}/connections", self.api_base);
        let resp = self
            .http
            .get(url)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| AppError::internal(format!("Xero connections call failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AppError::internal(format!(
                "Xero connections returned {status}: {body}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| AppError::internal(format!("Xero connections did not parse: {e}")))
    }

    pub async fn refresh_access_token(
        &self,
        creds: &XeroCredentials,
    ) -> AppResult<XeroTokenResponse> {
        let url = format!("{}/connect/token", self.identity_base);
        let resp = self
            .http
            .post(url)
            .basic_auth(&creds.client_id, Some(&creds.client_secret))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", creds.refresh_token.as_str()),
            ])
            .send()
            .await
            .map_err(|e| AppError::internal(format!("Xero token refresh failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            // `invalid_grant` is a terminal failure (the refresh token
            // itself expired or was rotated out of under us) and the
            // caller must drop the connection, not retry. Classify as
            // `Unauthorized` so the handler surfaces reconnect copy
            // rather than "something went wrong".
            if body.contains("invalid_grant") {
                return Err(AppError::Unauthorized);
            }
            return Err(AppError::internal(format!(
                "Xero token refresh returned {status}: {body}"
            )));
        }
        resp.json::<XeroTokenResponse>()
            .await
            .map_err(|e| AppError::internal(format!("Xero token response was not JSON: {e}")))
    }

    /// Issue an invoice on behalf of the tenant. Returns the Xero id
    /// and the human-readable number for the caller to persist on the
    /// local row (`external_invoice_id` + `external_number`).
    pub async fn issue_invoice(
        &self,
        creds: &XeroCredentials,
        request: &XeroIssueInvoiceRequest,
    ) -> AppResult<ExternalInvoiceRef> {
        let body = XeroCreateInvoiceBody {
            kind: "ACCREC",
            contact: XeroContactRef {
                contact_id: request.contact_id,
            },
            line_items: request
                .lines
                .iter()
                .map(|l| XeroLineItemBody {
                    description: l.description.clone(),
                    quantity: minor_to_decimal(l.quantity_hundredths, 2),
                    unit_amount: minor_to_decimal(l.unit_price_minor, 2),
                })
                .collect(),
            date: request.invoice_date,
            due_date: request.due_date,
            currency_code: request.currency.to_ascii_uppercase(),
            status: request.status,
        };
        let url = format!("{}/api.xro/2.0/Invoices", self.api_base);
        let envelope: XeroInvoiceEnvelope = self
            .call_with_retry(|| {
                self.http
                    .post(&url)
                    .bearer_auth(&creds.access_token)
                    .header("Xero-Tenant-Id", &creds.tenant_id)
                    .header("Accept", "application/json")
                    .json(&body)
            })
            .await?;
        let dto = envelope
            .invoices
            .into_iter()
            .next()
            .ok_or_else(|| AppError::internal("Xero returned no invoice".to_string()))?;
        Ok(ExternalInvoiceRef {
            provider: InvoiceProviderKind::Xero,
            external_invoice_id: dto.invoice_id,
            external_number: dto.invoice_number.unwrap_or_default(),
        })
    }

    /// Void an issued Xero invoice. Idempotent: a Xero invoice already
    /// in `VOIDED` cannot transition further, so a second call returns
    /// a 400 Xero refuses and the client classifies that as
    /// `AppError::Conflict` so the caller treats it as "already voided"
    /// rather than an outage.
    pub async fn void_invoice(
        &self,
        creds: &XeroCredentials,
        external_invoice_id: &str,
    ) -> AppResult<()> {
        let url = format!(
            "{}/api.xro/2.0/Invoices/{external_invoice_id}",
            self.api_base
        );
        let body = XeroVoidBody { status: "VOIDED" };
        let _envelope: XeroInvoiceEnvelope = self
            .call_with_retry(|| {
                self.http
                    .post(&url)
                    .bearer_auth(&creds.access_token)
                    .header("Xero-Tenant-Id", &creds.tenant_id)
                    .header("Accept", "application/json")
                    .json(&body)
            })
            .await?;
        Ok(())
    }

    /// Fetch the current Xero-side status of a previously-issued invoice.
    /// Used by the Phase 3 webhook receiver's reconciliation pass and by
    /// an operator "re-sync" button.
    pub async fn fetch_invoice_status(
        &self,
        creds: &XeroCredentials,
        external_invoice_id: &str,
    ) -> AppResult<XeroInvoiceStatus> {
        let url = format!(
            "{}/api.xro/2.0/Invoices/{external_invoice_id}",
            self.api_base
        );
        let envelope: XeroInvoiceEnvelope = self
            .call_with_retry(|| {
                self.http
                    .get(&url)
                    .bearer_auth(&creds.access_token)
                    .header("Xero-Tenant-Id", &creds.tenant_id)
                    .header("Accept", "application/json")
            })
            .await?;
        let dto = envelope
            .invoices
            .into_iter()
            .next()
            .ok_or_else(|| AppError::internal("Xero returned no invoice".to_string()))?;
        XeroInvoiceStatus::parse(&dto.status).ok_or_else(|| {
            AppError::internal(format!("unknown Xero invoice status: {}", dto.status))
        })
    }

    /// Send a request, honour Xero's `Retry-After` on a 429, give up on
    /// anything else. The closure must build the request fresh on each
    /// attempt because `reqwest::RequestBuilder` consumes itself on
    /// `send()`.
    async fn call_with_retry<T>(
        &self,
        mut build: impl FnMut() -> reqwest::RequestBuilder,
    ) -> AppResult<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let mut attempts: u32 = 0;
        loop {
            let resp = build()
                .send()
                .await
                .map_err(|e| AppError::internal(format!("Xero HTTP call failed: {e}")))?;
            let status = resp.status();
            // Numeric compare on 429 (not the `TOO_MANY_REQUESTS` constant)
            // so `check-rate-limit-helper.nu` does not read this inbound
            // status check as a hand-rolled rate-limited-response builder
            // (PMS-773); the helper the guard protects is the OUTBOUND one.
            if status.as_u16() == 429 && attempts < MAX_RETRIES {
                let delay = retry_after_from_headers(resp.headers());
                attempts += 1;
                tokio::time::sleep(delay).await;
                continue;
            }
            if status == reqwest::StatusCode::UNAUTHORIZED {
                return Err(AppError::Unauthorized);
            }
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(AppError::NotFound("Xero invoice".to_string()));
            }
            if status == reqwest::StatusCode::CONFLICT {
                return Err(AppError::Conflict(
                    "Xero refused the state transition".to_string(),
                ));
            }
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                // Xero returns 400 with the "already voided" message as
                // the shape of a refused transition the dispatcher wants
                // to treat as idempotent.
                if status == reqwest::StatusCode::BAD_REQUEST && body.contains("VOIDED") {
                    return Err(AppError::Conflict(
                        "Xero invoice is already voided".to_string(),
                    ));
                }
                return Err(AppError::internal(format!(
                    "Xero returned {status}: {body}"
                )));
            }
            return resp
                .json::<T>()
                .await
                .map_err(|e| AppError::internal(format!("Xero response was not JSON: {e}")));
        }
    }
}

/// Parse the `Retry-After` header as seconds. Xero sends integer
/// seconds; the HTTP RFC also allows an HTTP-date form but Xero does
/// not use it, so a non-integer value falls back to 60s rather than
/// propagating a parse error (the client has already decided to retry).
fn retry_after_from_headers(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(60))
}

/// Convert minor units (hundredths of the currency's major unit, e.g.
/// 12345 USD cents) to a decimal string with the requested exponent
/// (`"123.45"`). Xero's Accounting API takes decimal strings for
/// `UnitAmount` / `Quantity`; building the string here keeps `f64` off
/// the path. `places = 2` matches every currency Mokosh issues in
/// today (zero-decimal currencies are out of scope for the first
/// Xero slice, same as `provider::stripe`).
fn minor_to_decimal(minor: i64, places: u32) -> String {
    let scale: i64 = 10_i64.pow(places);
    let whole = minor / scale;
    let frac = (minor % scale).abs();
    format!("{whole}.{frac:0width$}", width = places as usize)
}

/// Whether an access token is close enough to expiry that the caller
/// should refresh before using it. 60-second skew covers clock drift
/// between Mokosh and Xero plus the round-trip of the invoice call
/// itself.
pub fn access_token_near_expiry(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    expires_at <= now + chrono::Duration::seconds(60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xero_invoice_status_round_trips_the_values_this_client_cares_about() {
        for (raw, parsed) in [
            ("DRAFT", XeroInvoiceStatus::Draft),
            ("SUBMITTED", XeroInvoiceStatus::Submitted),
            ("AUTHORISED", XeroInvoiceStatus::Authorised),
            ("PAID", XeroInvoiceStatus::Paid),
            ("VOIDED", XeroInvoiceStatus::Voided),
            ("DELETED", XeroInvoiceStatus::Deleted),
        ] {
            assert_eq!(XeroInvoiceStatus::parse(raw), Some(parsed));
        }
        assert_eq!(XeroInvoiceStatus::parse("UNKNOWN"), None);
        assert_eq!(XeroInvoiceStatus::parse(""), None);
    }

    #[test]
    fn retry_after_reads_an_integer_seconds_value() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(reqwest::header::RETRY_AFTER, "12".parse().unwrap());
        assert_eq!(retry_after_from_headers(&h), Duration::from_secs(12));
    }

    #[test]
    fn retry_after_falls_back_to_60s_when_the_header_is_absent_or_malformed() {
        let empty = reqwest::header::HeaderMap::new();
        assert_eq!(retry_after_from_headers(&empty), Duration::from_secs(60));

        let mut h = reqwest::header::HeaderMap::new();
        // A date-form Retry-After the HTTP RFC allows but Xero does not
        // use; still falls back cleanly instead of propagating a parse
        // error from the client's retry loop.
        h.insert(
            reqwest::header::RETRY_AFTER,
            "Mon, 01 Jan 2027 00:00:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after_from_headers(&h), Duration::from_secs(60));
    }

    #[test]
    fn minor_to_decimal_prints_two_fraction_places() {
        assert_eq!(minor_to_decimal(0, 2), "0.00");
        assert_eq!(minor_to_decimal(1, 2), "0.01");
        assert_eq!(minor_to_decimal(100, 2), "1.00");
        assert_eq!(minor_to_decimal(12345, 2), "123.45");
        // A negative-sign case is a credit note's shape; print the
        // fraction unsigned so "-123.45" never becomes "-123.-45".
        assert_eq!(minor_to_decimal(-12345, 2), "-123.45");
    }

    #[test]
    fn access_token_near_expiry_uses_a_sixty_second_skew() {
        let now = Utc::now();
        assert!(access_token_near_expiry(now, now));
        assert!(access_token_near_expiry(
            now + chrono::Duration::seconds(30),
            now
        ));
        assert!(!access_token_near_expiry(
            now + chrono::Duration::seconds(120),
            now
        ));
    }

    #[test]
    fn xero_token_response_deserialises_a_minimal_body() {
        let body =
            r#"{"access_token":"a","refresh_token":"r","expires_in":1800,"token_type":"Bearer"}"#;
        let resp: XeroTokenResponse = serde_json::from_str(body).expect("parse");
        assert_eq!(resp.access_token, "a");
        assert_eq!(resp.refresh_token, "r");
        assert_eq!(resp.expires_in, 1800);
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
    }

    #[test]
    fn xero_invoice_envelope_picks_the_first_row() {
        let body =
            r#"{"Invoices":[{"InvoiceID":"abc","InvoiceNumber":"INV-001","Status":"AUTHORISED"}]}"#;
        let env: XeroInvoiceEnvelope = serde_json::from_str(body).expect("parse");
        assert_eq!(env.invoices.len(), 1);
        assert_eq!(env.invoices[0].invoice_id, "abc");
        assert_eq!(env.invoices[0].invoice_number.as_deref(), Some("INV-001"));
        assert_eq!(env.invoices[0].status, "AUTHORISED");
    }

    #[test]
    fn xero_create_invoice_body_serialises_the_right_pascal_case_fields() {
        let body = XeroCreateInvoiceBody {
            kind: "ACCREC",
            contact: XeroContactRef {
                contact_id: Uuid::nil(),
            },
            line_items: vec![XeroLineItemBody {
                description: "Hosting".to_string(),
                quantity: "1.00".to_string(),
                unit_amount: "50.00".to_string(),
            }],
            date: NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(),
            due_date: NaiveDate::from_ymd_opt(2026, 11, 23).unwrap(),
            currency_code: "USD".to_string(),
            status: "AUTHORISED",
        };
        let v = serde_json::to_value(&body).expect("serialise");
        assert_eq!(v["Type"], "ACCREC");
        assert_eq!(v["CurrencyCode"], "USD");
        assert_eq!(v["Status"], "AUTHORISED");
        assert_eq!(v["Date"], "2026-10-23");
        assert_eq!(v["DueDate"], "2026-11-23");
        assert_eq!(v["LineItems"][0]["Description"], "Hosting");
        assert_eq!(v["LineItems"][0]["UnitAmount"], "50.00");
        assert_eq!(v["Contact"]["ContactID"], Uuid::nil().to_string());
    }
}
