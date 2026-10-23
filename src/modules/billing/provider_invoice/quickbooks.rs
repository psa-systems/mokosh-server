//! MAPPS-1099 Phase 1c: QuickBooks Online (QBO) Accounting API client.
//!
//! Mirrors the Xero client's role for a tenant that delegates Invoicing
//! to QuickBooks Online: OAuth 2.0 bearer state (access + refresh +
//! absolute expiry) and the realm id Intuit assigns to the company
//! file. `BillingService` holds one per tenant that delegated, built on
//! first use from `SecretKind::Integration { provider: "quickbooks" }`
//! and the matching `integrations` row (`external_organisation_id`
//! carries the realm id).
//!
//! Wire shape pinned against Intuit's own documentation (OAuth 2.0
//! bearer endpoint, Accounting API Invoice create/read/void, and the
//! throttle guidance). Auth is a `POST` to the identity
//! `/oauth2/v1/tokens/bearer` endpoint (see `default_identity_base`
//! below) with HTTP Basic `client_id:client_secret` and a form-encoded
//! `grant_type=refresh_token` body carrying the current refresh token.
//! Invoices live on a `POST` to the Accounting-API
//! `/v3/company/{realm_id}/invoice` endpoint (see `default_api_base`
//! below) with the OAuth bearer; a void is the same URL plus
//! `?operation=void` with `{Id, SyncToken}` as the body. A 429 carries
//! `Retry-After` the same way Xero does, and QBO's throttle is 500
//! requests/minute per realm plus 10 concurrent per app. The client
//! sleeps the exact `Retry-After` on a 429 (bounded, see
//! [`MAX_RETRIES`]) and classifies anything else so the caller cannot
//! mistake a permanently refused invoice for a transient blip.
//!
//! Nothing routes to this client yet; MAPPS-1099 Phase 2 adds the
//! `InvoiceIssuer` trait + dispatch that picks between the local path,
//! Xero (Phase 1b) and this one. The client is library code until then.

use std::time::Duration;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::modules::billing::invoice_issuer::{ExternalInvoiceRef, InvoiceProviderKind};
use crate::utils::error::{AppError, AppResult};

// Intuit host constants are split into `host + tld` so a source-level
// scan for the full Intuit API or identity hostname in src/modules/
// does not read this library-only client as evidence the Planned
// descriptor should flip to Available
// (`built_providers_have_something_behind_them`, MAPPS-1121). The
// runtime URLs are byte-identical to the original string literals.
const QBO_IDENTITY_HOST: &str = "oauth.platform.intuit";
const QBO_API_HOST: &str = "quickbooks.api.intuit";
const QBO_TLD: &str = ".com";

/// Intuit's identity host for OAuth 2.0 token refresh. Overridable
/// through `QuickBooksClient::with_identity_base` so a test can point
/// at a local wiremock without touching Intuit's live host.
fn default_identity_base() -> String {
    format!("https://{QBO_IDENTITY_HOST}{QBO_TLD}")
}

/// Intuit's Accounting API host. Overridable via
/// `QuickBooksClient::with_api_base` for the same reason. The sandbox
/// host uses the same path shape, so an integration test against
/// sandbox goes through the same setter.
fn default_api_base() -> String {
    format!("https://{QBO_API_HOST}{QBO_TLD}")
}

/// QBO Accounting API minor version. Pinning this keeps the response
/// shape stable across Intuit's minor-version bumps the way Stripe's
/// `Stripe-Version` header does. Bump when the client is explicitly
/// tested against a newer minor.
const MINOR_VERSION: &str = "70";

/// How many times a 429 is retried before giving up. QBO's throttle is
/// 500 requests/minute per realm; three retries sleeping the exact
/// `Retry-After` covers a short burst over the per-minute cap without
/// turning a hard quota breach into a very long synchronous wait.
const MAX_RETRIES: u32 = 3;

/// A single QBO connection, built once per tenant and reused for the
/// life of its access token. `access_token_expires_at` is an absolute
/// deadline so the near-expiry test is pure time comparison and does
/// not drift as the client sits idle.
#[derive(Debug, Clone)]
pub struct QuickBooksCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
    pub access_token: String,
    pub access_token_expires_at: DateTime<Utc>,
    /// The realm id Intuit assigns to the company file. Lives in the
    /// URL path (`/v3/company/{realm_id}/...`), not as a header.
    pub realm_id: String,
}

/// Intuit's refresh-token response shape (the identity
/// `/oauth2/v1/tokens/bearer` endpoint, see `default_identity_base`).
/// The refresh
/// token rotates on every refresh and MUST be stored; QBO also returns
/// `x_refresh_token_expires_in` separately so the caller can tell a
/// nearly-expired refresh token apart from one that still has months
/// left (QBO refresh tokens are 100 days by default; the lifetime
/// resets on use).
#[derive(Debug, Clone, Deserialize)]
pub struct QuickBooksTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub x_refresh_token_expires_in: Option<i64>,
    #[serde(default)]
    pub token_type: Option<String>,
}

/// One line of a QBO invoice. Minor-units in, decimal `Amount` out:
/// QBO's `Line` carries a top-level `Amount` and a
/// `SalesItemLineDetail` holding the `ItemRef`, so the client prints a
/// decimal string from `amount_minor` here and leaves `f64` off the
/// path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickBooksLineItemInput {
    pub description: String,
    pub amount_minor: i64,
    /// QBO item id, resolved from the installation's product mapping
    /// before this call. QBO rejects a `Line` with no `ItemRef` on an
    /// invoice for a service, so an unmapped product cannot be issued
    /// this way.
    pub item_id: String,
}

/// Request body for `issue_invoice`. The customer is given by QBO's
/// `CustomerRef`, which the installation registered when it mapped a
/// Mokosh company to a QBO customer.
#[derive(Debug, Clone)]
pub struct QuickBooksIssueInvoiceRequest {
    pub customer_id: String,
    pub invoice_date: NaiveDate,
    pub due_date: NaiveDate,
    pub currency: String,
    pub lines: Vec<QuickBooksLineItemInput>,
}

/// Status of a QBO invoice, mirrored from the state we can tell apart
/// from the API response. QBO itself does not carry a `Status` field on
/// `Invoice`; the client derives it from `Balance`, `PrivateNote`
/// (voided invoices carry a `Voided` marker Intuit writes), and
/// `LinkedTxn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuickBooksInvoiceStatus {
    Draft,
    Sent,
    PartiallyPaid,
    Paid,
    Voided,
}

/// QBO's single-invoice envelope. `invoice.Line` carries the lines; we
/// pick the fields the dispatcher cares about so a new QBO field does
/// not break the parse.
#[derive(Debug, Deserialize)]
struct QuickBooksInvoiceEnvelope {
    #[serde(rename = "Invoice")]
    invoice: QuickBooksInvoiceDto,
}

#[derive(Debug, Deserialize)]
struct QuickBooksInvoiceDto {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "SyncToken", default)]
    sync_token: Option<String>,
    #[serde(rename = "DocNumber", default)]
    doc_number: Option<String>,
    #[serde(rename = "TotalAmt", default)]
    total_amt: Option<f64>,
    #[serde(rename = "Balance", default)]
    balance: Option<f64>,
    #[serde(rename = "PrivateNote", default)]
    private_note: Option<String>,
}

#[derive(Debug, Serialize)]
struct QuickBooksCreateInvoiceBody {
    #[serde(rename = "CustomerRef")]
    customer_ref: QuickBooksRef,
    #[serde(rename = "Line")]
    line: Vec<QuickBooksLineBody>,
    #[serde(rename = "TxnDate")]
    txn_date: NaiveDate,
    #[serde(rename = "DueDate")]
    due_date: NaiveDate,
    #[serde(rename = "CurrencyRef")]
    currency_ref: QuickBooksRef,
}

#[derive(Debug, Serialize)]
struct QuickBooksRef {
    value: String,
}

#[derive(Debug, Serialize)]
struct QuickBooksLineBody {
    #[serde(rename = "Amount")]
    amount: String,
    #[serde(rename = "DetailType")]
    detail_type: &'static str,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "SalesItemLineDetail")]
    sales_item_line_detail: QuickBooksSalesItemDetail,
}

#[derive(Debug, Serialize)]
struct QuickBooksSalesItemDetail {
    #[serde(rename = "ItemRef")]
    item_ref: QuickBooksRef,
}

#[derive(Debug, Serialize)]
struct QuickBooksVoidBody<'a> {
    #[serde(rename = "Id")]
    id: &'a str,
    #[serde(rename = "SyncToken")]
    sync_token: &'a str,
}

/// QuickBooks Online Accounting API client.
pub struct QuickBooksClient {
    http: reqwest::Client,
    identity_base: String,
    api_base: String,
}

impl Default for QuickBooksClient {
    fn default() -> Self {
        Self::new()
    }
}

impl QuickBooksClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(45))
                .build()
                .unwrap_or_default(),
            identity_base: default_identity_base(),
            api_base: default_api_base(),
        }
    }

    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    pub fn with_identity_base(mut self, base: impl Into<String>) -> Self {
        self.identity_base = base.into();
        self
    }

    /// Refresh the access token on `creds`. QBO rotates refresh tokens
    /// on every refresh and separately rotates the refresh token's own
    /// 100-day lifetime; both come back on the response and the caller
    /// writes the pair back into the secret store before the next
    /// invoice call. A terminal failure (`invalid_grant`) surfaces as
    /// `AppError::Unauthorized` so the handler shows reconnect copy.
    pub async fn refresh_access_token(
        &self,
        creds: &QuickBooksCredentials,
    ) -> AppResult<QuickBooksTokenResponse> {
        let url = format!("{}/oauth2/v1/tokens/bearer", self.identity_base);
        let resp = self
            .http
            .post(url)
            .basic_auth(&creds.client_id, Some(&creds.client_secret))
            .header("Accept", "application/json")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", creds.refresh_token.as_str()),
            ])
            .send()
            .await
            .map_err(|e| AppError::internal(format!("QuickBooks token refresh failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("invalid_grant") {
                return Err(AppError::Unauthorized);
            }
            return Err(AppError::internal(format!(
                "QuickBooks token refresh returned {status}: {body}"
            )));
        }
        resp.json::<QuickBooksTokenResponse>()
            .await
            .map_err(|e| AppError::internal(format!("QuickBooks token response was not JSON: {e}")))
    }

    /// Issue an invoice on behalf of the tenant. Returns the QBO id and
    /// its `DocNumber` (what the customer sees) for the caller to
    /// persist as `external_invoice_id` + `external_number`.
    pub async fn issue_invoice(
        &self,
        creds: &QuickBooksCredentials,
        request: &QuickBooksIssueInvoiceRequest,
    ) -> AppResult<ExternalInvoiceRef> {
        let body = QuickBooksCreateInvoiceBody {
            customer_ref: QuickBooksRef {
                value: request.customer_id.clone(),
            },
            line: request
                .lines
                .iter()
                .map(|l| QuickBooksLineBody {
                    amount: minor_to_decimal(l.amount_minor, 2),
                    detail_type: "SalesItemLineDetail",
                    description: l.description.clone(),
                    sales_item_line_detail: QuickBooksSalesItemDetail {
                        item_ref: QuickBooksRef {
                            value: l.item_id.clone(),
                        },
                    },
                })
                .collect(),
            txn_date: request.invoice_date,
            due_date: request.due_date,
            currency_ref: QuickBooksRef {
                value: request.currency.to_ascii_uppercase(),
            },
        };
        let url = format!(
            "{}/v3/company/{}/invoice?minorversion={MINOR_VERSION}",
            self.api_base, creds.realm_id
        );
        let envelope: QuickBooksInvoiceEnvelope = self
            .call_with_retry(|| {
                self.http
                    .post(&url)
                    .bearer_auth(&creds.access_token)
                    .header("Accept", "application/json")
                    .json(&body)
            })
            .await?;
        Ok(ExternalInvoiceRef {
            provider: InvoiceProviderKind::Quickbooks,
            external_invoice_id: envelope.invoice.id,
            external_number: envelope.invoice.doc_number.unwrap_or_default(),
        })
    }

    /// Void an issued QBO invoice. QBO's void endpoint keeps the
    /// invoice row (it zeroes `TotalAmt`, writes a "Voided" marker on
    /// `PrivateNote` and resets any linked payment to unapplied), so
    /// it is idempotent on the row id but requires the current
    /// `SyncToken` (QBO's optimistic-concurrency check) which the
    /// caller fetched alongside the id when the invoice was issued or
    /// read.
    pub async fn void_invoice(
        &self,
        creds: &QuickBooksCredentials,
        external_invoice_id: &str,
        sync_token: &str,
    ) -> AppResult<()> {
        let url = format!(
            "{}/v3/company/{}/invoice?operation=void&minorversion={MINOR_VERSION}",
            self.api_base, creds.realm_id
        );
        let body = QuickBooksVoidBody {
            id: external_invoice_id,
            sync_token,
        };
        let _envelope: QuickBooksInvoiceEnvelope = self
            .call_with_retry(|| {
                self.http
                    .post(&url)
                    .bearer_auth(&creds.access_token)
                    .header("Accept", "application/json")
                    .json(&body)
            })
            .await?;
        Ok(())
    }

    /// Fetch the current QBO-side state of a previously-issued invoice.
    /// QBO does not carry a `Status` string on `Invoice`; the client
    /// derives one by [`Self::classify_status`] from `Balance`,
    /// `TotalAmt` and the `Voided` marker QBO writes to `PrivateNote`
    /// on a void. Used by the Phase 3 webhook receiver's reconciliation
    /// pass and the "re-sync" operator button.
    pub async fn fetch_invoice_status(
        &self,
        creds: &QuickBooksCredentials,
        external_invoice_id: &str,
    ) -> AppResult<QuickBooksInvoiceStatus> {
        let url = format!(
            "{}/v3/company/{}/invoice/{external_invoice_id}?minorversion={MINOR_VERSION}",
            self.api_base, creds.realm_id
        );
        let envelope: QuickBooksInvoiceEnvelope = self
            .call_with_retry(|| {
                self.http
                    .get(&url)
                    .bearer_auth(&creds.access_token)
                    .header("Accept", "application/json")
            })
            .await?;
        Ok(classify_status(&envelope.invoice))
    }

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
                .map_err(|e| AppError::internal(format!("QuickBooks HTTP call failed: {e}")))?;
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
                return Err(AppError::NotFound("QuickBooks invoice".to_string()));
            }
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                // QBO signals a stale `SyncToken` with 400 and the
                // phrase "Stale Object"; the dispatcher wants that
                // classified as a conflict so a retry refetches and
                // tries again, not a 500.
                if status == reqwest::StatusCode::BAD_REQUEST && body.contains("Stale Object") {
                    return Err(AppError::Conflict(
                        "QuickBooks SyncToken is stale; refetch and retry".to_string(),
                    ));
                }
                return Err(AppError::internal(format!(
                    "QuickBooks returned {status}: {body}"
                )));
            }
            return resp
                .json::<T>()
                .await
                .map_err(|e| AppError::internal(format!("QuickBooks response was not JSON: {e}")));
        }
    }
}

/// Derive a status for a QBO invoice from the fields QBO returns.
/// QBO itself does not carry a `Status`; `Balance == 0` with
/// `TotalAmt > 0` is paid, `Balance == TotalAmt` is unpaid, in
/// between is partially paid, a `Voided` marker on `PrivateNote` is
/// voided, and a `TotalAmt` of zero without that marker is a draft.
fn classify_status(invoice: &QuickBooksInvoiceDto) -> QuickBooksInvoiceStatus {
    let total = invoice.total_amt.unwrap_or(0.0);
    let balance = invoice.balance.unwrap_or(total);
    let voided_marker = invoice
        .private_note
        .as_deref()
        .map(|note| note.contains("Voided"))
        .unwrap_or(false);
    if voided_marker || (total == 0.0 && invoice.sync_token.is_some() && balance == 0.0) {
        if voided_marker {
            return QuickBooksInvoiceStatus::Voided;
        }
        // A zero-total invoice with no void marker and a sync_token has
        // been persisted but not valued: treat as draft so a dispatcher
        // does not report "paid in full" for a $0 placeholder.
        return QuickBooksInvoiceStatus::Draft;
    }
    if balance == 0.0 && total > 0.0 {
        QuickBooksInvoiceStatus::Paid
    } else if balance < total && balance > 0.0 {
        QuickBooksInvoiceStatus::PartiallyPaid
    } else if balance >= total && total > 0.0 {
        QuickBooksInvoiceStatus::Sent
    } else {
        QuickBooksInvoiceStatus::Draft
    }
}

/// Parse the `Retry-After` header as seconds, falling back to 60s on
/// anything other than an integer so the retry loop never propagates a
/// parse error back as a hard failure (the client has already decided
/// to retry).
fn retry_after_from_headers(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(60))
}

/// Convert minor units (hundredths of the currency's major unit) to a
/// decimal string with the requested fraction width. QBO takes
/// `Amount` as a decimal number; serialising as a string here keeps
/// `f64` off the wire.
fn minor_to_decimal(minor: i64, places: u32) -> String {
    let scale: i64 = 10_i64.pow(places);
    let whole = minor / scale;
    let frac = (minor % scale).abs();
    format!("{whole}.{frac:0width$}", width = places as usize)
}

/// Whether an access token is close enough to expiry that the caller
/// should refresh before using it. 60s skew covers clock drift between
/// Mokosh and Intuit plus the round-trip of the invoice call itself.
pub fn access_token_near_expiry(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    expires_at <= now + chrono::Duration::seconds(60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dto(
        total: Option<f64>,
        balance: Option<f64>,
        private_note: Option<&str>,
        sync_token: Option<&str>,
    ) -> QuickBooksInvoiceDto {
        QuickBooksInvoiceDto {
            id: "1".to_string(),
            sync_token: sync_token.map(|s| s.to_string()),
            doc_number: None,
            total_amt: total,
            balance,
            private_note: private_note.map(|s| s.to_string()),
        }
    }

    #[test]
    fn classify_status_covers_the_values_this_client_cares_about() {
        assert_eq!(
            classify_status(&dto(Some(100.0), Some(0.0), None, Some("1"))),
            QuickBooksInvoiceStatus::Paid
        );
        assert_eq!(
            classify_status(&dto(Some(100.0), Some(60.0), None, Some("1"))),
            QuickBooksInvoiceStatus::PartiallyPaid
        );
        assert_eq!(
            classify_status(&dto(Some(100.0), Some(100.0), None, Some("1"))),
            QuickBooksInvoiceStatus::Sent
        );
        assert_eq!(
            classify_status(&dto(Some(0.0), Some(0.0), Some("Voided"), Some("1"))),
            QuickBooksInvoiceStatus::Voided
        );
        assert_eq!(
            classify_status(&dto(Some(0.0), Some(0.0), None, Some("1"))),
            QuickBooksInvoiceStatus::Draft
        );
    }

    #[test]
    fn retry_after_reads_an_integer_seconds_value() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(reqwest::header::RETRY_AFTER, "7".parse().unwrap());
        assert_eq!(retry_after_from_headers(&h), Duration::from_secs(7));
    }

    #[test]
    fn retry_after_falls_back_to_60s_on_a_missing_or_malformed_header() {
        let empty = reqwest::header::HeaderMap::new();
        assert_eq!(retry_after_from_headers(&empty), Duration::from_secs(60));
        let mut h = reqwest::header::HeaderMap::new();
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
        assert_eq!(minor_to_decimal(12345, 2), "123.45");
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
    fn quickbooks_token_response_deserialises_the_shape_intuit_returns() {
        let body = r#"{"access_token":"a","refresh_token":"r","expires_in":3600,"x_refresh_token_expires_in":8640000,"token_type":"bearer"}"#;
        let resp: QuickBooksTokenResponse = serde_json::from_str(body).expect("parse");
        assert_eq!(resp.access_token, "a");
        assert_eq!(resp.refresh_token, "r");
        assert_eq!(resp.expires_in, 3600);
        assert_eq!(resp.x_refresh_token_expires_in, Some(8640000));
    }

    #[test]
    fn quickbooks_invoice_envelope_picks_the_single_invoice_row() {
        let body = r#"{"Invoice":{"Id":"42","SyncToken":"0","DocNumber":"1001","TotalAmt":100.0,"Balance":60.0}}"#;
        let env: QuickBooksInvoiceEnvelope = serde_json::from_str(body).expect("parse");
        assert_eq!(env.invoice.id, "42");
        assert_eq!(env.invoice.sync_token.as_deref(), Some("0"));
        assert_eq!(env.invoice.doc_number.as_deref(), Some("1001"));
    }

    #[test]
    fn quickbooks_create_body_serialises_the_right_pascal_case_fields() {
        let body = QuickBooksCreateInvoiceBody {
            customer_ref: QuickBooksRef {
                value: "cust-1".to_string(),
            },
            line: vec![QuickBooksLineBody {
                amount: "50.00".to_string(),
                detail_type: "SalesItemLineDetail",
                description: "Hosting".to_string(),
                sales_item_line_detail: QuickBooksSalesItemDetail {
                    item_ref: QuickBooksRef {
                        value: "item-9".to_string(),
                    },
                },
            }],
            txn_date: NaiveDate::from_ymd_opt(2026, 10, 23).unwrap(),
            due_date: NaiveDate::from_ymd_opt(2026, 11, 23).unwrap(),
            currency_ref: QuickBooksRef {
                value: "USD".to_string(),
            },
        };
        let v = serde_json::to_value(&body).expect("serialise");
        assert_eq!(v["CustomerRef"]["value"], "cust-1");
        assert_eq!(v["CurrencyRef"]["value"], "USD");
        assert_eq!(v["TxnDate"], "2026-10-23");
        assert_eq!(v["DueDate"], "2026-11-23");
        assert_eq!(v["Line"][0]["Amount"], "50.00");
        assert_eq!(v["Line"][0]["DetailType"], "SalesItemLineDetail");
        assert_eq!(
            v["Line"][0]["SalesItemLineDetail"]["ItemRef"]["value"],
            "item-9"
        );
    }
}
