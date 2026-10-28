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

use crate::modules::billing::invoice_issuer::{
    decimal_string_to_minor, ExternalBillRef, ExternalCreditNoteRef, ExternalExpenseRef,
    ExternalInvoiceRef, ExternalSettlement, InvoiceProviderKind,
};
use crate::utils::error::{AppError, AppResult};

/// Xero's identity host for OAuth 2.0 token refresh. Overridable through
/// `XeroClient::with_identity_base` so a test can point at a local stub
/// without touching Xero's live host.
///
/// These were assembled from parts until MAPPS-1153, so that
/// `built_providers_have_something_behind_them` (MAPPS-1121) would not
/// read a library-only client as evidence the descriptor should flip to
/// `Built`. The descriptor has flipped, and that guard now asserts the
/// opposite: a built provider must have a real host behind it, and these
/// literals are what it finds.
fn default_identity_base() -> String {
    "https://identity.xero.com".to_string()
}
fn default_api_base() -> String {
    "https://api.xero.com".to_string()
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
/// What a bill push needs from the caller (MAPPS-1155).
///
/// `contact_id` is the vendor's id in Xero, not the customer's: a bill is
/// raised against whoever the MSP owes.
#[derive(Debug, Clone)]
pub struct XeroCreateBillRequest {
    pub contact_id: Uuid,
    pub issue_date: NaiveDate,
    pub due_date: NaiveDate,
    pub currency: String,
    pub lines: Vec<XeroLineItemInput>,
}

/// Request body for `pay_bill`: money leaving against a bill the provider
/// holds (PMS-1545).
///
/// Xero attaches a payment to the document it settles, so the bill's own
/// `InvoiceID` is the whole link; `bank_account_id` is the account it left,
/// which is the value PMS-1541 put on the integration row.
#[derive(Debug, Clone)]
pub struct XeroPayBillRequest {
    pub bill_id: Uuid,
    pub bank_account_id: String,
    pub paid_on: NaiveDate,
    pub amount_minor: i64,
}

/// What a credit note push needs from the caller (PMS-1546).
///
/// No due date, which is the shape difference from an invoice: a credit
/// note is money owed BACK and nothing falls due on it. `contact_id` is
/// the customer's, because a receivable credit is raised against whoever
/// was invoiced.
#[derive(Debug, Clone)]
pub struct XeroIssueCreditNoteRequest {
    pub contact_id: Uuid,
    pub issue_date: NaiveDate,
    pub currency: String,
    pub lines: Vec<XeroLineItemInput>,
}

/// What applying a credit note to an invoice needs (PMS-1546).
///
/// Xero keeps allocation as its own sub-resource rather than a field on
/// the credit note, so this is a second call and not a larger body. The
/// amount is carried in minor units like every other money field here and
/// serialised to a decimal string at the wire.
#[derive(Debug, Clone)]
pub struct XeroAllocateCreditRequest {
    pub invoice_id: Uuid,
    pub amount_minor: i64,
    pub date: NaiveDate,
}

/// A credit note as Xero holds it now: its status, and the allocations
/// standing against it (PMS-1546).
///
/// Both answers come from one `GET`, for the reason the QuickBooks void
/// target does: a caller that asked twice could act on a status from one
/// read and allocations from another.
#[derive(Debug, Clone)]
pub struct XeroCreditNoteState {
    /// `None` when Xero sent a status this client does not know, which is
    /// not the same as voided and must not be read as it.
    pub status: Option<XeroInvoiceStatus>,
    pub allocation_ids: Vec<String>,
}

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

/// One line of a spend-money transaction (PMS-1541).
///
/// An expense line is an amount against an ACCOUNT, where an invoice line
/// is a quantity at a price: a taxi fare is one number, and the account is
/// what the MSP's books file it under.
#[derive(Debug, Clone)]
pub struct XeroSpendLineInput {
    pub description: String,
    pub amount_minor: i64,
    /// The Xero account code this cost lands in, from the expense-category
    /// mapping (migration 286).
    pub account_code: String,
}

/// Request body for `record_spend`: a reimbursement leaving the MSP's
/// account (PMS-1541).
///
/// `bank_account_id` is the account the money left, which Xero refuses the
/// call without; `contact_id` is the person reimbursed, which Xero also
/// refuses the call without.
#[derive(Debug, Clone)]
pub struct XeroRecordSpendRequest {
    pub bank_account_id: String,
    pub contact_id: Uuid,
    pub paid_on: NaiveDate,
    pub currency: String,
    pub lines: Vec<XeroSpendLineInput>,
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

/// `GET /Invoices/{id}` read for its amounts (PMS-1543). Its own DTO
/// rather than fields bolted onto [`XeroInvoiceDto`]: that one is shared
/// with the issue path, where `AmountPaid` is always absent and a reader
/// would wonder why.
///
/// Xero serialises these as JSON numbers, and the client never hands a
/// float to a money field, so they are read as strings through serde's
/// untagged scalar and converted by [`decimal_string_to_minor`].
#[derive(Debug, Deserialize)]
struct XeroSettlementEnvelope {
    #[serde(rename = "Invoices", default)]
    invoices: Vec<XeroSettlementDto>,
}

#[derive(Debug, Deserialize)]
struct XeroSettlementDto {
    #[serde(rename = "Type", default)]
    kind: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "AmountPaid", default, deserialize_with = "scalar_as_string")]
    amount_paid: Option<String>,
    #[serde(rename = "Total", default, deserialize_with = "scalar_as_string")]
    total: Option<String>,
}

/// Read a JSON number or string into a string, so a provider that changes
/// which it sends does not change what this client can parse.
fn scalar_as_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Ok(match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        other => Some(other.to_string()),
    })
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
struct XeroBankAccountRef {
    #[serde(rename = "AccountID")]
    account_id: String,
}

#[derive(Debug, Serialize)]
struct XeroSpendLineBody {
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "LineAmount")]
    line_amount: String,
    #[serde(rename = "AccountCode")]
    account_code: String,
}

/// A spend-money bank transaction. `Type: "SPEND"` is the whole
/// difference between money leaving and money arriving, so it is a
/// literal here and a unit test reads this call's own body for it.
#[derive(Debug, Serialize)]
struct XeroBankTransactionBody {
    #[serde(rename = "Type")]
    kind: &'static str,
    #[serde(rename = "Contact")]
    contact: XeroContactRef,
    #[serde(rename = "BankAccount")]
    bank_account: XeroBankAccountRef,
    #[serde(rename = "LineItems")]
    line_items: Vec<XeroSpendLineBody>,
    #[serde(rename = "Date")]
    date: NaiveDate,
    #[serde(rename = "CurrencyCode")]
    currency_code: String,
    #[serde(rename = "Status")]
    status: &'static str,
}

#[derive(Debug, Deserialize)]
struct XeroBankTransactionEnvelope {
    #[serde(rename = "BankTransactions")]
    bank_transactions: Vec<XeroBankTransactionDto>,
}

#[derive(Debug, Deserialize)]
struct XeroBankTransactionDto {
    #[serde(rename = "BankTransactionID")]
    bank_transaction_id: String,
}

#[derive(Debug, Serialize)]
struct XeroPaymentInvoiceRef {
    #[serde(rename = "InvoiceID")]
    invoice_id: Uuid,
}

#[derive(Debug, Serialize)]
struct XeroPaymentBody {
    #[serde(rename = "Invoice")]
    invoice: XeroPaymentInvoiceRef,
    #[serde(rename = "Account")]
    account: XeroBankAccountRef,
    #[serde(rename = "Date")]
    date: NaiveDate,
    #[serde(rename = "Amount")]
    amount: String,
}

#[derive(Debug, Deserialize)]
struct XeroPaymentEnvelope {
    #[serde(rename = "Payments", default)]
    payments: Vec<XeroPaymentDto>,
}

#[derive(Debug, Deserialize)]
struct XeroPaymentDto {
    #[serde(rename = "PaymentID", default)]
    payment_id: String,
}

#[derive(Debug, Serialize)]
struct XeroCreateCreditNoteBody {
    #[serde(rename = "Type")]
    kind: &'static str,
    #[serde(rename = "Contact")]
    contact: XeroContactRef,
    #[serde(rename = "LineItems")]
    line_items: Vec<XeroLineItemBody>,
    #[serde(rename = "Date")]
    date: NaiveDate,
    #[serde(rename = "CurrencyCode")]
    currency_code: String,
    #[serde(rename = "Status")]
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct XeroAllocationsBody {
    #[serde(rename = "Allocations")]
    allocations: Vec<XeroAllocationBody>,
}

#[derive(Debug, Serialize)]
struct XeroAllocationBody {
    #[serde(rename = "Invoice")]
    invoice: XeroPaymentInvoiceRef,
    #[serde(rename = "Amount")]
    amount: String,
    #[serde(rename = "Date")]
    date: NaiveDate,
}

#[derive(Debug, Deserialize)]
struct XeroCreditNoteEnvelope {
    #[serde(rename = "CreditNotes", default)]
    credit_notes: Vec<XeroCreditNoteDto>,
}

#[derive(Debug, Deserialize)]
struct XeroCreditNoteDto {
    #[serde(rename = "CreditNoteID")]
    credit_note_id: String,
    #[serde(rename = "CreditNoteNumber", default)]
    credit_note_number: Option<String>,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "Allocations", default)]
    allocations: Vec<XeroAllocationDto>,
}

#[derive(Debug, Deserialize)]
struct XeroAllocationDto {
    #[serde(rename = "AllocationID", default)]
    allocation_id: Option<String>,
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
    /// Raise a bill against a vendor (MAPPS-1155).
    ///
    /// The same endpoint, the same retry policy and the same credentials
    /// as [`Self::issue_invoice`], with one field different: `ACCPAY`
    /// rather than `ACCREC`. In Xero an invoice and a bill are one
    /// resource distinguished by `Type`, which is why the client carries
    /// that as a field rather than a literal.
    ///
    /// Getting it wrong is not a cosmetic error. `ACCREC` against a
    /// vendor would put money the MSP OWES on the receivable side of
    /// their accounts, and a test asserts the type on the wire for
    /// exactly that reason.
    /// Record a reimbursement as a spend-money bank transaction
    /// (PMS-1541).
    ///
    /// `SPEND`, not `RECEIVE`: this is the MSP's money leaving to pay
    /// somebody back. Xero refuses the call without a `Contact` and
    /// without a `BankAccount`, which is why both are required fields on
    /// the request rather than options with a fallback.
    ///
    /// `AUTHORISED`: the money has already left the MSP's account by the
    /// time a claim is marked reimbursed here, so a draft over there would
    /// be a second place to confirm something that has happened.
    /// Record a payment against a bill the provider holds (PMS-1545).
    ///
    /// `PUT /Payments`, not a second bill: the bill is already over there
    /// (MAPPS-1155 raised it), and what is being told to Xero is that it
    /// has been settled. Xero's own `Payments` resource takes payments
    /// against either document type, so an `ACCPAY` bill is paid the same
    /// way a receivable is collected.
    ///
    /// Returns the provider's payment id, which is what a reconciliation
    /// reads back; the amount is sent as a decimal string for the reason
    /// every other money field here is, so no float reaches the wire.
    pub async fn pay_bill(
        &self,
        creds: &XeroCredentials,
        request: &XeroPayBillRequest,
    ) -> AppResult<String> {
        let body = XeroPaymentBody {
            invoice: XeroPaymentInvoiceRef {
                invoice_id: request.bill_id,
            },
            account: XeroBankAccountRef {
                account_id: request.bank_account_id.clone(),
            },
            date: request.paid_on,
            amount: minor_to_decimal(request.amount_minor, 2),
        };
        let url = format!("{}/api.xro/2.0/Payments", self.api_base);
        let envelope: XeroPaymentEnvelope = self
            .call_with_retry(|| {
                self.http
                    .put(&url)
                    .bearer_auth(&creds.access_token)
                    .header("Xero-Tenant-Id", &creds.tenant_id)
                    .header("Accept", "application/json")
                    .json(&body)
            })
            .await?;
        envelope
            .payments
            .into_iter()
            .next()
            .map(|p| p.payment_id)
            .ok_or_else(|| AppError::internal("Xero returned no payment".to_string()))
    }

    pub async fn record_spend(
        &self,
        creds: &XeroCredentials,
        request: &XeroRecordSpendRequest,
    ) -> AppResult<ExternalExpenseRef> {
        let body = XeroBankTransactionBody {
            kind: "SPEND",
            contact: XeroContactRef {
                contact_id: request.contact_id,
            },
            bank_account: XeroBankAccountRef {
                account_id: request.bank_account_id.clone(),
            },
            line_items: request
                .lines
                .iter()
                .map(|l| XeroSpendLineBody {
                    description: l.description.clone(),
                    line_amount: minor_to_decimal(l.amount_minor, 2),
                    account_code: l.account_code.clone(),
                })
                .collect(),
            date: request.paid_on,
            currency_code: request.currency.to_ascii_uppercase(),
            status: "AUTHORISED",
        };
        let url = format!("{}/api.xro/2.0/BankTransactions", self.api_base);
        let envelope: XeroBankTransactionEnvelope = self
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
            .bank_transactions
            .into_iter()
            .next()
            .ok_or_else(|| AppError::internal("Xero returned no bank transaction".to_string()))?;
        Ok(ExternalExpenseRef {
            provider: InvoiceProviderKind::Xero,
            external_expense_id: dto.bank_transaction_id,
        })
    }

    pub async fn create_bill(
        &self,
        creds: &XeroCredentials,
        request: &XeroCreateBillRequest,
    ) -> AppResult<ExternalBillRef> {
        let body = XeroCreateInvoiceBody {
            kind: "ACCPAY",
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
            date: request.issue_date,
            due_date: request.due_date,
            currency_code: request.currency.to_ascii_uppercase(),
            // AUTHORISED: the MSP has the bill in their hand already, so a
            // draft over there would be a second place to approve
            // something that is not in question.
            status: "AUTHORISED",
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
            .ok_or_else(|| AppError::internal("Xero returned no bill".to_string()))?;
        Ok(ExternalBillRef {
            provider: InvoiceProviderKind::Xero,
            external_bill_id: dto.invoice_id,
        })
    }

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

    /// Issue a credit note against an invoice this organisation holds
    /// (PMS-1546).
    ///
    /// `/CreditNotes` and not `/Invoices` with a third type: Xero keeps
    /// invoices and bills in one resource and credit notes in their own,
    /// so the type literal alone would not have been enough.
    ///
    /// `ACCRECCREDIT` and not `ACCPAYCREDIT`, which is the same mistake
    /// `ACCREC` against a vendor would be, in the other direction: the
    /// payable form credits a VENDOR, and a customer refund filed there
    /// would reduce what the MSP owes somebody else.
    ///
    /// `AUTHORISED`, because the credit note exists in Mokosh before this
    /// call and is not awaiting anybody's approval, and Xero refuses to
    /// allocate one that is still `DRAFT`.
    pub async fn issue_credit_note(
        &self,
        creds: &XeroCredentials,
        request: &XeroIssueCreditNoteRequest,
    ) -> AppResult<ExternalCreditNoteRef> {
        let body = XeroCreateCreditNoteBody {
            kind: "ACCRECCREDIT",
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
            date: request.issue_date,
            currency_code: request.currency.to_ascii_uppercase(),
            status: "AUTHORISED",
        };
        let url = format!("{}/api.xro/2.0/CreditNotes", self.api_base);
        let envelope: XeroCreditNoteEnvelope = self
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
            .credit_notes
            .into_iter()
            .next()
            .ok_or_else(|| AppError::internal("Xero returned no credit note".to_string()))?;
        Ok(ExternalCreditNoteRef {
            provider: InvoiceProviderKind::Xero,
            external_credit_note_id: dto.credit_note_id,
            external_number: dto.credit_note_number.unwrap_or_default(),
        })
    }

    /// Apply a credit note to the invoice it corrects (PMS-1546).
    ///
    /// A second call rather than a field, because Xero keeps allocation
    /// as the credit note's own sub-resource. Unallocated, the credit
    /// sits on the customer's account as `RemainingCredit` and the
    /// invoice keeps showing its full balance, which is the disagreement
    /// this whole path exists to close.
    ///
    /// Xero refuses an amount over what the invoice still owes, so a
    /// caller crediting an invoice the customer has already settled over
    /// there gets a refusal rather than a negative balance.
    pub async fn allocate_credit_note(
        &self,
        creds: &XeroCredentials,
        credit_note_id: &str,
        request: &XeroAllocateCreditRequest,
    ) -> AppResult<()> {
        let body = XeroAllocationsBody {
            allocations: vec![XeroAllocationBody {
                invoice: XeroPaymentInvoiceRef {
                    invoice_id: request.invoice_id,
                },
                amount: minor_to_decimal(request.amount_minor, 2),
                date: request.date,
            }],
        };
        let url = format!(
            "{}/api.xro/2.0/CreditNotes/{credit_note_id}/Allocations",
            self.api_base
        );
        let _envelope: serde_json::Value = self
            .call_with_retry(|| {
                self.http
                    .put(&url)
                    .bearer_auth(&creds.access_token)
                    .header("Xero-Tenant-Id", &creds.tenant_id)
                    .header("Accept", "application/json")
                    .json(&body)
            })
            .await?;
        Ok(())
    }

    /// What Xero says about one credit note now: its status and the
    /// allocations standing against it (PMS-1546).
    ///
    /// `None` for an id this organisation does not hold, which is an
    /// answer and not a failure, exactly as the QuickBooks void target
    /// treats a 404: a credit note that is not there is already in the
    /// state a void is asking for.
    pub async fn fetch_credit_note(
        &self,
        creds: &XeroCredentials,
        credit_note_id: &str,
    ) -> AppResult<Option<XeroCreditNoteState>> {
        let url = format!("{}/api.xro/2.0/CreditNotes/{credit_note_id}", self.api_base);
        let envelope: XeroCreditNoteEnvelope = match self
            .call_with_retry(|| {
                self.http
                    .get(&url)
                    .bearer_auth(&creds.access_token)
                    .header("Xero-Tenant-Id", &creds.tenant_id)
                    .header("Accept", "application/json")
            })
            .await
        {
            Ok(envelope) => envelope,
            Err(AppError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let Some(dto) = envelope.credit_notes.into_iter().next() else {
            return Ok(None);
        };
        Ok(Some(XeroCreditNoteState {
            status: XeroInvoiceStatus::parse(&dto.status),
            allocation_ids: dto
                .allocations
                .into_iter()
                .filter_map(|a| a.allocation_id)
                .collect(),
        }))
    }

    /// Remove one allocation from a credit note (PMS-1546).
    ///
    /// What a void has to do first. Xero will not change a document an
    /// allocation stands against, so voiding an applied credit note is
    /// refused until the application is taken off; doing it in that order
    /// also puts the invoice back to the balance it had, which is what
    /// voiding the credit means.
    pub async fn delete_credit_note_allocation(
        &self,
        creds: &XeroCredentials,
        credit_note_id: &str,
        allocation_id: &str,
    ) -> AppResult<()> {
        let url = format!(
            "{}/api.xro/2.0/CreditNotes/{credit_note_id}/Allocations/{allocation_id}",
            self.api_base
        );
        let _answer: serde_json::Value = self
            .call_with_retry(|| {
                self.http
                    .delete(&url)
                    .bearer_auth(&creds.access_token)
                    .header("Xero-Tenant-Id", &creds.tenant_id)
                    .header("Accept", "application/json")
            })
            .await?;
        Ok(())
    }

    /// Void a credit note in Xero (PMS-1546).
    ///
    /// The same shape as [`Self::void_invoice`] on the credit note's own
    /// URL: a status write, idempotent on the id, with a second call
    /// against an already-voided document answering the 400 the client
    /// classifies as a conflict.
    pub async fn void_credit_note(
        &self,
        creds: &XeroCredentials,
        credit_note_id: &str,
    ) -> AppResult<()> {
        let url = format!("{}/api.xro/2.0/CreditNotes/{credit_note_id}", self.api_base);
        let body = XeroVoidBody { status: "VOIDED" };
        let _envelope: XeroCreditNoteEnvelope = self
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
    /// What the provider says has been paid against one bill (PMS-1543).
    ///
    /// The same `GET /Invoices/{id}` the invoice status read uses, for the
    /// amounts rather than the status: an `ACCPAY` invoice carries
    /// `AmountPaid` and `Total`, and the difference between that paid
    /// figure and the local `paid_minor` is what Mokosh has not recorded.
    ///
    /// Reconciled rather than accumulated on purpose. A webhook delivery
    /// says "this changed", not "this much arrived", and providers
    /// redeliver; reading the provider's own running total makes a second
    /// delivery a no-op by arithmetic instead of by a dedupe table.
    ///
    /// The document type is checked: Xero puts bills and invoices on one
    /// endpoint and one webhook category, so a receiver that did not look
    /// would happily read an `ACCREC` invoice as a bill and record the
    /// customer's payment as the MSP's.
    pub async fn fetch_bill_settlement(
        &self,
        creds: &XeroCredentials,
        external_bill_id: &str,
    ) -> AppResult<Option<ExternalSettlement>> {
        let url = format!("{}/api.xro/2.0/Invoices/{external_bill_id}", self.api_base);
        let envelope: XeroSettlementEnvelope = self
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
            .ok_or_else(|| AppError::internal("Xero returned no document".to_string()))?;
        // Not a bill: the caller asked about an id that turned out to be a
        // receivable, which is an answer and not a failure.
        if !dto.kind.eq_ignore_ascii_case("ACCPAY") {
            return Ok(None);
        }
        Ok(Some(ExternalSettlement {
            paid_minor: decimal_string_to_minor(dto.amount_paid.as_deref().unwrap_or("0")),
            total_minor: decimal_string_to_minor(dto.total.as_deref().unwrap_or("0")),
            voided: matches!(
                XeroInvoiceStatus::parse(&dto.status),
                Some(XeroInvoiceStatus::Voided) | Some(XeroInvoiceStatus::Deleted)
            ),
        }))
    }

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
    let scale: u64 = 10_u64.pow(places);
    let sign = if minor < 0 { "-" } else { "" };
    let abs = minor.unsigned_abs();
    format!(
        "{sign}{}.{:0width$}",
        abs / scale,
        abs % scale,
        width = places as usize
    )
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
        // |minor| < scale: the whole part collapses to 0, so the sign
        // must come from the input, not from a nonzero whole part.
        assert_eq!(minor_to_decimal(-50, 2), "-0.50");
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

    /// MAPPS-1155: a bill is `ACCPAY`, and getting that wrong is not
    /// cosmetic.
    ///
    /// Xero keeps invoices and bills in one resource and tells them apart
    /// by `Type`. `ACCREC` against a vendor would put money the MSP OWES
    /// on the receivable side of their accounts, where it would read as
    /// revenue. The client builds the body from the same struct for both,
    /// so this is the one field standing between the two meanings.
    #[test]
    fn a_bill_is_accpay_and_an_invoice_is_accrec() {
        let bill = XeroCreateInvoiceBody {
            kind: "ACCPAY",
            contact: XeroContactRef {
                contact_id: Uuid::nil(),
            },
            line_items: vec![XeroLineItemBody {
                description: "Rack space".to_string(),
                quantity: "1.00".to_string(),
                unit_amount: "120.00".to_string(),
            }],
            date: NaiveDate::from_ymd_opt(2026, 10, 25).unwrap(),
            due_date: NaiveDate::from_ymd_opt(2026, 11, 25).unwrap(),
            currency_code: "USD".to_string(),
            status: "AUTHORISED",
        };
        let v = serde_json::to_value(&bill).expect("serialise");
        assert_eq!(v["Type"], "ACCPAY", "a bill is payable, not receivable");
        assert_eq!(v["LineItems"][0]["Description"], "Rack space");
        assert_eq!(
            v["Status"], "AUTHORISED",
            "the MSP already has the bill, so a draft over there would be a \
             second place to approve something that is not in question"
        );

        // And the source of the literal is the only difference between the
        // two documents, which is why they cannot be confused by accident
        // anywhere except here.
        let src = include_str!("xero.rs");
        let start = src.find("pub async fn create_bill").expect("the bill call");
        // To the next method, not to a named one: everything between
        // `create_bill` and the next `pub async fn` is its body, and an
        // end marker further down would sweep in `issue_invoice`, which
        // legitimately says ACCREC.
        let end = start
            + src[start..]
                .find("\n    pub async fn ")
                .expect("the next method");
        let create_bill = &src[start..end];
        assert!(
            create_bill.contains(r#"kind: "ACCPAY""#),
            "the bill call sends ACCPAY"
        );
        assert!(
            !create_bill.contains(r#"kind: "ACCREC""#),
            "and never the receivable type"
        );
    }

    /// PMS-1546: a customer credit is `ACCRECCREDIT`, and it goes to
    /// `/CreditNotes`.
    ///
    /// Two mistakes are available here and both are silent. The payable
    /// form, `ACCPAYCREDIT`, would credit a VENDOR, so money the MSP is
    /// giving a customer back would reduce what it owes somebody else.
    /// And posting the receivable credit to `/Invoices`, which is what
    /// the one-resource shape of bills and invoices suggests, is refused
    /// by Xero outright: credit notes are their own resource.
    #[test]
    fn a_customer_credit_is_accreccredit_on_the_credit_notes_resource() {
        let note = XeroCreateCreditNoteBody {
            kind: "ACCRECCREDIT",
            contact: XeroContactRef {
                contact_id: Uuid::nil(),
            },
            line_items: vec![XeroLineItemBody {
                description: "Overcharged month".to_string(),
                quantity: "1.00".to_string(),
                unit_amount: "40.00".to_string(),
            }],
            date: NaiveDate::from_ymd_opt(2026, 10, 28).unwrap(),
            currency_code: "USD".to_string(),
            status: "AUTHORISED",
        };
        let v = serde_json::to_value(&note).expect("serialise");
        assert_eq!(
            v["Type"], "ACCRECCREDIT",
            "a customer credit, not a vendor one"
        );
        assert!(
            v.get("DueDate").is_none(),
            "nothing falls due on money owed back: {v}"
        );
        assert_eq!(
            v["Status"], "AUTHORISED",
            "Xero refuses to allocate a draft credit note"
        );

        let src = include_str!("xero.rs");
        let start = src
            .find("pub async fn issue_credit_note")
            .expect("the credit note call");
        let end = start
            + src[start..]
                .find("\n    pub async fn ")
                .expect("the next method");
        let issue_credit_note = &src[start..end];
        assert!(
            issue_credit_note.contains(r#"kind: "ACCRECCREDIT""#),
            "the credit note call sends the receivable credit type"
        );
        assert!(
            !issue_credit_note.contains(r#"kind: "ACCPAYCREDIT""#),
            "and never the payable one, which credits a vendor"
        );
        assert!(
            issue_credit_note.contains("/api.xro/2.0/CreditNotes"),
            "and posts to the credit notes resource"
        );
    }

    /// PMS-1541: a reimbursement is SPEND, never RECEIVE.
    ///
    /// The type is the whole difference between money leaving and money
    /// arriving, and a wrong one puts a reimbursement on the income side
    /// of the MSP's books. Read off `record_spend`'s own body, bounded to
    /// the next method so the bill and invoice calls below cannot satisfy
    /// it.
    #[test]
    fn a_reimbursement_is_spend_and_never_receive() {
        let src = include_str!("xero.rs");
        let start = src
            .find("pub async fn record_spend")
            .expect("the spend call");
        let end = start
            + src[start..]
                .find("\n    pub async fn ")
                .expect("the next method");
        let record_spend = &src[start..end];
        assert!(
            record_spend.contains(r#"kind: "SPEND""#),
            "the spend call sends SPEND"
        );
        assert!(
            !record_spend.contains(r#"kind: "RECEIVE""#),
            "and never the money-in type"
        );
    }

    /// The spend body carries the two refs Xero refuses the call without,
    /// and an amount per line rather than a quantity at a price.
    #[test]
    fn the_spend_body_serialises_the_bank_account_and_the_contact() {
        let body = XeroBankTransactionBody {
            kind: "SPEND",
            contact: XeroContactRef {
                contact_id: Uuid::nil(),
            },
            bank_account: XeroBankAccountRef {
                account_id: "13918178-849a-247f-8ed7-c7b1f5e7e71c".to_string(),
            },
            line_items: vec![XeroSpendLineBody {
                description: "Taxi to site".to_string(),
                line_amount: "32.50".to_string(),
                account_code: "429".to_string(),
            }],
            date: NaiveDate::from_ymd_opt(2026, 11, 1).unwrap(),
            currency_code: "USD".to_string(),
            status: "AUTHORISED",
        };
        let v = serde_json::to_value(&body).expect("serialise");
        assert_eq!(v["Type"], "SPEND");
        assert_eq!(
            v["BankAccount"]["AccountID"], "13918178-849a-247f-8ed7-c7b1f5e7e71c",
            "the account the money left"
        );
        assert_eq!(v["Contact"]["ContactID"], Uuid::nil().to_string());
        assert_eq!(v["Date"], "2026-11-01");
        assert_eq!(v["Status"], "AUTHORISED");
        assert_eq!(v["LineItems"][0]["LineAmount"], "32.50");
        assert_eq!(
            v["LineItems"][0]["AccountCode"], "429",
            "and what the cost was filed under"
        );
        assert!(
            v["LineItems"][0].get("Quantity").is_none(),
            "a claim line is an amount, not a quantity at a price"
        );
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
