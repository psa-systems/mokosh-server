//! Billing module: invoices, payments, refunds, payment gateway configs, tax
//! rates.
//!
//! Schema lives in `010_billing.sql` (+ later per-feature migrations); this
//! module wires the HTTP + service layer on top. Endpoints landed incrementally
//! across the PMS-33 story.
//!
//! ## PMS-711: payment-provider "Pay Now"
//!
//! A tenant connects their OWN Stripe account (a per-tenant restricted key,
//! stored write-only in `payment_gateway_configs` per PMS-342), so funds settle
//! to them and the platform is never in the money flow. The [`provider`] module
//! abstracts the gateway behind [`PaymentProvider`]; [`provider::StripeProvider`]
//! is the first adapter, and adding PayPal is a new impl rather than a rewrite.
//! The portal `POST /invoices/:id/pay` mints a hosted checkout session, and the
//! unauthenticated, signature-verified `POST /api/v1/stripe/webhooks/:tenant_id`
//! reconciles the result back onto the invoice (amount, currency, provider
//! reference, timestamp). Reconciliation is idempotent (unique provider
//! references) and always net of refunds.
//!
//! In scope: full payment, Stripe-driven partial payment, and refunds
//! (`charge.refunded` feeds `payment_refunds`, and the invoice is recomputed net
//! of refunds). Out of scope (deliberately, not implicitly): Stripe Connect
//! onboarding (the tenant's own key is used instead), PayPal (a follow-up
//! adapter), and zero-decimal currencies (see the `provider::stripe` module
//! doc). Manual payments and refunds keep working through the existing
//! `/payments` path unchanged.

pub mod credential_move;
pub mod documents;
pub mod issuer;
pub mod models;
pub mod provider;
pub mod routes;
pub mod service;
pub mod stripe_webhook;
pub mod worker;

pub use credential_move::{CredentialMoveOutcome, GatewayCredentialMover};
pub use issuer::Issuer;
pub use models::*;
pub use provider::{CheckoutParams, CheckoutSession, PaymentEvent, PaymentProvider, RefundLine};
pub use routes::billing_routes;
pub use service::BillingService;
pub use stripe_webhook::{stripe_webhook_handler, StripeWebhookState};
pub use worker::RecurringInvoicingWorker;
