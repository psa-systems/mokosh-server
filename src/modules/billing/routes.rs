//! Billing HTTP routes. Endpoints land incrementally across PMS-33.

use std::sync::Arc;

use axum::Router;

use super::service::BillingService;

#[derive(Clone)]
pub struct BillingRouterState {
    pub service: Arc<BillingService>,
}

/// Build the `/invoices` + `/payments` + `/payment-gateways` + `/tax-rates`
/// router. Empty in the scaffolding commit (PMS-34); each follow-up
/// sub-task adds endpoints.
pub fn billing_routes(service: BillingService) -> Router {
    let _state = BillingRouterState {
        service: Arc::new(service),
    };
    Router::new()
}
