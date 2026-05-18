//! Billing service. Endpoints land incrementally; this commit (PMS-34)
//! is the scaffold so the router has something to mount.

use crate::db::Database;

/// Billing operations: invoices, payments, gateway configs, tax rates.
#[derive(Clone)]
pub struct BillingService {
    pub(super) db: Database,
}

impl BillingService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}
