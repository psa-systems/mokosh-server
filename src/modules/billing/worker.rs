//! Recurring-invoicing worker (PMS-64 AC5).
//!
//! Each tick turns every active, recurring (non-`one_time`) contract that
//! is due for its current billing period into a draft invoice built from
//! the contract's recurring items, idempotently per period via the
//! `contract_invoice_runs` ledger. Delegates to
//! [`BillingService::generate_due_recurring_invoices_all_tenants`], which
//! enumerates tenants and runs the per-tenant generator. Cross-tenant,
//! like the contract lifecycle worker and the notifications dispatcher:
//! the worker owns the cadence, the service owns the per-period
//! transaction + dedupe.
//!
//! Implements the shared [`Job`](crate::scheduler::Job) trait so it can be
//! registered on the [`Scheduler`](crate::scheduler::Scheduler). The spawn
//! site is `src/main.rs`. Billing periods are day-granular, so a daily-ish
//! tick is ample; the idempotency ledger makes extra ticks within a period
//! no-ops, so the exact interval is not load-bearing.

use async_trait::async_trait;

use crate::scheduler::Job;
use crate::utils::error::AppResult;

use super::service::BillingService;

/// Worker handle. Clone is cheap (the service wraps an `Arc`-backed
/// `Database`).
#[derive(Clone)]
pub struct RecurringInvoicingWorker {
    service: BillingService,
}

impl RecurringInvoicingWorker {
    pub fn new(service: BillingService) -> Self {
        Self { service }
    }
}

#[async_trait]
impl Job for RecurringInvoicingWorker {
    fn name(&self) -> &'static str {
        "recurring_invoicing"
    }

    async fn run(&self) -> AppResult<()> {
        let created = self
            .service
            .generate_due_recurring_invoices_all_tenants(chrono::Utc::now())
            .await?;
        if created > 0 {
            tracing::info!(created, "recurring invoicing sweep");
        }
        Ok(())
    }
}

/// PMS-1037: mail the customer about overdue invoices on the tenant's
/// schedule. Hourly, so each tenant's local sending hour is hit once a day;
/// `invoice_reminders` keeps a second run in the same hour from sending
/// twice.
#[derive(Clone)]
pub struct InvoiceReminderWorker {
    service: BillingService,
}

impl InvoiceReminderWorker {
    pub fn new(service: BillingService) -> Self {
        Self { service }
    }
}

#[async_trait]
impl Job for InvoiceReminderWorker {
    fn name(&self) -> &'static str {
        "invoice_reminders"
    }

    async fn run(&self) -> AppResult<()> {
        let sent = self
            .service
            .send_due_reminders_all_tenants(chrono::Utc::now())
            .await?;
        if sent > 0 {
            tracing::info!(sent, "invoice reminder sweep");
        }
        Ok(())
    }
}
