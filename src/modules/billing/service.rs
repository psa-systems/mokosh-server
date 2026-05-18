//! Billing service. Endpoints land incrementally across PMS-33.

use chrono::Utc;
use rust_decimal::Decimal;
use uuid::Uuid;

use crate::db::Database;
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::PaginationParams;

use super::models::*;

/// Billing operations: invoices, payments, gateway configs, tax rates.
#[derive(Clone)]
pub struct BillingService {
    db: Database,
    /// 32-byte AES-256-GCM key used to encrypt
    /// `payment_gateway_configs.config_encrypted` at rest. Sourced from
    /// `AppConfig::encryption_key`; falls back to a zero-key for the
    /// default `new()` constructor so non-production callers stay
    /// compilable.
    encryption_key: [u8; 32],
}

impl BillingService {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            encryption_key: [0u8; 32],
        }
    }

    /// Production constructor: takes the same `ENCRYPTION_KEY` env that
    /// auth uses for token encryption. Hands the key down to the
    /// payment-gateway-config write path so secrets never hit the DB
    /// in cleartext.
    pub fn with_encryption_key(db: Database, encryption_key: [u8; 32]) -> Self {
        Self {
            db,
            encryption_key,
        }
    }

    /// PMS-35: paginated + filterable invoice list. `lines` is left
    /// `None` on list rollups — the customer-facing UI fetches lines
    /// only when expanding a row.
    pub async fn list_invoices(
        &self,
        tenant_id: Uuid,
        filter: &InvoiceFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<InvoiceResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;

        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut param_idx = 4;
        if filter.company_id.is_some() {
            conditions.push(format!("company_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.status.is_some() {
            conditions.push(format!("status = ${param_idx}"));
            param_idx += 1;
        }
        if filter.contract_id.is_some() {
            conditions.push(format!("contract_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.q.is_some() {
            conditions.push(format!("(invoice_number ILIKE ${param_idx} OR po_number ILIKE ${param_idx})"));
        }

        let where_clause = conditions.join(" AND ");
        let order_by = pagination.order_by(
            "invoice_date DESC",
            &["invoice_date", "due_date", "total", "created_at"],
        );
        let query = format!(
            r#"
            SELECT id, tenant_id, invoice_number, company_id, billing_contact_id,
                   contract_id, status, invoice_date, due_date, payment_terms,
                   subtotal, tax_amount, discount_amount, total, amount_paid,
                   balance_due, currency, notes, po_number, sent_at, paid_at,
                   created_at, updated_at
            FROM invoices
            WHERE {where_clause}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM invoices WHERE {where_clause}");

        let mut q = sqlx::query_as::<_, InvoiceRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(cid) = filter.company_id {
            q = q.bind(cid);
            cq = cq.bind(cid);
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status);
            cq = cq.bind(status);
        }
        if let Some(ctid) = filter.contract_id {
            q = q.bind(ctid);
            cq = cq.bind(ctid);
        }
        if let Some(ref s) = filter.q {
            let pattern = format!("%{s}%");
            q = q.bind(pattern.clone());
            cq = cq.bind(pattern);
        }

        let rows = q.fetch_all(self.db.pool()).await?;
        let total = cq.fetch_one(self.db.pool()).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// PMS-37: create an invoice with its line items in one
    /// transaction. Atomically increments `invoice_sequences.last_number`
    /// (per tenant) for the human-readable invoice number; computes
    /// `subtotal = sum(line.total)` and `total = subtotal + tax -
    /// discount`. `balance_due` is initialised to `total`; payments
    /// move it down via PMS-39.
    pub async fn create_invoice(
        &self,
        tenant_id: Uuid,
        request: &CreateInvoiceRequest,
    ) -> AppResult<InvoiceResponse> {
        let mut tx = self.db.pool().begin().await?;

        // Per-tenant invoice sequence is row-locked by UPDATE
        // RETURNING; concurrent invoice creates serialise on this row
        // so numbers are dense and unique.
        let seq_row: Option<(i32, Option<String>)> = sqlx::query_as(
            r#"
            UPDATE invoice_sequences
            SET last_number = last_number + 1
            WHERE tenant_id = $1
            RETURNING last_number, prefix
            "#,
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (next_number, prefix) = match seq_row {
            Some(v) => v,
            None => {
                // First invoice for this tenant: seed the sequence row.
                sqlx::query(
                    "INSERT INTO invoice_sequences (tenant_id, last_number) VALUES ($1, 1)",
                )
                .bind(tenant_id)
                .execute(&mut *tx)
                .await?;
                (1, Some("INV-".to_string()))
            }
        };
        let invoice_number = format!("{}{:06}", prefix.unwrap_or_else(|| "INV-".to_string()), next_number);

        // Compute totals from the supplied lines. Tax / discount are
        // optional - default to 0.
        let subtotal: Decimal = request
            .lines
            .iter()
            .map(|l| l.quantity * l.unit_price)
            .sum();
        let tax = request.tax_amount.unwrap_or(Decimal::ZERO);
        let discount = request.discount_amount.unwrap_or(Decimal::ZERO);
        let total = subtotal + tax - discount;

        let invoice_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO invoices (
                id, tenant_id, invoice_number, company_id, billing_contact_id,
                contract_id, status, invoice_date, due_date, payment_terms,
                subtotal, tax_amount, discount_amount, total, amount_paid,
                balance_due, currency, notes, po_number
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, $9, $10, $11,
                    $12, $13, 0, $13, $14, $15, $16)
            "#,
        )
        .bind(invoice_id)
        .bind(tenant_id)
        .bind(&invoice_number)
        .bind(request.company_id)
        .bind(request.billing_contact_id)
        .bind(request.contract_id)
        .bind(request.invoice_date)
        .bind(request.due_date)
        .bind(&request.payment_terms)
        .bind(subtotal)
        .bind(tax)
        .bind(discount)
        .bind(total)
        .bind(request.currency.as_deref().unwrap_or("USD"))
        .bind(&request.notes)
        .bind(&request.po_number)
        .execute(&mut *tx)
        .await?;

        for line in &request.lines {
            sqlx::query(
                r#"
                INSERT INTO invoice_lines (
                    id, invoice_id, line_type, description, quantity, unit_price,
                    total, ticket_id, project_id, sort_order
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(invoice_id)
            .bind(line.line_type.as_str())
            .bind(&line.description)
            .bind(line.quantity)
            .bind(line.unit_price)
            .bind(line.quantity * line.unit_price)
            .bind(line.ticket_id)
            .bind(line.project_id)
            .bind(line.sort_order)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        self.get_invoice(tenant_id, invoice_id).await
    }

    /// PMS-40: list payment gateway configs for the tenant. Each
    /// response carries the *decrypted* config so a finance admin can
    /// confirm what's wired without an extra round-trip to a "reveal"
    /// endpoint.
    pub async fn list_payment_gateways(
        &self,
        tenant_id: Uuid,
    ) -> AppResult<Vec<PaymentGatewayConfigResponse>> {
        let rows = sqlx::query_as::<_, PaymentGatewayRow>(
            r#"
            SELECT id, provider, is_active, is_test_mode, config_encrypted
            FROM payment_gateway_configs
            WHERE tenant_id = $1
            ORDER BY provider
            "#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        rows.into_iter()
            .map(|r| {
                let decrypted = crate::utils::crypto::decrypt(
                    &r.config_encrypted,
                    &self.encryption_key,
                )?;
                let config: serde_json::Value =
                    serde_json::from_str(&decrypted).unwrap_or(serde_json::Value::Null);
                Ok(PaymentGatewayConfigResponse {
                    id: r.id,
                    provider: GatewayProvider::from_str(&r.provider)
                        .unwrap_or(GatewayProvider::Stripe),
                    is_active: r.is_active,
                    is_test_mode: r.is_test_mode,
                    config,
                })
            })
            .collect()
    }

    /// PMS-40: upsert a payment gateway config. `(tenant_id, provider)`
    /// is unique in the schema, so the same call ends up insert-or-update.
    /// Encrypts the `config` blob at rest with the host encryption key.
    pub async fn upsert_payment_gateway(
        &self,
        tenant_id: Uuid,
        request: &UpsertPaymentGatewayConfigRequest,
    ) -> AppResult<PaymentGatewayConfigResponse> {
        let plaintext = serde_json::to_string(&request.config).map_err(|e| {
            AppError::BadRequest(format!("config must serialise to JSON: {e}"))
        })?;
        let encrypted =
            crate::utils::crypto::encrypt(&plaintext, &self.encryption_key)?;

        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO payment_gateway_configs
                (tenant_id, provider, is_active, is_test_mode, config_encrypted)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, provider) DO UPDATE SET
                is_active        = EXCLUDED.is_active,
                is_test_mode     = EXCLUDED.is_test_mode,
                config_encrypted = EXCLUDED.config_encrypted,
                updated_at       = NOW()
            RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(request.provider.as_str())
        .bind(request.is_active)
        .bind(request.is_test_mode)
        .bind(&encrypted)
        .fetch_one(self.db.pool())
        .await?;

        Ok(PaymentGatewayConfigResponse {
            id,
            provider: request.provider,
            is_active: request.is_active,
            is_test_mode: request.is_test_mode,
            config: request.config.clone(),
        })
    }

    /// PMS-40: delete a payment gateway config. No-op if absent.
    pub async fn delete_payment_gateway(
        &self,
        tenant_id: Uuid,
        provider: GatewayProvider,
    ) -> AppResult<()> {
        sqlx::query("DELETE FROM payment_gateway_configs WHERE tenant_id = $1 AND provider = $2")
            .bind(tenant_id)
            .bind(provider.as_str())
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    /// PMS-39: list payments. Optional filter on invoice_id and/or
    /// company_id.
    pub async fn list_payments(
        &self,
        tenant_id: Uuid,
        filter: &PaymentFilter,
        pagination: &PaginationParams,
    ) -> AppResult<(Vec<PaymentResponse>, u64)> {
        let offset = pagination.offset() as i64;
        let limit = pagination.limit() as i64;
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut param_idx = 4;
        if filter.invoice_id.is_some() {
            conditions.push(format!("invoice_id = ${param_idx}"));
            param_idx += 1;
        }
        if filter.company_id.is_some() {
            conditions.push(format!("company_id = ${param_idx}"));
        }
        let where_clause = conditions.join(" AND ");
        let order_by = pagination.order_by(
            "payment_date DESC",
            &["payment_date", "amount", "created_at"],
        );
        let query = format!(
            r#"
            SELECT id, tenant_id, invoice_id, company_id, payment_date, amount,
                   payment_method, reference_number, gateway_transaction_id,
                   notes, created_at
            FROM payments
            WHERE {where_clause}
            ORDER BY {order_by}
            LIMIT $2 OFFSET $3
            "#
        );
        let count_query = format!("SELECT COUNT(*) FROM payments WHERE {where_clause}");
        let mut q = sqlx::query_as::<_, PaymentRow>(&query)
            .bind(tenant_id)
            .bind(limit)
            .bind(offset);
        let mut cq = sqlx::query_scalar::<_, i64>(&count_query).bind(tenant_id);
        if let Some(iid) = filter.invoice_id {
            q = q.bind(iid);
            cq = cq.bind(iid);
        }
        if let Some(cid) = filter.company_id {
            q = q.bind(cid);
            cq = cq.bind(cid);
        }
        let rows = q.fetch_all(self.db.pool()).await?;
        let total = cq.fetch_one(self.db.pool()).await?;
        Ok((rows.into_iter().map(Into::into).collect(), total as u64))
    }

    /// PMS-39: record a payment. When `invoice_id` is set, the linked
    /// invoice's `amount_paid` is bumped and `balance_due` recomputed
    /// in the same transaction; the status moves to `paid` (or
    /// `partially_paid`) accordingly.
    pub async fn create_payment(
        &self,
        tenant_id: Uuid,
        request: &CreatePaymentRequest,
    ) -> AppResult<PaymentResponse> {
        let mut tx = self.db.pool().begin().await?;

        let payment_id = Uuid::new_v4();
        let created_at: chrono::DateTime<Utc> = sqlx::query_scalar(
            r#"
            INSERT INTO payments (
                id, tenant_id, invoice_id, company_id, payment_date, amount,
                payment_method, reference_number, gateway_transaction_id, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING created_at
            "#,
        )
        .bind(payment_id)
        .bind(tenant_id)
        .bind(request.invoice_id)
        .bind(request.company_id)
        .bind(request.payment_date)
        .bind(request.amount)
        .bind(request.payment_method.as_str())
        .bind(&request.reference_number)
        .bind(&request.gateway_transaction_id)
        .bind(&request.notes)
        .fetch_one(&mut *tx)
        .await?;

        if let Some(invoice_id) = request.invoice_id {
            // Pull the current totals + tenant guard.
            let current: Option<(Decimal, Decimal)> = sqlx::query_as(
                "SELECT total, amount_paid FROM invoices WHERE id = $1 AND tenant_id = $2",
            )
            .bind(invoice_id)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((total, prior_paid)) = current else {
                return Err(AppError::NotFound("Invoice".to_string()));
            };
            let new_paid = prior_paid + request.amount;
            let new_balance = total - new_paid;
            let new_status = if new_balance <= Decimal::ZERO {
                "paid"
            } else if new_paid > Decimal::ZERO {
                "partially_paid"
            } else {
                "sent"
            };
            let paid_at = if new_status == "paid" { Some(Utc::now()) } else { None };
            sqlx::query(
                r#"
                UPDATE invoices SET
                    amount_paid = $2,
                    balance_due = $3,
                    status      = $4,
                    paid_at     = COALESCE($5, paid_at),
                    updated_at  = NOW()
                WHERE id = $1
                "#,
            )
            .bind(invoice_id)
            .bind(new_paid)
            .bind(new_balance)
            .bind(new_status)
            .bind(paid_at)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(PaymentResponse {
            id: payment_id,
            tenant_id,
            invoice_id: request.invoice_id,
            company_id: request.company_id,
            payment_date: request.payment_date,
            amount: request.amount,
            payment_method: request.payment_method,
            reference_number: request.reference_number.clone(),
            gateway_transaction_id: request.gateway_transaction_id.clone(),
            notes: request.notes.clone(),
            created_at,
        })
    }

    /// PMS-39: delete a payment. Reverses the linked invoice's
    /// `amount_paid` / `balance_due` / `status`. Hard delete is the
    /// right call for unposted payments; once a payment has been
    /// posted to accounting it should be voided through a credit
    /// note instead - which is out of scope for this commit.
    pub async fn delete_payment(&self, tenant_id: Uuid, payment_id: Uuid) -> AppResult<()> {
        let mut tx = self.db.pool().begin().await?;

        let row: Option<(Option<Uuid>, Decimal)> = sqlx::query_as(
            "SELECT invoice_id, amount FROM payments WHERE id = $1 AND tenant_id = $2",
        )
        .bind(payment_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((invoice_id, amount)) = row else {
            return Err(AppError::NotFound("Payment".to_string()));
        };

        sqlx::query("DELETE FROM payments WHERE id = $1")
            .bind(payment_id)
            .execute(&mut *tx)
            .await?;

        if let Some(invoice_id) = invoice_id {
            let current: Option<(Decimal, Decimal)> = sqlx::query_as(
                "SELECT total, amount_paid FROM invoices WHERE id = $1",
            )
            .bind(invoice_id)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some((total, prior_paid)) = current {
                let new_paid = (prior_paid - amount).max(Decimal::ZERO);
                let new_balance = total - new_paid;
                let new_status = if new_paid == Decimal::ZERO {
                    "sent"
                } else if new_balance <= Decimal::ZERO {
                    "paid"
                } else {
                    "partially_paid"
                };
                sqlx::query(
                    r#"
                    UPDATE invoices SET
                        amount_paid = $2,
                        balance_due = $3,
                        status      = $4,
                        paid_at     = CASE WHEN $4 = 'paid' THEN paid_at ELSE NULL END,
                        updated_at  = NOW()
                    WHERE id = $1
                    "#,
                )
                .bind(invoice_id)
                .bind(new_paid)
                .bind(new_balance)
                .bind(new_status)
                .execute(&mut *tx)
                .await?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    /// PMS-38: update an invoice header and optionally replace its
    /// line items in one transaction. Rejects edits on
    /// `InvoiceStatus::is_frozen` invoices (sent, paid, partially paid,
    /// void, written off) - correction goes through a credit note,
    /// which is out of scope for this commit.
    pub async fn update_invoice(
        &self,
        tenant_id: Uuid,
        invoice_id: Uuid,
        request: &UpdateInvoiceRequest,
    ) -> AppResult<InvoiceResponse> {
        let current = self.get_invoice(tenant_id, invoice_id).await?;
        if current.status.is_frozen() {
            return Err(AppError::Conflict(format!(
                "Invoice in status '{}' cannot be edited",
                current.status.as_str()
            )));
        }

        let mut tx = self.db.pool().begin().await?;

        // Replace lines first (if requested) so the recomputed
        // subtotal reflects the new set when we write the header.
        let subtotal = if let Some(lines) = &request.lines {
            sqlx::query("DELETE FROM invoice_lines WHERE invoice_id = $1")
                .bind(invoice_id)
                .execute(&mut *tx)
                .await?;
            let mut sub = Decimal::ZERO;
            for line in lines {
                let line_total = line.quantity * line.unit_price;
                sub += line_total;
                sqlx::query(
                    r#"
                    INSERT INTO invoice_lines (
                        id, invoice_id, line_type, description, quantity,
                        unit_price, total, ticket_id, project_id, sort_order
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    "#,
                )
                .bind(Uuid::new_v4())
                .bind(invoice_id)
                .bind(line.line_type.as_str())
                .bind(&line.description)
                .bind(line.quantity)
                .bind(line.unit_price)
                .bind(line_total)
                .bind(line.ticket_id)
                .bind(line.project_id)
                .bind(line.sort_order)
                .execute(&mut *tx)
                .await?;
            }
            sub
        } else {
            current.subtotal
        };

        let tax = request.tax_amount.unwrap_or(current.tax_amount);
        let discount = request.discount_amount.unwrap_or(current.discount_amount);
        let total = subtotal + tax - discount;
        let balance_due = total - current.amount_paid;

        // `sent_at` is stamped when the status first moves to `sent`.
        let status = request.status.unwrap_or(current.status);
        let sent_at = if matches!(status, InvoiceStatus::Sent) && current.sent_at.is_none() {
            Some(Utc::now())
        } else {
            current.sent_at
        };

        sqlx::query(
            r#"
            UPDATE invoices SET
                billing_contact_id = COALESCE($2, billing_contact_id),
                contract_id        = COALESCE($3, contract_id),
                invoice_date       = COALESCE($4, invoice_date),
                due_date           = COALESCE($5, due_date),
                payment_terms      = COALESCE($6, payment_terms),
                notes              = COALESCE($7, notes),
                po_number          = COALESCE($8, po_number),
                status             = $9,
                subtotal           = $10,
                tax_amount         = $11,
                discount_amount    = $12,
                total              = $13,
                balance_due        = $14,
                sent_at            = $15,
                updated_at         = NOW()
            WHERE id = $1
            "#,
        )
        .bind(invoice_id)
        .bind(request.billing_contact_id)
        .bind(request.contract_id)
        .bind(request.invoice_date)
        .bind(request.due_date)
        .bind(request.payment_terms.as_deref())
        .bind(request.notes.as_deref())
        .bind(request.po_number.as_deref())
        .bind(status.as_str())
        .bind(subtotal)
        .bind(tax)
        .bind(discount)
        .bind(total)
        .bind(balance_due)
        .bind(sent_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        self.get_invoice(tenant_id, invoice_id).await
    }

    /// PMS-36: read a single invoice with `lines` populated. 404 when
    /// the id is outside the tenant.
    pub async fn get_invoice(
        &self,
        tenant_id: Uuid,
        invoice_id: Uuid,
    ) -> AppResult<InvoiceResponse> {
        let row = sqlx::query_as::<_, InvoiceRow>(
            r#"
            SELECT id, tenant_id, invoice_number, company_id, billing_contact_id,
                   contract_id, status, invoice_date, due_date, payment_terms,
                   subtotal, tax_amount, discount_amount, total, amount_paid,
                   balance_due, currency, notes, po_number, sent_at, paid_at,
                   created_at, updated_at
            FROM invoices
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(invoice_id)
        .fetch_optional(self.db.pool())
        .await?
        .ok_or_else(|| AppError::NotFound("Invoice".to_string()))?;

        let line_rows = sqlx::query_as::<_, InvoiceLineRow>(
            r#"
            SELECT id, line_type, description, quantity, unit_price, total,
                   ticket_id, project_id, sort_order
            FROM invoice_lines
            WHERE invoice_id = $1
            ORDER BY sort_order, created_at
            "#,
        )
        .bind(invoice_id)
        .fetch_all(self.db.pool())
        .await?;

        let mut resp: InvoiceResponse = row.into();
        resp.lines = Some(line_rows.into_iter().map(Into::into).collect());
        Ok(resp)
    }
}

#[derive(sqlx::FromRow)]
struct PaymentGatewayRow {
    id: Uuid,
    provider: String,
    is_active: bool,
    is_test_mode: bool,
    config_encrypted: String,
}

#[derive(sqlx::FromRow)]
struct PaymentRow {
    id: Uuid,
    tenant_id: Uuid,
    invoice_id: Option<Uuid>,
    company_id: Uuid,
    payment_date: chrono::NaiveDate,
    amount: Decimal,
    payment_method: String,
    reference_number: Option<String>,
    gateway_transaction_id: Option<String>,
    notes: Option<String>,
    created_at: chrono::DateTime<Utc>,
}

impl From<PaymentRow> for PaymentResponse {
    fn from(r: PaymentRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            invoice_id: r.invoice_id,
            company_id: r.company_id,
            payment_date: r.payment_date,
            amount: r.amount,
            payment_method: PaymentMethod::from_str(&r.payment_method)
                .unwrap_or(PaymentMethod::Other),
            reference_number: r.reference_number,
            gateway_transaction_id: r.gateway_transaction_id,
            notes: r.notes,
            created_at: r.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct InvoiceLineRow {
    id: Uuid,
    line_type: String,
    description: String,
    quantity: Decimal,
    unit_price: Decimal,
    total: Decimal,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    sort_order: i32,
}

impl From<InvoiceLineRow> for InvoiceLineResponse {
    fn from(r: InvoiceLineRow) -> Self {
        Self {
            id: r.id,
            line_type: InvoiceLineType::from_str(&r.line_type).unwrap_or(InvoiceLineType::Service),
            description: r.description,
            quantity: r.quantity,
            unit_price: r.unit_price,
            total: r.total,
            ticket_id: r.ticket_id,
            project_id: r.project_id,
            sort_order: r.sort_order,
        }
    }
}

#[derive(sqlx::FromRow)]
struct InvoiceRow {
    id: Uuid,
    tenant_id: Uuid,
    invoice_number: String,
    company_id: Uuid,
    billing_contact_id: Option<Uuid>,
    contract_id: Option<Uuid>,
    status: String,
    invoice_date: chrono::NaiveDate,
    due_date: chrono::NaiveDate,
    payment_terms: Option<String>,
    subtotal: Decimal,
    tax_amount: Decimal,
    discount_amount: Decimal,
    total: Decimal,
    amount_paid: Decimal,
    balance_due: Decimal,
    currency: Option<String>,
    notes: Option<String>,
    po_number: Option<String>,
    sent_at: Option<chrono::DateTime<Utc>>,
    paid_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<InvoiceRow> for InvoiceResponse {
    fn from(r: InvoiceRow) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            invoice_number: r.invoice_number,
            company_id: r.company_id,
            billing_contact_id: r.billing_contact_id,
            contract_id: r.contract_id,
            status: InvoiceStatus::from_str(&r.status).unwrap_or(InvoiceStatus::Draft),
            invoice_date: r.invoice_date,
            due_date: r.due_date,
            payment_terms: r.payment_terms,
            subtotal: r.subtotal,
            tax_amount: r.tax_amount,
            discount_amount: r.discount_amount,
            total: r.total,
            amount_paid: r.amount_paid,
            balance_due: r.balance_due,
            currency: r.currency,
            notes: r.notes,
            po_number: r.po_number,
            sent_at: r.sent_at,
            paid_at: r.paid_at,
            created_at: r.created_at,
            updated_at: r.updated_at,
            lines: None,
        }
    }
}

#[allow(dead_code)]
fn _force_use(_: &AppError) {}
