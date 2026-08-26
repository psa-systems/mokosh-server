//! Ticket automation engine
//!
//! Handles ticket automation rules including:
//! - On create triggers
//! - On update triggers
//! - Scheduled triggers
//! - SLA breach/warning triggers

use std::sync::Arc;
use std::time::Duration;

use crate::modules::auth::TenantId;
use url::Url;
use uuid::Uuid;

use crate::db::Database;
use crate::modules::notifications::NotificationsService;
use crate::utils::email::{LogMailer, Mailer};
use crate::utils::error::AppResult;
use crate::utils::net::{
    guard_outbound_url, private_target_allowlist, HostResolver, PrivateTargetAllowlist,
    SystemResolver, UrlGuardError,
};

use super::models::*;

/// Redirect hops the `webhook` action follows. Each one is re-screened, so a
/// rule cannot reach a private address by way of a redirect either.
const WEBHOOK_MAX_HOPS: usize = 5;

/// Why a `webhook` action did not deliver. Every variant is logged; none is
/// folded into a success (PMS-809).
#[derive(Debug, thiserror::Error)]
enum WebhookError {
    /// The SSRF guard refused the target. Carries the resolved address it
    /// refused, so the log names it.
    #[error("{0}")]
    Refused(#[from] UrlGuardError),
    #[error("{0}")]
    Transport(String),
    #[error("more than {0} redirects")]
    TooManyRedirects(usize),
}

/// Automation engine for processing ticket automation rules
#[derive(Clone)]
pub struct AutomationEngine {
    db: Database,
    mailer: Arc<dyn Mailer>,
    http: reqwest::Client,
    /// Resolver the `webhook` action screens through. A field rather than a
    /// call so a test can script DNS without touching the network.
    resolver: Arc<dyn HostResolver>,
    /// When `Some`, the `send_notification` action dispatches through
    /// the notifications queue (template + worker delivery) instead of
    /// hitting the mailer directly. None preserves the legacy inline
    /// send so older test fixtures still work.
    notifications: Option<NotificationsService>,
}

impl AutomationEngine {
    pub fn new(db: Database) -> Self {
        Self::with_deps(db, Arc::new(LogMailer))
    }

    /// Build with an explicit mailer. The HTTP client used for the
    /// `webhook` action is created here with a 10-second timeout; one
    /// misbehaving endpoint should not stall the rest of the rule
    /// chain.
    pub fn with_deps(db: Database, mailer: Arc<dyn Mailer>) -> Self {
        Self::build(db, mailer, None)
    }

    /// Like [`Self::with_deps`] but additionally wires the
    /// notifications dispatcher so the `send_notification` action
    /// enqueues an email rather than calling SMTP inline.
    pub fn with_dispatcher(
        db: Database,
        mailer: Arc<dyn Mailer>,
        notifications: NotificationsService,
    ) -> Self {
        Self::build(db, mailer, Some(notifications))
    }

    fn build(
        db: Database,
        mailer: Arc<dyn Mailer>,
        notifications: Option<NotificationsService>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("mokosh-server/automation")
            // The webhook action follows redirects itself so it can re-run the
            // SSRF guard on every hop; reqwest must not do it underneath.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client builds with default config");
        Self {
            db,
            mailer,
            http,
            resolver: Arc::new(SystemResolver),
            notifications,
        }
    }

    /// Process automation rules for a trigger type
    pub async fn process_rules(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        trigger: AutomationTrigger,
    ) -> AppResult<()> {
        // Get active rules for this trigger type
        let rules = self.get_active_rules(tenant_id, trigger).await?;

        for rule in rules {
            if self
                .evaluate_conditions(tenant_id, ticket_id, &rule)
                .await?
            {
                self.execute_actions(tenant_id, ticket_id, &rule).await?;
            }
        }

        Ok(())
    }

    /// Get active automation rules for a trigger type
    async fn get_active_rules(
        &self,
        tenant_id: TenantId,
        trigger: AutomationTrigger,
    ) -> AppResult<Vec<AutomationRule>> {
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let rows = sqlx::query_as::<_, AutomationRuleRow>(
            r#"
            SELECT id, tenant_id, name, description, is_active, trigger_type,
                   conditions, actions, priority, last_run_at, run_count,
                   created_at, updated_at
            FROM ticket_automation_rules
            WHERE tenant_id = $1 AND trigger_type = $2 AND is_active = TRUE
            ORDER BY priority ASC
            "#,
        )
        .bind(tenant_id)
        .bind(trigger.as_str())
        .fetch_all(&mut *tx)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Evaluate if rule conditions match the ticket
    async fn evaluate_conditions(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        rule: &AutomationRule,
    ) -> AppResult<bool> {
        // Parse conditions from JSON
        let conditions: Vec<AutomationCondition> =
            serde_json::from_value(rule.conditions.clone()).unwrap_or_default();

        if conditions.is_empty() {
            return Ok(true); // No conditions means always match
        }

        // Get ticket data
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        let ticket = sqlx::query_as::<_, TicketDataRow>(
            r#"
            SELECT t.*, s.name as status_name, p.name as priority_name
            FROM tickets t
            LEFT JOIN ticket_statuses s ON t.status_id = s.id
            LEFT JOIN ticket_priorities p ON t.priority_id = p.id
            WHERE t.tenant_id = $1 AND t.id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(ticket_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(ticket) = ticket else {
            return Ok(false);
        };

        // Evaluate each condition
        for condition in conditions {
            if !self.evaluate_condition(&ticket, &condition) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Evaluate a single condition against ticket data
    fn evaluate_condition(&self, ticket: &TicketDataRow, condition: &AutomationCondition) -> bool {
        let field_value = match condition.field.as_str() {
            "status" => Some(ticket.status_name.clone()),
            "priority" => Some(ticket.priority_name.clone()),
            "company_id" => Some(ticket.company_id.to_string()),
            "assigned_to_id" => ticket.assigned_to_id.map(|id| id.to_string()),
            "source" => Some(ticket.source.clone()),
            "is_billable" => Some(ticket.is_billable.to_string()),
            _ => None,
        };

        let Some(value) = field_value else {
            return false;
        };

        let expected = condition.value.as_str().unwrap_or("").to_string();

        match condition.operator.as_str() {
            "equals" => value == expected,
            "not_equals" => value != expected,
            "contains" => value.contains(&expected),
            "starts_with" => value.starts_with(&expected),
            "ends_with" => value.ends_with(&expected),
            "is_null" => value.is_empty(),
            "is_not_null" => !value.is_empty(),
            _ => false,
        }
    }

    /// Execute automation rule actions
    async fn execute_actions(
        &self,
        tenant_id: TenantId,
        ticket_id: Uuid,
        rule: &AutomationRule,
    ) -> AppResult<()> {
        let actions: Vec<AutomationAction> =
            serde_json::from_value(rule.actions.clone()).unwrap_or_default();

        for action in actions {
            match action.action_type.as_str() {
                "set_status" => {
                    if let Some(status_id) = action.params.get("status_id").and_then(|v| v.as_str())
                    {
                        if let Ok(id) = Uuid::parse_str(status_id) {
                            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                            sqlx::query(
                                "UPDATE tickets SET status_id = $1, updated_at = NOW() WHERE id = $2",
                            )
                            .bind(id)
                            .bind(ticket_id)
                            .execute(&mut *tx)
                            .await?;
                            tx.commit().await?;
                        }
                    }
                }
                "set_priority" => {
                    if let Some(priority_id) =
                        action.params.get("priority_id").and_then(|v| v.as_str())
                    {
                        if let Ok(id) = Uuid::parse_str(priority_id) {
                            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                            sqlx::query(
                                "UPDATE tickets SET priority_id = $1, updated_at = NOW() WHERE id = $2",
                            )
                            .bind(id)
                            .bind(ticket_id)
                            .execute(&mut *tx)
                            .await?;
                            tx.commit().await?;
                        }
                    }
                }
                "assign_to" => {
                    if let Some(user_id) = action.params.get("user_id").and_then(|v| v.as_str()) {
                        if let Ok(id) = Uuid::parse_str(user_id) {
                            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                            sqlx::query(
                                "UPDATE tickets SET assigned_to_id = $1, updated_at = NOW() WHERE id = $2",
                            )
                            .bind(id)
                            .bind(ticket_id)
                            .execute(&mut *tx)
                            .await?;
                            tx.commit().await?;
                        }
                    }
                }
                "set_queue" => {
                    if let Some(queue_id) = action.params.get("queue_id").and_then(|v| v.as_str()) {
                        if let Ok(id) = Uuid::parse_str(queue_id) {
                            let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                            sqlx::query(
                                "UPDATE tickets SET queue_id = $1, updated_at = NOW() WHERE id = $2",
                            )
                            .bind(id)
                            .bind(ticket_id)
                            .execute(&mut *tx)
                            .await?;
                            tx.commit().await?;
                        }
                    }
                }
                "add_note" => {
                    if let Some(content) = action.params.get("content").and_then(|v| v.as_str()) {
                        let note_type = action
                            .params
                            .get("note_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("internal");
                        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
                        sqlx::query(
                            "INSERT INTO ticket_notes (id, tenant_id, ticket_id, note_type, content, created_by_id) VALUES ($1, $2, $3, $4, $5, $6)",
                        )
                        .bind(Uuid::new_v4())
                        .bind(tenant_id)
                        .bind(ticket_id)
                        .bind(note_type)
                        .bind(content)
                        .bind(Uuid::nil()) // System-generated
                        .execute(&mut *tx)
                        .await?;
                        tx.commit().await?;
                    }
                }
                "send_notification" => {
                    // Hand off to NotificationsService when wired so
                    // the message gets templated + retried + recorded
                    // in `notifications`. Fall back to a direct mailer
                    // send for legacy fixtures that build the engine
                    // without a dispatcher. `params.to` is still
                    // required either way.
                    let to = action.params.get("to").and_then(|v| v.as_str());
                    // PMS-789: the fallback subject names the deployment, so
                    // it is the configured name rather than a literal.
                    let default_subject =
                        format!("{} ticket update", crate::utils::app_name::app_name());
                    let subject = action
                        .params
                        .get("subject")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&default_subject);
                    let body = action
                        .params
                        .get("body")
                        .and_then(|v| v.as_str())
                        .unwrap_or("A ticket you watch has been updated.");
                    match to {
                        Some(addr) if !addr.is_empty() => match &self.notifications {
                            Some(notify) => {
                                let context = serde_json::json!({
                                    "recipient_email": addr,
                                    "subject": subject,
                                    "body": body,
                                    "ticket_id": ticket_id.to_string(),
                                });
                                if let Err(e) = notify
                                    .dispatch(tenant_id, "ticket.automation.notify", &context)
                                    .await
                                {
                                    tracing::warn!(
                                        ?e, %ticket_id, rule = %rule.name,
                                        "send_notification dispatch failed",
                                    );
                                }
                            }
                            None => {
                                if let Err(e) = self.mailer.send_text(addr, subject, body).await {
                                    tracing::warn!(
                                        ?e, %ticket_id, rule = %rule.name,
                                        "send_notification email failed (legacy mailer path)",
                                    );
                                }
                            }
                        },
                        _ => tracing::warn!(
                            %ticket_id, rule = %rule.name,
                            "send_notification action missing 'to' param",
                        ),
                    }
                }
                "webhook" => {
                    // Required: params.url. Optional: params.method
                    // (default POST), params.payload (default a small
                    // JSON envelope naming the ticket + rule). Failures
                    // log and continue; one bad webhook should not abort
                    // the rule chain.
                    let Some(url) = action.params.get("url").and_then(|v| v.as_str()) else {
                        tracing::warn!(
                            %ticket_id, rule_id = %rule.id, rule = %rule.name,
                            "webhook action missing 'url' param",
                        );
                        continue;
                    };
                    // Parsed here rather than handed to reqwest as a string:
                    // the guard screens a `Url`, and an unusable value is a
                    // named failure instead of a transport error later.
                    let target = match Url::parse(url) {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::warn!(
                                %ticket_id, rule_id = %rule.id, rule = %rule.name, error = %e,
                                "webhook action has an unusable 'url' param",
                            );
                            continue;
                        }
                    };
                    let method = action
                        .params
                        .get("method")
                        .and_then(|v| v.as_str())
                        .unwrap_or("POST")
                        .to_ascii_uppercase();
                    let payload = action.params.get("payload").cloned().unwrap_or_else(|| {
                        serde_json::json!({
                            "tenant_id": tenant_id.get(),
                            "ticket_id": ticket_id,
                            "rule_id": rule.id,
                            "rule_name": rule.name,
                        })
                    });

                    match send_guarded_webhook(
                        &self.http,
                        self.resolver.as_ref(),
                        private_target_allowlist(),
                        &target,
                        &method,
                        &payload,
                    )
                    .await
                    {
                        Ok(status) if status.is_success() => {
                            tracing::info!(
                                %ticket_id, rule_id = %rule.id, rule = %rule.name, status = %status,
                                "automation webhook delivered",
                            );
                        }
                        Ok(status) => tracing::warn!(
                            %ticket_id, rule_id = %rule.id, rule = %rule.name, status = %status,
                            "automation webhook returned non-2xx",
                        ),
                        // PMS-809: a refused target is a failed action naming
                        // the rule and the address, not a silent no-op.
                        Err(WebhookError::Refused(guard)) => tracing::warn!(
                            %ticket_id, rule_id = %rule.id, rule = %rule.name, blocked = %guard,
                            "automation webhook refused: target is not on the public internet",
                        ),
                        Err(e) => tracing::warn!(
                            %ticket_id, rule_id = %rule.id, rule = %rule.name, error = %e,
                            "automation webhook send failed",
                        ),
                    }
                }
                _ => {
                    tracing::warn!("Unknown automation action type: {}", action.action_type);
                }
            }
        }

        // Update rule stats
        let mut tx = self.db.begin_with_tenant(tenant_id).await?;
        sqlx::query(
            "UPDATE ticket_automation_rules SET last_run_at = NOW(), run_count = run_count + 1 WHERE id = $1",
        )
        .bind(rule.id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(())
    }
}

/// Send one webhook, screening the target before the first connect and again
/// for every redirect hop (PMS-809).
///
/// A free function, not a method: it needs no `Database`, so the refusal path is
/// unit testable without Postgres. The method is re-issued unchanged on a
/// redirect - a webhook receiver that wants a different verb should publish the
/// final URL.
async fn send_guarded_webhook(
    http: &reqwest::Client,
    resolver: &dyn HostResolver,
    allowlist: &PrivateTargetAllowlist,
    target: &Url,
    method: &str,
    payload: &serde_json::Value,
) -> Result<reqwest::StatusCode, WebhookError> {
    let mut url = target.clone();
    for _ in 0..=WEBHOOK_MAX_HOPS {
        // A tenant integration may legitimately listen on its own port, so the
        // port set is not pinned here; the resolved address is what is screened.
        guard_outbound_url(resolver, &url, None, allowlist).await?;

        let request = match method {
            "GET" => http.get(url.clone()),
            "PUT" => http.put(url.clone()).json(payload),
            "PATCH" => http.patch(url.clone()).json(payload),
            "DELETE" => http.delete(url.clone()),
            _ => http.post(url.clone()).json(payload),
        };
        let response = request
            .send()
            .await
            .map_err(|e| WebhookError::Transport(e.to_string()))?;
        let status = response.status();
        if !status.is_redirection() {
            return Ok(status);
        }
        let location = match response
            .headers()
            .get(reqwest::header::LOCATION)
            .map(|v| v.to_str())
        {
            Some(Ok(value)) => Some(value.to_string()),
            // A Location the transport cannot read as text is not silently a
            // "no redirect": say so, then let the chain end here.
            Some(Err(e)) => {
                tracing::warn!(url = %url, error = %e, "automation webhook got an unreadable Location header");
                None
            }
            None => None,
        };
        // A 3xx with no usable Location is where the chain ends; report the
        // redirect itself rather than inventing a failure.
        let Some(location) = location else {
            return Ok(status);
        };
        url = url
            .join(&location)
            .map_err(|e| WebhookError::Transport(format!("unusable redirect target: {e}")))?;
    }
    Err(WebhookError::TooManyRedirects(WEBHOOK_MAX_HOPS))
}

#[derive(sqlx::FromRow)]
struct AutomationRuleRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    is_active: bool,
    trigger_type: String,
    conditions: serde_json::Value,
    actions: serde_json::Value,
    priority: i32,
    last_run_at: Option<chrono::DateTime<chrono::Utc>>,
    run_count: i32,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<AutomationRuleRow> for AutomationRule {
    fn from(row: AutomationRuleRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            description: row.description,
            is_active: row.is_active,
            trigger_type: AutomationTrigger::from_str(&row.trigger_type)
                .unwrap_or(AutomationTrigger::OnCreate),
            conditions: row.conditions,
            actions: row.actions,
            priority: row.priority,
            last_run_at: row.last_run_at,
            run_count: row.run_count,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)] // `id` mirrors the ticket PK we already passed in; kept for FromRow symmetry with the SELECT.
struct TicketDataRow {
    id: Uuid,
    company_id: Uuid,
    assigned_to_id: Option<Uuid>,
    source: String,
    is_billable: bool,
    status_name: String,
    priority_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::net::IpAddr;

    /// Scripted DNS. Every answer is declared by the test, and each case below
    /// is refused by the guard BEFORE a connect, so no test opens a socket.
    struct FakeResolver(Vec<IpAddr>);

    #[async_trait]
    impl HostResolver for FakeResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
            Ok(self.0.clone())
        }
    }

    fn resolver(ip: &str) -> FakeResolver {
        FakeResolver(vec![ip.parse().expect("test IP parses")])
    }

    async fn send(
        resolver: &FakeResolver,
        allowlist: &PrivateTargetAllowlist,
        target: &str,
    ) -> Result<reqwest::StatusCode, WebhookError> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // Every case here is refused before the connect; the timeout is
            // belt-and-braces so a future edit cannot hang the suite.
            .timeout(Duration::from_secs(1))
            .build()
            .expect("client builds");
        send_guarded_webhook(
            &http,
            resolver,
            allowlist,
            &Url::parse(target).expect("test URL parses"),
            "POST",
            &serde_json::json!({}),
        )
        .await
    }

    #[tokio::test]
    async fn webhook_refuses_a_loopback_target() {
        let err = send(
            &resolver("127.0.0.1"),
            &PrivateTargetAllowlist::default(),
            "http://hook.internal/notify",
        )
        .await
        .expect_err("a loopback webhook target is refused");
        assert!(
            matches!(&err, WebhookError::Refused(UrlGuardError::Blocked(ip)) if ip.to_string() == "127.0.0.1"),
            "expected a refusal naming the address, got {err:?}"
        );
    }

    #[tokio::test]
    async fn webhook_refuses_an_rfc1918_target() {
        let err = send(
            &resolver("10.1.2.3"),
            &PrivateTargetAllowlist::default(),
            "http://hook.internal:9000/notify",
        )
        .await
        .expect_err("an RFC1918 webhook target is refused");
        assert!(
            matches!(&err, WebhookError::Refused(UrlGuardError::Blocked(ip)) if ip.to_string() == "10.1.2.3"),
            "expected a refusal naming the address, got {err:?}"
        );
    }

    #[tokio::test]
    async fn webhook_refuses_a_non_http_scheme() {
        let err = send(
            &resolver("93.184.216.34"),
            &PrivateTargetAllowlist::default(),
            "ftp://hooks.example.com/notify",
        )
        .await
        .expect_err("a non-http(s) webhook target is refused");
        assert!(
            matches!(&err, WebhookError::Refused(UrlGuardError::Scheme(s)) if s == "ftp"),
            "expected a scheme refusal, got {err:?}"
        );
    }

    /// The allowlist reaches this path too: the same private target the tests
    /// above refuse passes the screen once an operator names its network. The
    /// assertion stops at the guard rather than calling `send_guarded_webhook`,
    /// because a target that PASSES would then connect, and no test here opens a
    /// socket. `utils::net` covers the allow decision itself.
    #[tokio::test]
    async fn webhook_screen_honours_the_operator_allowlist() {
        let target = Url::parse("http://hook.internal:9000/notify").expect("test URL parses");
        let allowlist = PrivateTargetAllowlist::parse("10.0.0.0/8");
        assert_eq!(
            guard_outbound_url(&resolver("10.1.2.3"), &target, None, &allowlist).await,
            Ok(())
        );
    }
}
