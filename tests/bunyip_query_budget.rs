//! PMS-777: the per-request query budget of the Bunyip Resource-Server auth
//! path, pinned as a regression test.
//!
//! Every authenticated `/api/v1/*` call runs this path before any handler code,
//! so its cost is a throughput ceiling on a 20-connection pool, not a latency
//! footnote. It used to issue NINE statements over nine pool checkouts for an
//! already-provisioned caller: `users` twice, `tenant_invitations` once, the
//! three `ensure_default_config` provisioning probes, and the PMS-698 tenant
//! gate - with three of them wrapped in a `BEGIN` / `set_config` / `ROLLBACK`
//! transaction, for twenty round trips in all.
//!
//! The budget is now two statements: one `users` read (carrying the waiting
//! -invite flag) and the PMS-698 `tenants` status gate, which is
//! security-relevant and deliberately NOT cached.
//!
//! The count comes from a `tracing` subscriber that records `sqlx::query`
//! events, which is the in-process equivalent of Postgres `log_statement=all`
//! (and sees the `BEGIN` / `set_config` / `ROLLBACK` traffic too, so a
//! transaction sneaking back in fails the test). This file holds exactly ONE
//! test on purpose: the subscriber is process-global, so a second test running
//! concurrently would count its statements as well.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use uuid::Uuid;

use mokosh_server::modules::auth::middleware::{
    place_bunyip_user, place_bunyip_user_from_local_state, LocalPlacement,
};
use mokosh_server::modules::auth::oidc_rs::AtClaims;
use mokosh_server::modules::auth::AuthService;
use mokosh_server::modules::invitations::InvitationsService;
use mokosh_server::modules::tenants::TenantService;
use mokosh_server::Database;

/// Statements observed while [`Recorder::armed`] is set.
#[derive(Default)]
struct Recorder {
    armed: AtomicBool,
    statements: Mutex<Vec<String>>,
}

impl Recorder {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.statements.lock().expect("statement log"))
    }
}

/// Pulls the SQL text off an `sqlx::query` event. sqlx records the full text as
/// `db.statement` and a one-line version as `summary`; either identifies the
/// statement, so prefer the full text and fall back to the summary.
#[derive(Default)]
struct SqlVisitor {
    statement: Option<String>,
    summary: Option<String>,
}

impl Visit for SqlVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "db.statement" => self.statement = Some(format!("{value:?}")),
            "summary" => self.summary = Some(format!("{value:?}")),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "db.statement" => self.statement = Some(value.to_string()),
            "summary" => self.summary = Some(value.to_string()),
            _ => {}
        }
    }
}

struct RecordingLayer(Arc<Recorder>);

impl<S: tracing::Subscriber> Layer<S> for RecordingLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "sqlx::query" || !self.0.armed.load(Ordering::SeqCst) {
            return;
        }
        let mut visitor = SqlVisitor::default();
        event.record(&mut visitor);
        let sql = visitor
            .statement
            .or(visitor.summary)
            .unwrap_or_else(|| "<no sql field>".to_string());
        self.0
            .statements
            .lock()
            .expect("statement log")
            .push(sql.split_whitespace().collect::<Vec<_>>().join(" "));
    }
}

fn services(
    pool: &PgPool,
) -> (
    Arc<AuthService>,
    Arc<TenantService>,
    Arc<InvitationsService>,
) {
    let db = Database::from_pool(pool.clone());
    (
        Arc::new(AuthService::new(db.clone(), "test-secret".into(), vec![])),
        Arc::new(TenantService::new(db.clone())),
        Arc::new(InvitationsService::new(db)),
    )
}

fn claims(sub: Uuid) -> AtClaims {
    AtClaims {
        iss: "https://bunyip.test".into(),
        sub: sub.to_string(),
        aud: "https://api.mokosh.test".into(),
        client_id: "mokosh".into(),
        scope: "openid".into(),
        exp: 0,
        iat: 0,
        // What the SPA's token actually carries; the role reconcile is then a
        // no-op for an already-admin user, so it writes nothing.
        bunyip_role: Some("subscriber".to_string()),
    }
}

/// How many statements one authenticated request may cost before the handler
/// runs. Raising this number is a throughput regression, not a test failure to
/// paper over: see the module docs for what each statement is.
const QUERY_BUDGET: usize = 2;

#[sqlx::test]
async fn an_authenticated_bunyip_request_costs_two_statements(pool: PgPool) {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(RecordingLayer(recorder.clone())),
    )
    .expect("install the recording subscriber");

    let (auth, tenants, invitations) = services(&pool);
    let sub = Uuid::new_v4();

    // First sight: the full JIT path, with userinfo-supplied email and name.
    place_bunyip_user(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        Some("budget@example.com".to_string()),
        true,
        Some("Budget".to_string()),
        Some("Tester".to_string()),
        &claims(sub),
    )
    .await
    .expect("first placement");

    // One warm request, so the `ensure_default_config` memo is populated
    // exactly as it is in a running server after the tenant's first request.
    match place_bunyip_user_from_local_state(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        &claims(sub),
    )
    .await
    {
        LocalPlacement::Placed(state) => {
            state.expect("warm-up request authenticates from local state")
        }
        LocalPlacement::UserinfoNeeded => panic!("an already-placed user must not need userinfo"),
    };

    // The measured request.
    recorder.armed.store(true, Ordering::SeqCst);
    let placed = match place_bunyip_user_from_local_state(
        &auth,
        Some(&tenants),
        Some(&invitations),
        sub,
        &claims(sub),
    )
    .await
    {
        LocalPlacement::Placed(state) => state,
        LocalPlacement::UserinfoNeeded => panic!("an already-placed user must not need userinfo"),
    };
    recorder.armed.store(false, Ordering::SeqCst);

    assert!(
        placed.is_some(),
        "the measured request must still authenticate"
    );

    let statements = recorder.take();
    assert_eq!(
        statements.len(),
        QUERY_BUDGET,
        "one authenticated request must cost {QUERY_BUDGET} statements, got: {statements:#?}"
    );

    // AC: `users` is read exactly once, `tenant_invitations` at most once, and
    // the surviving statements are the two named in the module docs.
    let users_reads = statements
        .iter()
        .filter(|s| s.contains("FROM users"))
        .count();
    assert_eq!(users_reads, 1, "`users` is read once: {statements:#?}");
    let invite_reads = statements
        .iter()
        .filter(|s| s.contains("tenant_invitations"))
        .count();
    assert!(
        invite_reads <= 1,
        "`tenant_invitations` is read at most once: {statements:#?}"
    );
    assert!(
        statements
            .iter()
            .any(|s| s.contains("SELECT status FROM tenants")),
        "the PMS-698 principal gate still runs on every request: {statements:#?}"
    );

    // No transaction: the pre-PMS-777 path wrapped three of its reads in
    // `begin_with_tenant`, paying `BEGIN` + `set_config` + `ROLLBACK` round
    // trips to run one SELECT.
    for noise in ["BEGIN", "set_config", "ROLLBACK", "COMMIT"] {
        assert!(
            !statements.iter().any(|s| s.contains(noise)),
            "the request path must issue no `{noise}`: {statements:#?}"
        );
    }

    // And none of the `ensure_default_config` provisioning probes.
    for probe in [
        "ticket_sequences",
        "ticket_statuses",
        "own_company_id IS NOT NULL",
    ] {
        assert!(
            !statements.iter().any(|s| s.contains(probe)),
            "a seeded tenant must not be re-probed for `{probe}`: {statements:#?}"
        );
    }
}
