//! API router configuration

use axum::{
    http::{header, HeaderValue, Method, StatusCode},
    middleware,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};

use crate::db::Database;
use crate::modules::approvals::{approval_routes, ApprovalsService};
use crate::modules::assets::{assets_routes, AssetsService};
use crate::modules::audit::{audit_routes, AuditService};
use crate::modules::auth::{
    auth_routes, bunyip_webhook::BunyipWebhookState, AuthMiddleware, AuthService,
};
use crate::modules::billing::{billing_routes, BillingService};
use crate::modules::calendar::{calendar_routes, dispatch_routes, CalendarService};
use crate::modules::contacts::{contact_routes, ContactService};
use crate::modules::contracts::{contracts_routes, ContractsService};
use crate::modules::dashboards::{dashboard_routes, DashboardsService};
use crate::modules::email_intake::{email_intake_routes, EmailIntakeService};
use crate::modules::invitations::{invitations_routes, InvitationsService};
use crate::modules::knowledge_base::{kb_routes, KbService};
use crate::modules::mileage_tracking::{mileage_tracking_routes, MileageTrackingService};
use crate::modules::notifications::{notifications_routes, NotificationsService};
use crate::modules::portal::{portal_routes, PortalAuthService};
use crate::modules::projects::{projects_routes, ProjectsService};
use crate::modules::quotes::{quotes_routes, QuotesService};
use crate::modules::reports::{reports_routes, ReportsService};
use crate::modules::rmm::{rmm_routes, RmmService};
use crate::modules::saved_reports::{saved_reports_routes, SavedReportsService};
use crate::modules::search::{search_routes, SearchService};
use crate::modules::settings::{settings_routes, SettingsService};
use crate::modules::sla::{sla_routes, SlaService};
#[cfg(feature = "multi-tenant")]
use crate::modules::tenants::{tenant_routes, TenantService};
use crate::modules::ticket_templates::{ticket_template_routes, TicketTemplatesService};
use crate::modules::tickets::{
    agent_attachment_routes, contact_notes_routes, portal_attachment_routes, ticket_routes,
    AttachmentConfig, AttachmentService, TicketService,
};
use crate::modules::time_tracking::{time_tracking_routes, TimeTrackingService};
use crate::modules::workflows::{workflow_routes, WorkflowsService};
use crate::version::VersionInfo;
use crate::version_check::version_check;

/// Create the main API router with all routes.
///
/// PSA endpoints authenticate via the bunyip-as-OP Resource-Server path
/// (`bunyip_verifier`, when `Some`) and the legacy HS256 cookie path.
#[allow(clippy::too_many_arguments)]
pub fn create_api_router(
    db: Database,
    jwt_secret: String,
    google_oauth: Arc<google_oauth_flow::Client>,
    client_origin: String,
    cors_origins: Vec<String>,
    super_admin_emails: Vec<String>,
    cookie_secure: bool,
    bunyip_verifier: Option<crate::modules::auth::oidc_rs::Verifier>,
    // PMS-638: the live, swappable mailer handle. Upcast to `Arc<dyn Mailer>`
    // for the services below; the concrete handle is threaded into
    // `settings_routes` so the admin email-settings endpoint can hot-swap it.
    shared_mailer: Arc<crate::utils::email::SharedMailer>,
    // 32-byte AES-256-GCM key. Used for at-rest encryption of any
    // per-tenant secret material (today: payment-gateway configs).
    encryption_key: [u8; 32],
    // PMS-591: shared secret for the BUNYIP-211 `account_deleted` webhook.
    // Verified as `hex(hmac_sha256(body, secret))` against the
    // `X-Webhook-Signature` header on `/api/v1/bunyip/webhooks/account-deleted`.
    bunyip_webhook_secret: Vec<u8>,
    // PMS-657: IP -> country resolver for login-location alerts, built from
    // IP2LOCATION_DB_PATH in main.rs. `None` disables the feature.
    geoip: Option<Arc<crate::utils::geoip::GeoIpService>>,
    // PMS-658: master switch for the suspicious-login notify-and-approve gate,
    // from LOGIN_APPROVAL_ENABLED in main.rs. Off by default (can block logins).
    login_approval_enabled: bool,
) -> Router {
    let cors_origin_values: Vec<HeaderValue> = cors_origins
        .iter()
        .map(|o| {
            o.parse::<HeaderValue>().unwrap_or_else(|e| {
                panic!("CORS_ORIGIN entry {o:?} is not a valid header value: {e}")
            })
        })
        .collect();
    let mailer: Arc<dyn crate::utils::email::Mailer> = shared_mailer.clone();

    // Create services. NotificationsService is constructed first so a
    // shared clone can be threaded into AuthService and TicketService,
    // letting them dispatch transactional messages (password reset,
    // welcome, ticket-note email) through the notifications queue
    // instead of calling the Mailer directly. The dispatcher worker
    // spawned from main.rs drains those rows.
    let notifications_service =
        NotificationsService::with_encryption_key(db.clone(), encryption_key);
    let auth_service = AuthService::with_dispatcher(
        db.clone(),
        jwt_secret.clone(),
        super_admin_emails,
        mailer.clone(),
        client_origin.clone(),
        notifications_service.clone(),
    )
    .with_geoip(geoip)
    .with_login_approval(login_approval_enabled);
    #[cfg(feature = "multi-tenant")]
    let tenant_service = TenantService::new(db.clone());
    // PMS-136: ContactService emails a `/portal/set-password` setup link when
    // an agent grants portal access, so it holds the shared mailer + the SPA
    // origin (the link base). `mailer` is cloned here because TicketService
    // also takes it below.
    let contact_service =
        ContactService::with_mailer(db.clone(), mailer.clone(), client_origin.clone());
    let ticket_service =
        TicketService::with_dispatcher(db.clone(), mailer.clone(), notifications_service.clone());
    // PMS-157: first-visit demo seeding. Holds its own clones of the
    // contacts + tickets services so it can drive the real create paths;
    // wired below as a middleware that runs after auth populates AuthState.
    let seed_service = Arc::new(crate::modules::seed::SeedService::new(
        db.clone(),
        contact_service.clone(),
        ticket_service.clone(),
    ));
    let billing_service = BillingService::with_encryption_key(db.clone(), encryption_key);
    let time_tracking_service = TimeTrackingService::new(db.clone());
    let mileage_tracking_service = MileageTrackingService::new(db.clone());
    let projects_service = ProjectsService::new(db.clone());
    // Wired with the notifications dispatcher so the appointment-reminder
    // worker (registered in main.rs) fans out `appointment.reminder`
    // events through the queue. The CRUD calendar/dispatch routes ignore
    // the handle.
    let calendar_service =
        CalendarService::with_dispatcher(db.clone(), notifications_service.clone());
    let contracts_service = ContractsService::new(db.clone());
    // PMS-673: quotes mail the client their sign-off link and notify the
    // owner when the client decides, so the service carries the mailer,
    // the dispatcher, and the portal origin those links are built from.
    let quotes_service = QuotesService::with_delivery(
        db.clone(),
        mailer.clone(),
        notifications_service.clone(),
        client_origin.clone(),
    );
    let assets_service = AssetsService::with_encryption_key(db.clone(), encryption_key);
    let kb_service = KbService::new(db.clone());
    // PMS-246: the SPA origin is the invite accept-link base (login-driven
    // acceptance), so created invites email the invitee.
    let invitations_service =
        Arc::new(InvitationsService::new(db.clone()).with_app_url(client_origin.clone()));
    let reports_service = ReportsService::new(db.clone());
    // PMS-457: saved-report definitions (Phase 1).
    let saved_reports_service = SavedReportsService::new(db.pool().clone());
    // PMS-448: ticket.created workflow rule executor + CRUD.
    let workflows_service = WorkflowsService::new(db.pool().clone());
    // PMS-448 AC4: admin-authored ticket templates (new-ticket pre-fills).
    let ticket_templates_service = TicketTemplatesService::new(db.pool().clone());
    // MAPPS-298: cross-entity tenant-scoped search.
    let search_service = SearchService::new(db.pool().clone());
    // PMS-453: per-user saved dashboards.
    let dashboards_service = DashboardsService::new(db.pool().clone());
    // PMS-450: email-to-ticket intake. Holds a TicketService clone so
    // the intake handler can reuse the full ticket-create flow
    // (audit + SLA assignment + ticket-number generation) without
    // duplicating the INSERT.
    // PMS-450 AC3: the intake service stores inbound attachments via the
    // shared `ticket_attachments` blob path, so it holds its own
    // `AttachmentService` (same env-driven dir + size cap as the agent /
    // portal upload routes).
    let email_intake_service = EmailIntakeService::new(
        db.pool().clone(),
        ticket_service.clone(),
        AttachmentService::new(db.pool().clone(), AttachmentConfig::from_env()),
    );
    // PMS-451: per-ticket approval requests.
    let approvals_service = ApprovalsService::new(db.pool().clone());
    let rmm_service =
        RmmService::with_dependencies(db.clone(), encryption_key, ticket_service.clone());
    // SLA service shares the notifications dispatcher so the
    // `sla_sweep` worker (spawned from main.rs with this same service)
    // can enqueue at-risk / breach alerts. The CRUD + evaluate routes
    // do not use the dispatcher; only the worker does.
    let sla_service = SlaService::with_dispatcher(db.clone(), notifications_service.clone());
    // PMS-113 AC2: Arc'd so both `settings_routes` and `tenant_routes`
    // share the same instance. The tenants-side module-config handlers
    // delegate to this; one canonical writer for `module_config`.
    let settings_service = Arc::new(SettingsService::new(db.clone()));
    let audit_service = AuditService::new(db.clone());

    // Create auth middleware. The bunyip Resource-Server verifier (when
    // present) is attached so the middleware can authenticate bunyip-minted
    // bearer tokens alongside legacy HS256 cookies.
    let mut auth_middleware = AuthMiddleware::new(auth_service.clone());
    if let Some(v) = bunyip_verifier {
        auth_middleware = auth_middleware.with_bunyip(v);
        // PMS-244: the bunyip path resolves the user's tenant from Mokosh's own
        // membership - a pending invite, else existing placement, else a
        // provisioned personal tenant. Its own cheap pool-backed tenant handle
        // (the router's `tenant_service` is moved into `tenant_routes`); the
        // invitations Arc is shared with `invitations_routes`.
        auth_middleware = auth_middleware
            .with_tenants(std::sync::Arc::new(TenantService::new(db.clone())))
            .with_invitations(invitations_service.clone());
    }

    // Build API v1 routes
    let api_v1 = Router::new()
        // Liveness probe: cheap, never touches downstream deps. Used by
        // orchestrators to decide whether to restart the container.
        .route("/health", get(health_check))
        // Readiness probe (PMS-130): also pings the DB, and best-effort
        // pings Infisical when `INFISICAL_BASE_URL` is set. Returns 503
        // with a JSON breakdown when a dependency is down so the
        // orchestrator drains traffic until the probe goes green.
        .route(
            "/ready",
            get({
                let db = db.clone();
                move || ready_check(db.clone())
            }),
        )
        // Build / version info (public, used for diagnostics)
        .route("/version", get(version_info))
        // Self-hosted update check (PMS-238). Opt-in via
        // `MOKOSH_UPDATE_CHECK_URL`; compares the running build against the
        // latest published release and reports whether an upgrade is
        // available. Disabled (no outbound request) when the env var is unset.
        .route("/version/check", get(version_check))
        // Auth routes
        .nest(
            "/auth",
            auth_routes(
                auth_service,
                google_oauth,
                client_origin.clone(),
                jwt_secret.clone(),
                cookie_secure,
            ),
        )
        // Tenant management. Only mounted in multi-tenant builds: in a
        // single-tenant deployment there is exactly one tenant and the
        // CRUD endpoints would be a foot-gun. PMS-24.
        ;
    #[cfg(feature = "multi-tenant")]
    let api_v1 = api_v1.nest(
        "/tenants",
        tenant_routes(tenant_service, settings_service.clone()),
    );
    let api_v1 = api_v1
        // Contact management. The canonical company endpoints live
        // under `/api/v1/contacts/companies/...` (one router for
        // companies + contacts + sites); a previous `nest("/companies",
        // Router::new())` here was dead - it matched nothing, so
        // `/api/v1/companies` returned a misleading 404 with no
        // explanation. Removed and documented (PMS-20).
        .nest("/contacts", contact_routes(contact_service.clone()))
        // Ticketing
        .nest("/tickets", ticket_routes(ticket_service.clone()))
        // PMS-483: ticket-note attachment upload / download / delete.
        // Merged at the top level so its `/tickets/{id}/notes/...`
        // path nests cleanly under the existing ticket tree.
        .merge(agent_attachment_routes(AttachmentService::new(
            db.pool().clone(),
            AttachmentConfig::from_env(),
        )))
        // PMS-468: agent "all comments from this contact" feed. The
        // route lives on the tickets module (TicketService owns the
        // notes surface) but mounts at the top level so its path
        // matches the SPA's `/contacts/{id}/notes` URL.
        .merge(contact_notes_routes(ticket_service))
        // Time tracking: time-entries, timesheets, timers, rounding,
        // work-types. PMS-43.
        .merge(time_tracking_routes(time_tracking_service))
        // Mileage tracking: mileage-entries CRUD (Log Time "Mileage" mode).
        // Gated by the time-tracking module. PMS-315.
        .merge(mileage_tracking_routes(mileage_tracking_service))
        // Projects: projects + phases + task statuses + tasks +
        // dependencies. PMS-52.
        .merge(projects_routes(projects_service))
        // Calendar / scheduling: events, appointments, availability,
        // time-off, on-call. PMS-59. Mounted via merge so the routes
        // appear at their natural top-level paths.
        .merge(calendar_routes(calendar_service.clone()))
        // Dispatch view (technician scheduling board). PMS-58: the
        // calendar story owns this aggregating endpoint that combines
        // appointments (recurring series expanded), availability, time
        // off, and on-call coverage for a date range. Backed by the
        // same CalendarService as the calendar routes.
        .nest("/dispatch", dispatch_routes(calendar_service))
        // Contracts: contracts + items + hour balances + rate cards. PMS-65.
        .merge(contracts_routes(contracts_service))
        // SLA: policies, targets, business hours, holidays, evaluator. PMS-107.
        .merge(sla_routes(sla_service))
        // Billing: invoices + payments + payment-gateways + tax-rates.
        // `billing_routes` defines the full paths so the URL structure
        // stays flat. PMS-34.
        .merge(billing_routes(billing_service))
        // Quotes: the sales document that precedes a Project, plus its
        // line items. Shares the billing module gate + finance role with
        // invoices. PMS-672.
        .merge(quotes_routes(quotes_service))
        // Assets / CMDB: types, assets, relationships, config items,
        // credential vault, audit log. PMS-72.
        .merge(assets_routes(assets_service))
        // Knowledge base: categories + articles + versions + portal feed. PMS-80.
        .merge(kb_routes(kb_service))
        // Org membership invitations (PMS-244): admin-only, tenant-scoped.
        .merge(invitations_routes(invitations_service))
        // Notifications: channels + templates + prefs + inbox + rules
        // + dispatcher. PMS-86.
        .merge(notifications_routes(notifications_service.clone()))
        // RMM: connections, device mappings, alert rules, alert ingest. PMS-101.
        .merge(rmm_routes(rmm_service))
        // Reports: dashboard, tickets, time, billing, CSV export. PMS-94.
        .merge(reports_routes(reports_service))
        // PMS-457: saved custom-report definitions (Phase 1; the
        // execution runtime ships separately as Phase 2).
        .merge(saved_reports_routes(saved_reports_service))
        // PMS-448: workflow-rule CRUD + per-ticket run timeline.
        .merge(workflow_routes(workflows_service))
        // PMS-448 AC4: ticket-template CRUD (new-ticket pre-fills).
        .merge(ticket_template_routes(ticket_templates_service))
        // MAPPS-298: cross-entity tenant-scoped global search.
        .merge(search_routes(search_service))
        // PMS-453: per-user saved dashboards (Phase 1; scheduled
        // report delivery follows under the same ticket).
        .merge(dashboard_routes(dashboards_service))
        // PMS-450: email-to-ticket intake. Authenticates via a
        // tenant-scoped bearer (`tenant_intake_tokens`), NOT the
        // user-auth middleware, so the gateway has no `users` row
        // to attribute the request to. The route handler extracts
        // the bearer directly from the request headers.
        .merge(email_intake_routes(email_intake_service))
        // PMS-451: ticket approvals (per-ticket list + create, caller's
        // pending queue, decide, cancel).
        .merge(approval_routes(approvals_service))
        // Settings: tenant settings + module configs. PMS-114.
        .merge(settings_routes(
            settings_service.clone(),
            db.clone(),
            encryption_key,
            shared_mailer.clone(),
        ))
        // Audit log read. PMS-118.
        .merge(audit_routes(audit_service))
        // PMS-647: admin-only tenant data export (first slice of PMS-646).
        // PMS-679: also the "Load demo data" endpoint, sharing the same
        // `seed_service` Arc as the first-visit seed middleware below.
        .merge(crate::modules::data_transfer::data_transfer_routes(
            db.clone(),
            seed_service.clone(),
        ))
        // PMS-275: the coarse per-request audit middleware (PMS-119) was
        // removed. It ran post-response with only the HTTP method + URL, so it
        // could never populate `entity_id` or the old/new value payload, and
        // because this router is nested under `/api/v1` the path it saw was
        // already prefix-stripped, leaving every row tagged entity_type
        // "unknown". The in-transaction `audit_write` path (PMS-117) is the
        // sole audit writer and records the entity type, record id, and
        // before/after snapshots that the audit trail needs.
        // First-visit demo seeding (PMS-157). Added before the auth layer
        // so it runs *inner* of it: auth populates AuthState, then this
        // reads the resolved tenant/user and seeds a new account's demo
        // data once (detached, best-effort). No-op for already-seen tenants.
        .layer(middleware::from_fn_with_state(
            crate::modules::seed::SeedMiddlewareState {
                service: seed_service,
            },
            crate::modules::seed::seed_middleware,
        ))
        // Apply auth middleware
        .layer(middleware::from_fn_with_state(
            auth_middleware.clone(),
            crate::modules::auth::middleware::auth_middleware,
        ))
        // PMS-113 AC3: make SettingsService reachable from
        // `RequireModuleEnabled` extractors via the request's
        // extensions. The extractor reads
        // `parts.extensions.get::<Arc<SettingsService>>()` and short-
        // circuits with 404 when the gated module is disabled.
        .layer(axum::Extension(settings_service))
        // PMS-298: outermost layer so every 4xx (including extractor
        // rejections such as a JSON body that fails to deserialize) is
        // returned as the standard `{error:{code,message}}` envelope instead
        // of raw axum/serde plaintext. JSON responses (every `AppError`) pass
        // through untouched.
        .layer(middleware::from_fn(
            crate::utils::error::normalize_error_envelope,
        ));

    // Build portal API routes. Portal identity is the contacts row,
    // so this surface runs its own auth middleware (mounted inside
    // `portal_routes`) and never sees `AuthMiddleware` / `AuthState`.
    let portal_service = PortalAuthService::new(db.clone(), jwt_secret.clone());
    // PMS-483: `portal_attachment_routes` needs its own clone of the
    // service so it can build the same `portal_auth_middleware` layer
    // independently (the layer is per-Router in axum, not inherited
    // from the merged-into parent).
    let portal_attachment_auth_service = PortalAuthService::new(db.clone(), jwt_secret.clone());
    let portal_ticket_service = TicketService::new(db.clone());
    let portal_kb_service = KbService::new(db.clone());
    let portal_billing_service = BillingService::with_encryption_key(db.clone(), encryption_key);
    let portal_quotes_service = QuotesService::with_delivery(
        db.clone(),
        shared_mailer.clone(),
        notifications_service.clone(),
        client_origin.clone(),
    );
    let portal_api = Router::new()
        .route("/health", get(health_check))
        .merge(portal_routes(
            portal_service,
            portal_ticket_service,
            portal_kb_service,
            portal_billing_service,
            portal_quotes_service,
        ))
        // PMS-483: portal-side ticket-note attachments. Same routes as
        // the agent surface, but behind `RequirePortalAuth` and
        // company-scoped via the contact's authenticated `company_id`.
        // The portal auth middleware is layered inside this builder
        // because `.merge` does NOT inherit the parent router's layers
        // - without that, every portal upload would 401 before the
        // handler.
        .merge(portal_attachment_routes(
            AttachmentService::new(db.pool().clone(), AttachmentConfig::from_env()),
            portal_attachment_auth_service,
        ))
        // PMS-298: same envelope normalization for the portal surface.
        .layer(middleware::from_fn(
            crate::utils::error::normalize_error_envelope,
        ));

    // CORS: SPA at msp.<tld> talks to api.msp.<tld> from a different origin,
    // so credentialed CORS must be tight (specific origins, not wildcard).
    // The list comes from the CORS_ORIGIN env var (comma-separated). The
    // bunyip apex is included so the SaaS shell can call mokosh endpoints
    // in the future without losing credentials.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(cors_origin_values))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
        .allow_credentials(true)
        // Cache preflight for 10 minutes per docs/cors.md §5 so browsers do not
        // re-issue an OPTIONS before every credentialed request (PMS-389).
        .max_age(std::time::Duration::from_secs(600));

    // PMS-591: Bunyip account-deleted webhook. Nested under `/api/v1/bunyip`
    // OUTSIDE the JWT auth chain: this endpoint authenticates itself via a
    // per-app HMAC-SHA256 signature (`X-Webhook-Signature`), and every
    // request from Bunyip's dispatcher lacks a mokosh session cookie by
    // design. The receiver soft-deletes the mirrored user row keyed by
    // `users.id = <bunyip sub>` (mokosh's users.id IS the bunyip sub per
    // the PMS-295 cutover, so no `bunyip_sub` column is needed).
    let bunyip_webhook_state = Arc::new(BunyipWebhookState {
        pool: db.pool().clone(),
        webhook_secret: bunyip_webhook_secret,
    });
    let bunyip_webhooks = Router::new()
        .route(
            "/webhooks/account-deleted",
            post(crate::modules::auth::bunyip_webhook::account_deleted),
        )
        .with_state(bunyip_webhook_state)
        // PMS-298: shared JSON error envelope so a bad request here matches
        // the rest of the API surface.
        .layer(middleware::from_fn(
            crate::utils::error::normalize_error_envelope,
        ));

    // Combine everything. The `.fallback` swallows any non-/api/v1/* request
    // (including hitting `/` directly in a browser) with a small placeholder
    // page that links the user back to the Mokosh frontend. This keeps
    // api.msp.<tld> from leaking internal route info.
    Router::new()
        .nest("/api/v1", api_v1)
        .nest("/api/v1/portal", portal_api)
        .nest("/api/v1/bunyip", bunyip_webhooks)
        .fallback(get(move |headers| {
            not_a_frontend(headers, client_origin.clone())
        }))
        // Apply global middleware
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(cors)
        // PMS-388: security response headers (HSTS, nosniff, frame-deny,
        // Referrer-Policy, Permissions-Policy, CSP) on every response -
        // the API, the portal API, and the `not_a_frontend` fallback. App-level
        // parity with bunyip-api's `SecurityHeaders`, per the 2026-06-17 standup
        // decision to keep this out of the shared Traefik layer.
        .layer(middleware::from_fn(
            crate::utils::security_headers::security_headers,
        ))
}

/// Fallback handler for any path outside `/api/v1/*`. Renders a small
/// "this is an API endpoint" page so direct browser visits to
/// `api.msp.<tld>` are friendly instead of leaking 404 internals. The
/// link points at the Bunyip SaaS shell on the matching apex; if the
/// host can't be parsed, falls back to `fallback_origin` (the env-injected
/// `CLIENT_ORIGIN`). No domain is ever hardcoded here.
async fn not_a_frontend(
    headers: axum::http::HeaderMap,
    fallback_origin: String,
) -> impl IntoResponse {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let hub_link = host
        .strip_prefix("api.msp.")
        .map(|tld| format!("https://{tld}"))
        .unwrap_or(fallback_origin);
    let body = format!(
        "<!doctype html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"utf-8\">\n\
         <title>Not a frontend</title>\n\
         <meta name=\"robots\" content=\"noindex\">\n\
         <style>body{{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#1a1a1a}}a{{color:#0066cc}}</style>\n\
         </head>\n\
         <body>\n\
         <h1>This is an API endpoint.</h1>\n\
         <p>You're looking at the Mokosh backend API. There is no user interface here.</p>\n\
         <p>Visit <a href=\"{hub_link}\">{hub_link}</a> to reach the application.</p>\n\
         </body>\n\
         </html>\n"
    );
    (StatusCode::NOT_FOUND, Html(body))
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Readiness probe (PMS-130). Pings every external dependency the
/// running server actually talks to:
///
/// - **Database** (always): `SELECT 1` against the pool. The legacy
///   `health_check()` returns `"OK"` unconditionally; this is the
///   first probe that distinguishes a process that booted from one
///   that can actually serve a request.
/// - **Infisical** (best-effort): if the operator set
///   `INFISICAL_BASE_URL` at process start, a 1-second HTTP probe
///   against `<base>/api/status`. Mokosh-server loads Infisical
///   secrets at boot only, so a transient Infisical outage does
///   not break in-flight requests; the probe still surfaces the
///   outage because the next process restart would fail. Skipped
///   when the env var was unset at boot (single-machine deployments
///   without an Infisical sibling). The 1s timeout matches the
///   Kubernetes `timeoutSeconds` default so the orchestrator gets
///   our error body instead of timing out the whole probe.
///
/// Response shape on 200:
/// ```json
/// {"status":"ready","checks":{"db":"ok","infisical":"ok"|"skipped"}}
/// ```
///
/// On 503 the same shape is returned with the failing dependency's
/// value replaced by a short error string so the orchestrator log
/// shows the root cause without a separate metrics scrape. The
/// response sets `Cache-Control: no-store` so an intermediate
/// proxy / CDN does not pin the failing state past the next probe.
async fn ready_check(
    db: crate::db::Database,
) -> (
    StatusCode,
    [(axum::http::HeaderName, &'static str); 2],
    String,
) {
    let db_result = db.health_check().await;
    let infisical_result = probe_infisical().await;

    let db_value = match &db_result {
        Ok(()) => serde_json::Value::String("ok".into()),
        Err(e) => serde_json::Value::String(format!("error: {e}")),
    };
    let infisical_value = match &infisical_result {
        Ok(true) => serde_json::Value::String("ok".into()),
        Ok(false) => serde_json::Value::String("skipped".into()),
        Err(e) => serde_json::Value::String(format!("error: {e}")),
    };

    let any_failed = db_result.is_err() || infisical_result.is_err();
    let status_label = if any_failed { "not_ready" } else { "ready" };
    let status_code = if any_failed {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };

    let body = serde_json::json!({
        "status": status_label,
        "checks": {
            "db": db_value,
            "infisical": infisical_value,
        },
    });
    (
        status_code,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
}

/// Captured-at-boot Infisical probe state. The handler used to read
/// `INFISICAL_BASE_URL` and build a fresh `reqwest::Client` on every
/// request, which leaked file descriptors and re-resolved DNS under
/// repeated orchestrator polling. Cache the parsed config + the HTTP
/// client in a `OnceLock` so subsequent probes reuse the connection
/// pool. The lock is initialised on the first /ready request, not at
/// `create_api_router` time, because the env var is process-global
/// and reading it lazily keeps the router signature unchanged.
struct InfisicalProbe {
    /// `<base>/api/status` URL with trailing-slash stripped from
    /// `<base>`. Pre-built so the probe path is a const lookup.
    url: String,
    /// Sanitised display form of `<base>` (scheme + host[:port] only,
    /// no userinfo or query string) used inside error strings so the
    /// response body and access log do not echo credentials the
    /// operator may have embedded in `INFISICAL_BASE_URL`.
    display: String,
    client: reqwest::Client,
}

static INFISICAL_PROBE: std::sync::OnceLock<Option<InfisicalProbe>> = std::sync::OnceLock::new();

fn infisical_probe() -> Option<&'static InfisicalProbe> {
    INFISICAL_PROBE
        .get_or_init(|| {
            let base = std::env::var("INFISICAL_BASE_URL").ok()?;
            let trimmed = base.trim_end_matches('/').to_string();
            // Best-effort credential scrub for error strings. If
            // `INFISICAL_BASE_URL` does not parse as a URL, fall back
            // to the literal trimmed string (no leak path exists for
            // a value that does not parse anyway, but stay defensive).
            let display = match url::Url::parse(&trimmed) {
                Ok(mut u) => {
                    let _ = u.set_username("");
                    let _ = u.set_password(None);
                    u.set_query(None);
                    u.set_fragment(None);
                    u.to_string().trim_end_matches('/').to_string()
                }
                Err(_) => trimmed.clone(),
            };
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(1))
                .build()
                .ok()?;
            Some(InfisicalProbe {
                url: format!("{trimmed}/api/status"),
                display,
                client,
            })
        })
        .as_ref()
}

/// Probe Infisical's `/api/status` endpoint when the operator opted
/// in via `INFISICAL_BASE_URL`. Returns:
///
/// - `Ok(true)` - probe ran and got a 2xx response
/// - `Ok(false)` - probe skipped (env var unset)
/// - `Err(_)` - env var set, but the probe failed (DNS, TCP, non-2xx
///   response, or 1s timeout). Error messages reference only the
///   sanitised display URL so credentials in the env var stay out
///   of the response body / access log.
async fn probe_infisical() -> Result<bool, String> {
    let Some(probe) = infisical_probe() else {
        return Ok(false);
    };
    let resp = probe
        .client
        .get(&probe.url)
        .send()
        .await
        .map_err(|e| format!("{}: {e}", probe.display))?;
    if !resp.status().is_success() {
        return Err(format!("{}: status {}", probe.display, resp.status()));
    }
    Ok(true)
}

/// Build / version info endpoint. Returns the package version, the
/// `git describe` string (matches the release tag for tagged builds), the
/// short commit hash, and the build timestamp. Useful when troubleshooting
/// to confirm exactly which revision a running server was built from.
async fn version_info() -> Json<VersionInfo> {
    Json(VersionInfo::current())
}
