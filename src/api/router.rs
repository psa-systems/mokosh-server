//! API router configuration

use axum::{
    http::{header, Method, StatusCode},
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

use super::cors_origin::CorsOriginMatcher;

use crate::db::Database;
use crate::modules::approvals::{approval_routes, ApprovalsService};
use crate::modules::assets::{assets_routes, AssetsService};
use crate::modules::audit::{audit_routes, AuditService};
use crate::modules::auth::{
    auth_routes, bunyip_webhook::BunyipWebhookState, AuthMiddleware, AuthService,
};
use crate::modules::billing::{
    billing_routes, provider_webhook_handler, BillingService, ProviderWebhookState,
};
use crate::modules::calendar::{calendar_routes, dispatch_routes, CalendarService};
use crate::modules::contacts::{contact_routes, ContactService};
use crate::modules::contracts::{contracts_routes, ContractsService};
use crate::modules::dashboards::{dashboard_routes, DashboardsService};
use crate::modules::email_intake::{email_intake_routes, EmailIntakeService};
use crate::modules::forms::{forms_routes, public_form_routes, FormsService};
use crate::modules::invitations::{invitations_routes, InvitationsService};
use crate::modules::knowledge_base::attachments::{
    kb_attachment_routes, public_kb_attachment_routes, KbAttachmentConfig, KbAttachmentService,
};
use crate::modules::knowledge_base::{kb_routes, KbService};
use crate::modules::mileage_tracking::{mileage_tracking_routes, MileageTrackingService};
use crate::modules::notifications::{notifications_routes, NotificationsService};
use crate::modules::platform::{platform_routes, PlatformAdminService};
use crate::modules::portal_roles::{portal_role_routes, PortalRoleService};
use crate::modules::projects::{projects_routes, ProjectsService};
use crate::modules::quotes::{quotes_routes, QuotesService};
use crate::modules::reports::{reports_routes, ReportsService};
use crate::modules::rmm::{rmm_routes, RmmService};
use crate::modules::saved_reports::{saved_reports_routes, SavedReportsService};
use crate::modules::search::{search_routes, SearchService};
use crate::modules::settings::{settings_routes, SettingsService};
use crate::modules::sla::{sla_routes, SlaService};
#[cfg(feature = "multi-tenant")]
use crate::modules::teams::{me_teams_routes, teams_routes, TeamsService};
use crate::modules::tenants::{public_tenant_routes, tenant_routes, TenantService};
use crate::modules::ticket_templates::{ticket_template_routes, TicketTemplatesService};
use crate::modules::tickets::{
    agent_attachment_routes, contact_notes_routes, public_ticket_attachment_routes, ticket_routes,
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
    client_origin: String,
    // MAPPS-425: base for emailed links to pages that exist only in the
    // mokosh-apps SPA. Distinct from `client_origin`, which is the apex on
    // every deployed environment because bunyip-web hosts login there.
    spa_base_url: String,
    cors_origins: Vec<String>,
    bunyip_verifier: Option<crate::modules::auth::oidc_rs::Verifier>,
    // PMS-638: the live, swappable mailer handle. Upcast to `Arc<dyn Mailer>`
    // for the services below; the concrete handle is threaded into
    // `settings_routes` so the admin email-settings endpoint can hot-swap it.
    shared_mailer: Arc<crate::utils::email::SharedMailer>,
    // 32-byte AES-256-GCM key. Used for at-rest encryption of any
    // per-tenant secret material (payment-gateway configs, and the legacy
    // TOTP shared secret on `users.mfa_secret` since PMS-871).
    encryption_key: [u8; 32],
    // PMS-591: shared secret for the BUNYIP-211 `account_deleted` webhook.
    // Verified as `hex(hmac_sha256(body, secret))` against the
    // `X-Webhook-Signature` header on `/api/v1/bunyip/webhooks/account-deleted`.
    bunyip_webhook_secret: Vec<u8>,
    // PMS-657: IP -> country resolver for login-location alerts, built from
    // IP2LOCATION_DB_PATH in main.rs. `None` disables the feature.
    geoip: Option<Arc<crate::utils::geoip::GeoIpService>>,
    // BUNYIP-475: advisory ASN / VPN enrichment service (shared dunite-ipenrich
    // crate), built from IP2PROXY_DB_PATH in main.rs. `None` disables the
    // admin enrichment lookup.
    ip_enrich: Option<Arc<dunite_ipenrich::IpEnrichService>>,
    // PMS-658: master switch for the suspicious-login notify-and-approve gate,
    // from LOGIN_APPROVAL_ENABLED in main.rs. Off by default (can block logins).
    login_approval_enabled: bool,
    // PMS-748: address a client can report an unwanted request-form email to,
    // from ABUSE_CONTACT_EMAIL in main.rs. `None` drops the line from the mail
    // rather than pointing it at the noreply from-address.
    abuse_contact_email: Option<String>,
    // MAPPS-429: this deployment's public API base, from PUBLIC_API_BASE_URL in
    // main.rs. Only the emailed logo needs it (a mail client cannot resolve a
    // relative src); `None` omits the logo rather than emitting a broken image.
    public_api_base_url: Option<String>,
    // MAPPS-457: instance-wide tenant creation cap, from MOKOSH_MAX_TENANTS.
    // `None` = uncapped (production today); `Some(N)` = 409 on further creates
    // once `SELECT COUNT(*) FROM tenants` reaches N.
    max_tenants: Option<usize>,
    // PMS-904: self-hosted (mokosh owns platform identity) or saas (federated
    // to Bunyip SSO), from MOKOSH_DEPLOYMENT_MODE in main.rs. Decides whether
    // the mail that exists only to service a local password is sent at all.
    deployment_mode: crate::utils::deployment::DeploymentMode,
    // PMS-968: where tenant-supplied secrets live, chosen once at boot by
    // `secrets::store_from_env`. Injected rather than built here so this
    // function cannot pick a backend, and so a deployment on Infisical has
    // every `BillingService` below on Infisical rather than whichever ones
    // remembered to ask.
    secrets: Arc<dyn crate::secrets::SecretStore>,
) -> Router {
    let cors_matcher = CorsOriginMatcher::from_entries(&cors_origins);
    let mailer: Arc<dyn crate::utils::email::Mailer> = shared_mailer.clone();

    // PMS-905: `bunyip_verifier` is moved into the auth middleware below, so
    // capture the one fact the auth service needs from it first.
    let sso_mounted = bunyip_verifier.is_some();
    if deployment_mode.is_saas() && !sso_mounted {
        // Loud, but not fatal. A `saas` deployment with no verifier can
        // authenticate nobody through SSO, so the local password path is the
        // only way in and stays open deliberately (see
        // `AuthService::local_password_auth_disabled`). Making this a boot
        // failure instead is precisely PMS-289, which took staging and
        // production down and needed PMS-292 to restore service.
        tracing::error!(
            "MOKOSH_DEPLOYMENT_MODE=saas but no Bunyip RS verifier is mounted (OIDC_ISSUER / \
             OIDC_AUDIENCE unset): local password login remains ENABLED because it is the only \
             auth path this instance has. Configure the verifier, or set the mode to self-hosted.",
        );
    }

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
        mailer.clone(),
        // MAPPS-425: stays on `client_origin` deliberately. This is the base
        // for `/reset-password/{token}`, and bunyip-web at the apex owns the
        // canonical reset page; mokosh-apps' route only redirects there. Same
        // for the invitation link and the not-a-frontend fallback below. Only
        // links to pages that exist ONLY in mokosh-apps take `spa_base_url`.
        client_origin.clone(),
        notifications_service.clone(),
    )
    .with_geoip(geoip)
    .with_login_approval(login_approval_enabled)
    .with_deployment_mode(deployment_mode)
    // PMS-905: local password auth closes only when a working alternative
    // exists. `bunyip_verifier` is `Some` exactly when OIDC_ISSUER and
    // OIDC_AUDIENCE are configured, so it is the signal for "SSO is set up
    // here" rather than a guess from the mode alone.
    .with_sso_mounted(sso_mounted)
    // PMS-871: `users.mfa_secret` is AES-256-GCM at rest under the same key
    // the payment-gateway configs use, so the auth service holds it too.
    .with_encryption_key(encryption_key);
    #[cfg(feature = "multi-tenant")]
    // PMS-729 finalize: attach the dispatcher + SPA origin so a super-admin
    // creating a tenant produces an emailed setup link for the fresh admin
    // (mirrors `AuthService::create_user(send_welcome_email = true)`; same
    // `client_origin`-based reset-password link the rest of the auth flow
    // already builds against). The pre-session bunyip placement path
    // (`auth_middleware.with_tenants(...)`) keeps its own bare
    // `TenantService::new` because it does not create tenants that need an
    // admin welcome.
    let tenant_service = TenantService::new(db.clone())
        .with_dispatcher(notifications_service.clone(), client_origin.clone())
        // MAPPS-457: attach the instance-wide tenant cap. `None` (unset
        // env) leaves the service uncapped, matching production today.
        .with_max_tenants(max_tenants);
    // PMS-136: ContactService emails a `/portal/set-password` setup link when
    // an agent grants portal access, so it holds the SPA origin (the link
    // base). PMS-700: that mail is queued through the same `auth.welcome`
    // dispatch the staff welcome mail uses, so it takes the dispatcher rather
    // than the mailer.
    let contact_service = ContactService::with_dispatcher(
        db.clone(),
        // MAPPS-425: `/portal/set-password` is a mokosh-apps route, so it takes
        // the SPA origin. Built from `client_origin` it landed on the apex,
        // which has no portal.
        spa_base_url.clone(),
        notifications_service.clone(),
    );
    let ticket_service =
        TicketService::with_dispatcher(db.clone(), mailer.clone(), notifications_service.clone());
    // PMS-711: the agent-facing billing service also sends the outbound invoice
    // "Pay Now" email on the send transition, so it takes the mailer + the SPA
    // origin the pay link is built from.
    let billing_service = BillingService::with_delivery(
        db.clone(),
        encryption_key,
        mailer.clone(),
        // MAPPS-425: the Pay Now link is `/portal/invoices/{id}`, a mokosh-apps
        // route, so it takes the SPA origin.
        spa_base_url.clone(),
        secrets.clone(),
    );
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
        // MAPPS-425: the emailed quote link is `/portal/quotes/{id}`, a
        // mokosh-apps route, so it takes the SPA origin.
        spa_base_url.clone(),
    );
    let assets_service = AssetsService::with_encryption_key(db.clone(), encryption_key);
    let kb_service = KbService::new(db.clone());
    // PMS-246: the SPA origin is the invite accept-link base (login-driven
    // acceptance), so created invites email the invitee.
    let invitations_service =
        Arc::new(InvitationsService::new(db.clone()).with_app_url(client_origin.clone()));
    let reports_service = ReportsService::new(db.clone());
    // PMS-457: saved-report definitions (Phase 1).
    let saved_reports_service = SavedReportsService::new(db.clone());
    // PMS-448: ticket.created workflow rule executor + CRUD.
    let workflows_service = WorkflowsService::new(db.clone());
    // PMS-448 AC4: admin-authored ticket templates (new-ticket pre-fills).
    let ticket_templates_service = TicketTemplatesService::new(db.clone());
    // PMS-731: form definitions + per-field validation, the substrate the
    // PMS-730 MACD request flow consumes. PMS-730 adds the request-link half,
    // which needs the dispatcher (to email the client their link) and the
    // ticket service (to turn their submission into a ticket).
    let forms_service = FormsService::with_request_links(
        db.clone(),
        notifications_service.clone(),
        TicketService::new(db.clone()),
    )
    // PMS-748: only the authenticated surface sends mail, but the public
    // surface is built from the same constructor, so both are given it and
    // neither can drift from the other.
    .with_abuse_contact(abuse_contact_email.clone())
    .with_public_api_base(public_api_base_url.clone());
    // MAPPS-298: cross-entity tenant-scoped search.
    let search_service = SearchService::new(db.clone());
    // PMS-453: per-user saved dashboards.
    let dashboards_service = DashboardsService::new(db.clone());
    // PMS-450: email-to-ticket intake. Holds a TicketService clone so
    // the intake handler can reuse the full ticket-create flow
    // (audit + SLA assignment + ticket-number generation) without
    // duplicating the INSERT.
    // PMS-450 AC3: the intake service stores inbound attachments via the
    // shared `ticket_attachments` blob path, so it holds its own
    // `AttachmentService` (same env-driven dir + size cap as the agent /
    // portal upload routes).
    let email_intake_service = EmailIntakeService::new(
        db.clone(),
        ticket_service.clone(),
        AttachmentService::new(db.clone(), AttachmentConfig::from_env()),
    );
    // PMS-451: per-ticket approval requests.
    let approvals_service = ApprovalsService::new(db.clone());
    let rmm_service =
        RmmService::with_dependencies(db.clone(), encryption_key, ticket_service.clone());
    // SLA service shares the notifications dispatcher so the
    // `sla_sweep` worker (spawned from main.rs with this same service)
    // can enqueue at-risk / breach alerts. The CRUD + evaluate routes
    // do not use the dispatcher; only the worker does.
    let sla_service = SlaService::with_dispatcher(db.clone(), notifications_service.clone());
    // PMS-157 / PMS-710: first-visit demo seeding. Holds its own clones of the
    // contacts, tickets, projects, and SLA services so it can drive the real
    // create paths for the connected demo dataset; wired below as a middleware
    // that runs after auth populates AuthState. Constructed here (after the
    // projects + SLA services exist) rather than at the top of the builder.
    let seed_service = Arc::new(crate::modules::seed::SeedService::new(
        db.clone(),
        contact_service.clone(),
        ticket_service.clone(),
        projects_service.clone(),
        sla_service.clone(),
    ));
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
        // pings Infisical when `INFISICAL_ADDRESS` is set. Returns 503
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
        // Auth routes. MAPPS-493 (phase 4): share the AuthService Arc with
        // tenant_routes so `/tenants/self-serve` can decode identity_tokens
        // minted by /auth/login. AuthService derives Clone, so this is a
        // cheap Arc bump. PMS-837 removed the Google OAuth popup routes and
        // their `google_oauth` / `cookie_secure` parameters.
        .nest("/auth", auth_routes(auth_service.clone()))
        // MAPPS-513: platform super-admin routes. Distinct credential
        // store (`platform_admins`) and distinct JWT typ so the
        // super-admin persona is isolated from the tenant identity
        // model. `RequirePlatformAdmin` extractor reads the platform
        // service from request extensions; the extension layer that
        // makes it reachable is attached at the very end of the
        // api_v1 build (alongside `settings_service`) so every route
        // (including the MAPPS-518 platform-admin-gated tenant
        // endpoints) can resolve it.
        .nest(
            "/platform",
            platform_routes(PlatformAdminService::new(db.clone(), jwt_secret.clone())),
        )
        // Tenant management. Only mounted in multi-tenant builds: in a
        // single-tenant deployment there is exactly one tenant and the
        // CRUD endpoints would be a foot-gun. PMS-24.
        ;
    #[cfg(feature = "multi-tenant")]
    let api_v1 = api_v1.nest(
        "/tenants",
        tenant_routes(
            tenant_service,
            settings_service.clone(),
            std::sync::Arc::new(auth_service),
        ),
    );
    // PMS-791 / MAPPS-461: teams CRUD + membership. Two mounts so the
    // "my teams" endpoint sits under /me alongside future me-scoped
    // routes rather than crowding /teams.
    #[cfg(feature = "multi-tenant")]
    let api_v1 = api_v1
        .nest("/teams", teams_routes(TeamsService::new(db.clone())))
        .nest("/me", me_teams_routes(TeamsService::new(db.clone())));
    let api_v1 = api_v1
        // Contact management. The canonical company endpoints live
        // under `/api/v1/contacts/companies/...` (one router for
        // companies + contacts + sites); a previous `nest("/companies",
        // Router::new())` here was dead - it matched nothing, so
        // `/api/v1/companies` returned a misleading 404 with no
        // explanation. Removed and documented (PMS-20).
        .nest(
            "/contacts",
            contact_routes(contact_service.clone(), PortalRoleService::new(db.clone())),
        )
        // MAPPS-618 phase B: Company-scoped branding asset uploads
        // (logo / favicon / background). Staff-gated on
        // `role.is_admin()`; the contact-plane siblings are wired
        // separately below under `/api/v1/contact`.
        .merge(crate::modules::branding::routes::staff_routes(db.clone()))
        // mokosh-contact-login prompt 007: MSP-admin portal-role CRUD.
        // Distinct top-level nest so the SPA hits `/api/v1/portal-roles`
        // and the routes inside stay uncluttered by the double-nest
        // `/contacts/portal-roles` shape the older read-only surface uses.
        //
        // PMS-929 (prompt 012): the nested Company-scoped role surface
        // under `/api/v1/contacts/companies/{id}/portal-roles` also
        // takes a `PortalRoleService`, built as a sibling instance
        // above; both instances share the same `db` handle and are
        // otherwise stateless.
        .nest(
            "/portal-roles",
            portal_role_routes(PortalRoleService::new(db.clone())),
        )
        // Ticketing.
        //
        // PMS-936: the ticket router now also carries the shared
        // `AttachmentService` so the portal `POST /tickets/{id}/attachments`
        // route can reuse the on-disk blob pipeline (same env-driven
        // dir + size cap as the agent surface).
        .nest(
            "/tickets",
            ticket_routes(
                ticket_service.clone(),
                AttachmentService::new(db.clone(), AttachmentConfig::from_env()),
                // PMS-937: the tickets router now also owns
                // `POST /tickets/{id}/approvals/request`, which needs
                // the shared ApprovalsService instance (used for both
                // contact-plane inserts and the staff-plane shortcut).
                approvals_service.clone(),
            ),
        )
        // PMS-483: ticket-note attachment upload / download / delete.
        // Merged at the top level so its `/tickets/{id}/notes/...`
        // path nests cleanly under the existing ticket tree.
        .merge(agent_attachment_routes(AttachmentService::new(
            db.clone(),
            AttachmentConfig::from_env(),
        )))
        // PMS-468: agent "all comments from this contact" feed. The
        // route lives on the tickets module (TicketService owns the
        // notes surface) but mounts at the top level so its path
        // matches the SPA's `/contacts/{id}/notes` URL.
        .merge(contact_notes_routes(ticket_service.clone()))
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
        //
        // PMS-936: also carries a `TicketService` clone so the
        // `POST /assets/{id}/report-issue` endpoint can create the
        // linked ticket through the shared portal-ticket path.
        .merge(assets_routes(assets_service, ticket_service.clone()))
        // Knowledge base: categories + articles + versions + portal feed. PMS-80.
        .merge(kb_routes(kb_service))
        // PMS-923: images an article embeds. Upload / list / delete are
        // manager-gated here; the READ is public (see the public tree below),
        // because an `<img>` cannot carry an Authorization header.
        .merge(kb_attachment_routes(KbAttachmentService::new(
            db.clone(),
            KbAttachmentConfig::from_env(),
        )))
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
        // PMS-731: form-definition CRUD + validated submissions.
        // MAPPS-425: the emailed link must resolve against the SPA, not the
        // apex. `/request-forms/:token` exists only in mokosh-apps, so the
        // apex serves bunyip's 404 for it.
        .merge(forms_routes(forms_service, spa_base_url.clone()))
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
        // BUNYIP-475: advisory ASN / VPN enrichment lookup (admin-gated),
        // consuming the shared dunite-ipenrich crate.
        .merge(crate::modules::ip_enrich::ip_enrich_routes(ip_enrich))
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
        // mokosh-contact-login prompt 008: the contact-plane middleware runs
        // on /api/v1/* too (not just /api/v1/contact/*) so a contact bearer
        // reaching a dual-plane endpoint (tickets, invoices, quotes) lands
        // in ContactAuthState. The `typ` claim isolation still holds - a
        // staff bearer decodes only in the staff branch and vice versa - so
        // this layer never overwrites an authenticated staff request; it
        // simply attaches ContactAuthState (default when the bearer is not
        // a contact token) so `RequireCallerContext` can fall back to it.
        .layer(middleware::from_fn_with_state(
            crate::modules::contact_portal::ContactAuthMiddleware::new(
                crate::modules::contact_portal::ContactAuthService::new(
                    db.clone(),
                    jwt_secret.clone(),
                ),
            ),
            crate::modules::contact_portal::middleware::portal_contact_middleware,
        ))
        // mokosh-contact-login prompt 008: `Extension<Database>` powers
        // `CallerContext::require_capability`'s DB-load of the effective
        // capability set. Attaching it once here lets every dual-plane
        // handler pull the db without threading it through router state.
        .layer(axum::Extension(db.clone()))
        // PMS-113 AC3: make SettingsService reachable from
        // `RequireModuleEnabled` extractors via the request's
        // extensions. The extractor reads
        // `parts.extensions.get::<Arc<SettingsService>>()` and short-
        // circuits with 404 when the gated module is disabled.
        .layer(axum::Extension(settings_service))
        // MAPPS-513 / MAPPS-518: make `PlatformAdminService` reachable
        // from the `RequirePlatformAdmin` extractor via request
        // extensions. Attached at the outermost layer so every
        // /api/v1 route (including the platform-admin-gated tenant
        // endpoints from MAPPS-518) can resolve it, not just the
        // /platform sub-tree.
        .layer(axum::Extension(Arc::new(PlatformAdminService::new(
            db.clone(),
            jwt_secret.clone(),
        ))))
        // PMS-298: outermost layer so every 4xx (including extractor
        // rejections such as a JSON body that fails to deserialize) is
        // returned as the standard `{error:{code,message}}` envelope instead
        // of raw axum/serde plaintext. JSON responses (every `AppError`) pass
        // through untouched.
        .layer(middleware::from_fn(
            crate::utils::error::normalize_error_envelope,
        ));

    // mokosh-contact-login: the /portal/* customer-portal surface retires
    // on this branch. The whole PortalAuthService + PortalRouter tree
    // built here pre-pivot is gone; the contact plane replaces it under
    // /api/v1/contact/* in a later prompt (004).

    // CORS: SPA at msp.<tld> talks to api.msp.<tld> from a different origin,
    // so credentialed CORS must be tight (specific origins, not wildcard).
    // The list comes from the CORS_ORIGIN env var (comma-separated). The
    // bunyip apex is included so the SaaS shell can call mokosh endpoints
    // in the future without losing credentials.
    //
    // PMS-729: entries starting with `https://*.` or `http://*.` are
    // scheme-locked wildcard suffixes: they match any Origin whose scheme
    // matches and whose host ends with the suffix (dot preserved). Used for
    // the client-portal wildcard host `{slug}.client.<apex>` so per-tenant
    // portal origins do not each need their own explicit CORS_ORIGIN entry.
    // See `CorsOriginMatcher::from_entries` for the parse rules.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            cors_matcher.matches(origin.as_bytes())
        }))
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
        // SAFETY (PMS-285 / PMS-692): the account-deleted webhook is pre-auth
        // (HMAC-signed, no session) and inherently cross-tenant - `soft_delete`
        // resolves the tenant FROM the `users` row it reads by bunyip sub, so
        // there is no `app.current_tenant` GUC to set beforehand. It runs on the
        // BYPASSRLS migrator pool; `users` is RLS-covered and would fail closed
        // on the unprivileged app pool.
        pool: db.migrator_pool().clone(),
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

    // PMS-711: Stripe webhook receiver. Nested under `/api/v1/stripe` OUTSIDE
    // the JWT auth chain: Stripe authenticates itself with the `Stripe-Signature`
    // header (HMAC over the raw body, keyed by the tenant's per-account webhook
    // secret). The tenant id in the path selects which tenant's secret to verify
    // against; it is not itself a credential. Its own `BillingService` instance
    // (the router's `billing_service` is moved into `billing_routes`).
    let stripe_webhook_state = Arc::new(ProviderWebhookState {
        billing: Arc::new(BillingService::with_secrets(
            db.clone(),
            encryption_key,
            secrets.clone(),
        )),
        provider_id: "stripe",
    });
    let stripe_webhooks = Router::new()
        .route("/webhooks/{tenant_id}", post(provider_webhook_handler))
        .with_state(stripe_webhook_state)
        .layer(middleware::from_fn(
            crate::utils::error::normalize_error_envelope,
        ));

    // PMS-969: PayPal webhook receiver, same handler and same shape, nested
    // under `/api/v1/paypal`. PayPal authenticates itself with five
    // `PAYPAL-TRANSMISSION-*` headers that the provider checks back with
    // PayPal rather than locally. Its prefix is in `RAW_BODY_PATHS` for the
    // same reason Stripe's is: the verify call sends the body back to PayPal
    // to compare, so a byte the sanitizer rewrote is a verification failure.
    let paypal_webhook_state = Arc::new(ProviderWebhookState {
        billing: Arc::new(BillingService::with_secrets(
            db.clone(),
            encryption_key,
            secrets.clone(),
        )),
        provider_id: "paypal",
    });
    let paypal_webhooks = Router::new()
        .route("/webhooks/{tenant_id}", post(provider_webhook_handler))
        .with_state(paypal_webhook_state)
        .layer(middleware::from_fn(
            crate::utils::error::normalize_error_envelope,
        ));

    // Combine everything. The `.fallback` swallows any non-/api/v1/* request
    // (including hitting `/` directly in a browser) with a small placeholder
    // page that links the user back to the Mokosh frontend. This keeps
    // api.msp.<tld> from leaking internal route info.
    // PMS-730: the unauthenticated client-facing request-form surface. Its
    // own nest, OUTSIDE `AuthMiddleware` and outside the portal tree, because
    // the caller has no session at all: the magic-link token is the only
    // identity, and it resolves its own tenant. Same envelope normalization as
    // the other trees so a 400 here looks like a 400 anywhere else.
    let public_api = Router::new()
        // MAPPS-429: the tenant logo, readable without a session. A client's
        // mail client renders it straight out of the request-form email and
        // will never authenticate.
        .merge(public_tenant_routes(TenantService::new(db.clone())))
        // MAPPS-618 phase B: same shape for the Company-scoped
        // assets (logo / favicon / background).
        .merge(crate::modules::branding::routes::public_routes(db.clone()))
        // PMS-923: an image embedded in a KB article. Unauthenticated by
        // necessity, not by preference: the browser fetches it as `<img src>`,
        // which carries no Authorization header, and the SPA holds a bearer
        // rather than a cookie. The attachment's v4 UUID is the only
        // credential, so anyone holding the URL can fetch the image even for an
        // `internal` article. Same bargain as the logo above.
        .merge(public_kb_attachment_routes(KbAttachmentService::new(
            db.clone(),
            KbAttachmentConfig::from_env(),
        )))
        // PMS-941: an image embedded in a ticket description or note, for the
        // same reason as the KB image above and with one extra guard: this
        // table also holds portal uploads and inbound-email attachments, so
        // the read serves only rows the inline-image upload path flagged with
        // `is_inline`. Anything else 404s here exactly as an unknown id does.
        .merge(public_ticket_attachment_routes(AttachmentService::new(
            db.clone(),
            AttachmentConfig::from_env(),
        )))
        .merge(public_form_routes(
            FormsService::with_request_links(
                db.clone(),
                notifications_service.clone(),
                TicketService::new(db.clone()),
            )
            .with_abuse_contact(abuse_contact_email)
            .with_public_api_base(public_api_base_url),
        ))
        .layer(middleware::from_fn(
            crate::utils::error::normalize_error_envelope,
        ));

    // mokosh-contact-login prompt 004: contact-plane sub-router at
    // /api/v1/contact/*. Distinct from /api/v1 (staff plane) - the
    // portal_contact_middleware only decodes `typ: "contact"` tokens,
    // so a staff bearer here is a 401 by construction.
    let contact_service =
        crate::modules::contact_portal::ContactAuthService::new(db.clone(), jwt_secret.clone())
            .with_notifications(notifications_service.clone())
            .with_spa_base_url(spa_base_url.clone());
    // MAPPS-618 phase B: share the ContactAuthService with the
    // branding router so it can `load_capabilities` for the
    // `settings:manage_company_branding` gate without a duplicate
    // instance.
    let contact_service_arc = std::sync::Arc::new(contact_service.clone());
    let contact_api = crate::modules::contact_portal::contact_routes(contact_service)
        .merge(crate::modules::branding::routes::contact_routes(
            db.clone(),
            contact_service_arc,
        ))
        .layer(middleware::from_fn(
            crate::utils::error::normalize_error_envelope,
        ));

    Router::new()
        .nest("/api/v1", api_v1)
        .nest("/api/v1/public", public_api)
        .nest("/api/v1/contact", contact_api)
        .nest("/api/v1/bunyip", bunyip_webhooks)
        .nest("/api/v1/stripe", stripe_webhooks)
        .nest("/api/v1/paypal", paypal_webhooks)
        .fallback(get(move |headers| {
            not_a_frontend(headers, client_origin.clone())
        }))
        // PMS-924: strip invisible characters from every JSON request body
        // before any extractor deserializes it. Added first, so it is the
        // INNERMOST of the outer layers: it runs after CORS has answered any
        // preflight, and it sees the full `/api/v1/...` path (nesting strips the
        // prefix only once routing starts), which is what lets it exempt the
        // three signature-verified receivers by path. One layer rather than a
        // `SanitizedJson<T>` extractor on 157 `Json<T>` handlers, so a route
        // added later cannot forget to opt in.
        .layer(middleware::from_fn(crate::utils::text::sanitize_json_body))
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
    // PMS-789: read the cached name. This handler has no `State` and must
    // render when the database is down, which is when it is most looked at.
    // Escaped: `sanitize` bars control characters, not `<` or `&`.
    let app = crate::utils::html::html_escape(&crate::utils::app_name::app_name());
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
         <p>You're looking at the {app} backend API. There is no user interface here.</p>\n\
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
/// - **Database** (always): `SELECT 1` against the pool, bounded by
///   [`READY_DB_PING_TIMEOUT`]. The legacy `health_check()` returns
///   `"OK"` unconditionally; this is the first probe that
///   distinguishes a process that booted from one that can actually
///   serve a request.
/// - **Infisical** (best-effort): if the operator set
///   `INFISICAL_ADDRESS` at process start, a 1-second HTTP probe
///   against `<base>/api/status`. Mokosh-server loads Infisical
///   secrets at boot only, so a transient Infisical outage does
///   not break in-flight requests; the probe still surfaces the
///   outage because the next process restart would fail. Skipped
///   when the env var was unset or blank at boot (single-machine
///   deployments without an Infisical sibling). The 1s timeout matches the
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
    let db_result = bounded_db_ping(db.health_check()).await;
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

/// Upper bound on the readiness DB ping (PMS-685). 3s leaves room for
/// a cold connection pool or a loaded Postgres, which can take ~1s to
/// answer `SELECT 1`; calling a reachable database unready makes the
/// orchestrator drain or restart a healthy instance. The ping was
/// previously unbounded, so a wedged connection could hold the probe
/// open indefinitely.
const READY_DB_PING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Run the readiness DB ping under [`READY_DB_PING_TIMEOUT`]. Takes the
/// ping future (rather than the pool) so the timeout path is unit
/// testable without a wedged database.
async fn bounded_db_ping(
    ping: impl std::future::Future<Output = crate::utils::error::AppResult<()>>,
) -> Result<(), String> {
    match tokio::time::timeout(READY_DB_PING_TIMEOUT, ping).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!(
            "db ping exceeded {}s",
            READY_DB_PING_TIMEOUT.as_secs()
        )),
    }
}

/// Captured-at-boot Infisical probe state. The handler used to read
/// `INFISICAL_ADDRESS` and build a fresh `reqwest::Client` on every
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
    /// operator may have embedded in `INFISICAL_ADDRESS`.
    display: String,
    client: reqwest::Client,
}

static INFISICAL_PROBE: std::sync::OnceLock<Option<InfisicalProbe>> = std::sync::OnceLock::new();

fn infisical_probe() -> Option<&'static InfisicalProbe> {
    INFISICAL_PROBE
        .get_or_init(|| {
            // GOV-50: the Infisical instance URL is read from the canonical
            // INFISICAL_ADDRESS only.
            let raw = std::env::var("INFISICAL_ADDRESS")
                .ok()
                .filter(|v| !v.trim().is_empty());
            build_infisical_probe(raw)
        })
        .as_ref()
}

/// Build the probe from the resolved Infisical address (`INFISICAL_ADDRESS`).
/// Split out of
/// [`infisical_probe`] so the blank-is-unconfigured rule is unit testable
/// without mutating the process-global env behind the `OnceLock`.
///
/// A blank value counts as unconfigured (PMS-707): Docker Compose renders
/// `KEY: ${VAR:-}` as the key present with an empty value, and probing
/// `/api/status` on an empty base URL would 503 the dev stack forever.
fn build_infisical_probe(raw: Option<String>) -> Option<InfisicalProbe> {
    let base = raw?;
    let base = base.trim();
    if base.is_empty() {
        return None;
    }
    let trimmed = base.trim_end_matches('/').to_string();
    // Best-effort credential scrub for error strings. If
    // `INFISICAL_ADDRESS` does not parse as a URL, fall back
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
}

/// Probe Infisical's `/api/status` endpoint when the operator opted
/// in via `INFISICAL_ADDRESS`. Returns:
///
/// - `Ok(true)` - probe ran and got a 2xx response
/// - `Ok(false)` - probe skipped (env var unset or blank)
/// - `Err(_)` - env var set, but the probe failed (DNS, TCP, non-2xx
///   response, or 1s timeout). Error messages reference only the
///   sanitised display URL so credentials in the env var stay out
///   of the response body / access log.
async fn probe_infisical() -> Result<bool, String> {
    let Some(probe) = infisical_probe() else {
        return Ok(false);
    };
    run_infisical_probe(probe).await
}

/// Run one configured probe. Split out of [`probe_infisical`] so the
/// "configured but unreachable stays an error" path is unit testable
/// without the process-global `OnceLock`.
async fn run_infisical_probe(probe: &InfisicalProbe) -> Result<bool, String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::error::AppError;

    /// A ping that answers just under the bound still reports ready
    /// (PMS-685: a slow-but-healthy DB must not read as unready).
    #[tokio::test(start_paused = true)]
    async fn slow_but_answering_db_ping_is_ok() {
        let ping = async {
            tokio::time::sleep(READY_DB_PING_TIMEOUT - std::time::Duration::from_millis(1)).await;
            Ok(())
        };
        assert_eq!(bounded_db_ping(ping).await, Ok(()));
    }

    /// A wedged ping is still bounded, so a truly unreachable DB fails
    /// the probe instead of hanging it open.
    #[tokio::test(start_paused = true)]
    async fn hung_db_ping_times_out() {
        let ping = async {
            std::future::pending::<()>().await;
            Ok(())
        };
        assert_eq!(
            bounded_db_ping(ping).await,
            Err("db ping exceeded 3s".to_string())
        );
    }

    /// A ping that fails fast surfaces the sqlx error, not the timeout.
    #[tokio::test]
    async fn failing_db_ping_surfaces_the_error() {
        let ping = async { Err(AppError::Database("connection closed".into())) };
        let err = bounded_db_ping(ping).await.expect_err("ping should fail");
        assert!(err.contains("connection closed"), "unexpected error: {err}");
    }

    /// Unset, empty, and whitespace-only all mean "no Infisical" (PMS-707).
    /// Compose renders an unset host var as an empty value, and probing an
    /// empty base URL 503'd the dev stack on every /ready.
    #[test]
    fn blank_infisical_base_url_is_unconfigured() {
        for raw in [None, Some(String::new()), Some("   \t ".to_string())] {
            assert!(
                build_infisical_probe(raw.clone()).is_none(),
                "expected no probe for {raw:?}"
            );
        }
    }

    /// A real value still builds the probe, against `<base>/api/status`.
    #[test]
    fn set_infisical_base_url_builds_the_probe() {
        let probe = build_infisical_probe(Some("http://infisical:8080/".to_string()))
            .expect("probe should be configured");
        assert_eq!(probe.url, "http://infisical:8080/api/status");
        assert_eq!(probe.display, "http://infisical:8080");
    }

    /// Configured-but-unreachable stays an error (which /ready turns into
    /// a 503), so PMS-707's blank-is-skipped rule does not weaken the
    /// fail-loud behaviour for a real deployment.
    #[tokio::test]
    async fn configured_but_unreachable_infisical_is_an_error() {
        // Port 1 is reserved and never listening, so this refuses fast.
        let probe = build_infisical_probe(Some("http://127.0.0.1:1".to_string()))
            .expect("probe should be configured");
        let err = run_infisical_probe(&probe)
            .await
            .expect_err("unreachable probe should error");
        assert!(
            err.contains("http://127.0.0.1:1"),
            "unexpected error: {err}"
        );
    }

    /// Drive the same `CompressionLayer::new()` the router applies globally and
    /// report the `content-encoding` it negotiated for `accept_encoding`.
    async fn negotiated_encoding(accept_encoding: &str) -> String {
        use tower::ServiceExt;

        // Well past the compression predicate's 32-byte floor, so the layer
        // actually encodes instead of passing the body through.
        let app = Router::new()
            .route(
                "/",
                get(|| async { "a body long enough to clear the compression size floor" }),
            )
            .layer(CompressionLayer::new());
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .header(header::ACCEPT_ENCODING, accept_encoding)
                    .body(axum::body::Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");

        response
            .headers()
            .get(header::CONTENT_ENCODING)
            .map(|v| v.to_str().expect("encoding is ascii").to_owned())
            .unwrap_or_default()
    }

    /// PMS-780: `CompressionLayer::new()` only offers the algorithms whose
    /// tower-http cargo features are compiled in, so dropping `compression-br`
    /// from Cargo.toml would silently downgrade every brotli client to gzip
    /// with no code change to review. This is the guard that fails instead.
    #[tokio::test]
    async fn brotli_is_negotiated_when_the_client_advertises_it() {
        assert_eq!(negotiated_encoding("br,gzip").await, "br");
    }

    /// The gzip-only client keeps getting gzip: brotli is added, not swapped.
    #[tokio::test]
    async fn gzip_only_client_still_gets_gzip() {
        assert_eq!(negotiated_encoding("gzip").await, "gzip");
    }
}
