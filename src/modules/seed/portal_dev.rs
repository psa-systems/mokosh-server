//! PMS-729: dev-only fixture seeder for the client-portal login flow.
//!
//! Inserts a handful of tenants + one portal-enabled contact per tenant so
//! a developer can exercise the host-derived tenant login end-to-end
//! against `http://{slug}.client.localhost:4301` on their local box.
//! The seeded rows are idempotent (`ON CONFLICT (slug) DO NOTHING`),
//! so re-running is a no-op after the first pass.
//!
//! # Hard guardrail (fail closed)
//!
//! Refuses to run when `ENVIRONMENT` is not `development`, `dev`, or
//! `test`. There is no override flag; the intent is that pointing this
//! at production is a mistake we should catch at the boundary rather
//! than trust the operator to not do.
//!
//! # Shape
//!
//! - `acme`:active, branded (logo URL) - the golden-path tenant.
//! - `beta`:active, no branding - proves the login page still renders
//!   the generic wordmark when `branding.logo_url` is absent.
//! - `inact`:inactive, so hitting `inact.client.localhost:4301`
//!   exercises the fail-closed path (unknown host, from the extractor's
//!   point of view: `status != 'active'` misses the DB filter).
//!
//! Every seeded portal contact shares [`PORTAL_DEV_PASSWORD`] so the
//! test flow is a copy-paste. This value is documented in the CLI help
//! output; the password is dev-only and never touches production.

use anyhow::{anyhow, Context};
use sqlx::PgPool;
use uuid::Uuid;

/// The dev password every seeded portal contact carries. Baked into the
/// seed output so the developer sees exactly what to type on the login
/// page. Long-random-ish but memorable enough to hand-type.
pub const PORTAL_DEV_PASSWORD: &str = "portal-dev-password-1234";

/// The dev password every seeded agent user carries. Same posture as
/// [`PORTAL_DEV_PASSWORD`]: dev-only, printed in the seed summary so a
/// developer can sign into the agent panel of the fixture tenant and
/// exercise the "grant portal access" flow (MAPPS-396). The agent panel
/// mints a `/portal/set-password?token=...` email through the tenant's
/// own `auth.welcome` template, so both halves have to exist for the
/// end-to-end wire to reach mailpit.
pub const AGENT_DEV_PASSWORD: &str = "agent-dev-password-1234";

/// The default tenant that migration 023 seeds. The dev-portal seed
/// copies its `notification_templates` + `notification_rules` into every
/// new fixture tenant so `auth.welcome` (the setup-link email) has a
/// row to render from; without this, the dispatcher silently drops the
/// send and no mail ever lands in mailpit.
const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

/// Which transactional event types the dev-portal seed copies from the
/// default tenant. Matches the set `TenantService::copy_default_config`
/// copies for real tenant provisioning so a fixture tenant's mail set
/// looks the same as a first-run production one.
const SEEDED_EVENT_TYPES: &[&str] = &[
    "appointment.reminder",
    "sla.at_risk",
    "sla.breached",
    "auth.password_reset",
    "auth.welcome",
    "forms.request_link",
];

/// One line of the seed's stdout summary. Groups the tenant's slug with
/// the URLs the developer needs to hit.
pub struct PortalDevSeedRow {
    pub slug: String,
    pub display_name: String,
    pub status: String,
    pub email: String,
    /// The agent-panel login email, or `None` for tenants where the
    /// seed skips agent-user provisioning (currently only `inact`,
    /// which is fixture-inactive on purpose).
    pub agent_email: Option<String>,
}

pub struct PortalDevSeedReport {
    pub rows: Vec<PortalDevSeedRow>,
    /// `true` if any row was newly inserted; `false` on a fully-idempotent
    /// re-run (every slug already existed).
    pub inserted: bool,
}

impl std::fmt::Display for PortalDevSeedReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Seeded {} portal tenants ({}):",
            self.rows.len(),
            if self.inserted {
                "new writes"
            } else {
                "already present"
            }
        )?;
        writeln!(f)?;
        writeln!(
            f,
            "Portal contact password (all seeded contacts): {PORTAL_DEV_PASSWORD}"
        )?;
        writeln!(
            f,
            "Agent user password  (all seeded agent users):  {AGENT_DEV_PASSWORD}"
        )?;
        writeln!(f)?;
        for row in &self.rows {
            writeln!(
                f,
                "  {slug:<7}  {name:<20}  status={status}  portal={email}",
                slug = row.slug,
                name = row.display_name,
                status = row.status,
                email = row.email,
            )?;
            if let Some(ref agent) = row.agent_email {
                writeln!(
                    f,
                    "  {slug:<7}  {pad:<20}  {status:<15}  agent={agent}",
                    slug = "",
                    pad = "",
                    status = "",
                    agent = agent,
                )?;
            }
        }
        writeln!(f)?;
        writeln!(f, "Try these URLs (browser or curl) after `just dev`:")?;
        writeln!(f, "  # Happy path (active, branded)")?;
        writeln!(f, "  http://acme.client.localhost:4301/portal/login")?;
        writeln!(f, "  # Active, no branding - generic wordmark")?;
        writeln!(f, "  http://beta.client.localhost:4301/portal/login")?;
        writeln!(f, "  # Inactive - fail-closed 401 / 404 on /portal/host")?;
        writeln!(f, "  http://inact.client.localhost:4301/portal/login")?;
        writeln!(
            f,
            "  # Unknown slug - fail-closed 401 / 404 on /portal/host"
        )?;
        writeln!(f, "  http://nope.client.localhost:4301/portal/login")?;
        Ok(())
    }
}

/// Refuse to run outside dev/test.
fn require_dev_environment() -> anyhow::Result<()> {
    let env = std::env::var("ENVIRONMENT")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|_| "development".to_string());
    match env.as_str() {
        "development" | "dev" | "test" => Ok(()),
        other => Err(anyhow!(
            "portal-dev-seed refuses to run outside dev/test (ENVIRONMENT={other}). \
             This fixture is not for production; there is no override flag."
        )),
    }
}

/// Insert the fixture set. Idempotent: skips any slug that already
/// exists, only reporting the row set that resulted. The returned
/// `inserted` flag distinguishes a first-run from a repeat run.
pub async fn portal_dev_seed(pool: &PgPool) -> anyhow::Result<PortalDevSeedReport> {
    require_dev_environment()?;

    let mut rows = Vec::new();
    let mut inserted = false;

    for spec in fixture_specs() {
        let tenant_id = upsert_tenant(pool, &spec, &mut inserted)
            .await
            .with_context(|| format!("seed tenant '{}'", spec.slug))?;
        // MAPPS-396: copy the default tenant's notification templates +
        // rules into the fixture tenant so `auth.welcome` (the setup-link
        // email) has a row to render from. Without this, the dispatcher
        // silently drops the send and no mail lands in mailpit, which
        // read as "grant portal access does nothing" during dev testing.
        copy_notification_templates(pool, tenant_id)
            .await
            .with_context(|| format!("seed notification templates for tenant '{}'", spec.slug))?;
        let company_id = upsert_company(pool, tenant_id, &spec, &mut inserted)
            .await
            .with_context(|| format!("seed company for tenant '{}'", spec.slug))?;
        upsert_portal_contact(pool, tenant_id, company_id, &spec, &mut inserted)
            .await
            .with_context(|| format!("seed portal contact for tenant '{}'", spec.slug))?;
        // MAPPS-396: an agent user under the fixture tenant so a dev can
        // actually sign into the agent panel and click "Grant portal
        // access" on a contact. Skipped for suspended tenants (they
        // exercise the fail-closed path on purpose).
        let agent_email = if let Some(ref email) = spec.agent_email {
            upsert_agent_user(pool, tenant_id, spec.slug, email, &mut inserted)
                .await
                .with_context(|| format!("seed agent user for tenant '{}'", spec.slug))?;
            Some(email.to_string())
        } else {
            None
        };
        rows.push(PortalDevSeedRow {
            slug: spec.slug.to_string(),
            display_name: spec.display_name.to_string(),
            status: spec.status.to_string(),
            email: spec.contact_email.to_string(),
            agent_email,
        });
    }

    Ok(PortalDevSeedReport { rows, inserted })
}

struct FixtureSpec {
    slug: &'static str,
    display_name: &'static str,
    status: &'static str,
    branding: serde_json::Value,
    company_name: &'static str,
    contact_email: &'static str,
    contact_first: &'static str,
    contact_last: &'static str,
    /// Agent-panel login for this tenant. `None` skips agent-user
    /// provisioning (currently only `inact`, which is fixture-inactive
    /// on purpose so signing in there is not a supported flow).
    agent_email: Option<&'static str>,
}

fn fixture_specs() -> Vec<FixtureSpec> {
    vec![
        FixtureSpec {
            slug: "acme",
            display_name: "Acme MSP",
            status: "active",
            // PMS-729 phase 2 §6: full branding surface so a dev flow
            // exercises every field the SPA reads (logo, primary
            // color, support contact, welcome copy, footer). Logo +
            // favicon use data-URIs so the seed does not depend on
            // any external CDN or served asset in the dev SPA image.
            branding: serde_json::json!({
                "logo_url": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 80 20'><rect width='80' height='20' fill='%233b82f6'/><text x='40' y='14' font-size='11' text-anchor='middle' fill='white' font-family='sans-serif'>ACME</text></svg>",
                "favicon_url": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><rect width='16' height='16' fill='%233b82f6'/><text x='8' y='12' font-size='10' text-anchor='middle' fill='white' font-family='sans-serif'>A</text></svg>",
                "primary_color": "#2563eb",
                "primary_color_dark": "#60a5fa",
                "support_email": "help@acme.example",
                "support_phone": "+1 555 0100",
                "support_hours": "Mon-Fri 9am-5pm ET",
                "footer_text": "Powered by Acme MSP",
                "welcome_message": "Welcome to Acme's client portal"
            }),
            company_name: "Acme Widgets Inc.",
            contact_email: "portal-user@acme.example",
            contact_first: "Acme",
            contact_last: "Portal",
            agent_email: Some("agent@acme.example"),
        },
        FixtureSpec {
            slug: "beta",
            display_name: "Beta MSP",
            status: "active",
            branding: serde_json::json!({}),
            company_name: "Beta Industries",
            contact_email: "portal-user@beta.example",
            contact_first: "Beta",
            contact_last: "Portal",
            agent_email: Some("agent@beta.example"),
        },
        FixtureSpec {
            slug: "inact",
            display_name: "Inactive MSP",
            status: "suspended",
            branding: serde_json::json!({}),
            company_name: "Inactive Co.",
            contact_email: "portal-user@inact.example",
            contact_first: "Inactive",
            contact_last: "Portal",
            agent_email: None,
        },
    ]
}

/// Insert a tenant row, returning its id. If a row with this slug
/// already exists, return that row's id and leave `inserted` alone.
async fn upsert_tenant(
    pool: &PgPool,
    spec: &FixtureSpec,
    inserted: &mut bool,
) -> anyhow::Result<Uuid> {
    let new_id = Uuid::new_v4();
    // `RETURNING` on ON CONFLICT DO NOTHING returns zero rows when the row
    // already existed, so fall back to a SELECT for the id. Kept in two
    // statements for readability; both hit the covered `idx_tenants_slug`.
    let inserted_row: Option<(Uuid,)> = sqlx::query_as(
        r#"
        INSERT INTO tenants (id, name, slug, status, kind, branding)
        VALUES ($1, $2, $3, $4, 'org', $5)
        ON CONFLICT (slug) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(new_id)
    .bind(spec.display_name)
    .bind(spec.slug)
    .bind(spec.status)
    .bind(&spec.branding)
    .fetch_optional(pool)
    .await?;

    if let Some((id,)) = inserted_row {
        *inserted = true;
        return Ok(id);
    }

    let (existing,): (Uuid,) = sqlx::query_as("SELECT id FROM tenants WHERE slug = $1")
        .bind(spec.slug)
        .fetch_one(pool)
        .await?;
    Ok(existing)
}

/// Insert a company under the tenant, keyed by (tenant_id, name) to stay
/// idempotent (there is no natural unique index on `companies.name`, so a
/// pre-check SELECT is the cheapest correct posture).
async fn upsert_company(
    pool: &PgPool,
    tenant_id: Uuid,
    spec: &FixtureSpec,
    inserted: &mut bool,
) -> anyhow::Result<Uuid> {
    if let Some((id,)) =
        sqlx::query_as::<_, (Uuid,)>("SELECT id FROM companies WHERE tenant_id = $1 AND name = $2")
            .bind(tenant_id)
            .bind(spec.company_name)
            .fetch_optional(pool)
            .await?
    {
        return Ok(id);
    }

    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, tenant_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(tenant_id)
        .bind(spec.company_name)
        .execute(pool)
        .await?;
    *inserted = true;
    Ok(id)
}

/// Copy the default tenant's notification templates + rules for the
/// transactional event types the portal + agent flows dispatch through.
/// Mirrors `TenantService::copy_default_config` so a fixture tenant's
/// mail set matches a production one seeded through the CRUD API.
///
/// Idempotent: presence of any template row on the target tenant is
/// treated as "already seeded" and the copy skips. This means editing
/// the source templates on the default tenant after a first run does
/// not clobber the fixture copies (matches the "migrations never
/// clobber operator edits" contract from migration 096).
async fn copy_notification_templates(pool: &PgPool, tenant_id: Uuid) -> anyhow::Result<()> {
    if tenant_id == DEFAULT_TENANT_ID {
        return Ok(());
    }
    let existing: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM notification_templates WHERE tenant_id = $1)",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;
    if existing {
        return Ok(());
    }

    sqlx::query(
        r#"
        INSERT INTO notification_templates
            (tenant_id, name, event_type, channel_type, subject, body_text, body_html, is_active)
        SELECT $1, name, event_type, channel_type, subject, body_text, body_html, is_active
        FROM notification_templates
        WHERE tenant_id = $2 AND event_type = ANY($3)
        "#,
    )
    .bind(tenant_id)
    .bind(DEFAULT_TENANT_ID)
    .bind(SEEDED_EVENT_TYPES)
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO notification_rules
            (tenant_id, name, event_type, channels, recipients, template_id, is_active)
        SELECT $1, r.name, r.event_type, r.channels, r.recipients, nt.id, r.is_active
        FROM notification_rules r
        JOIN notification_templates ot
          ON ot.id = r.template_id AND ot.tenant_id = $2
        JOIN notification_templates nt
          ON nt.tenant_id = $1
         AND nt.event_type = ot.event_type
         AND nt.channel_type = ot.channel_type
        WHERE r.tenant_id = $2 AND r.event_type = ANY($3)
        "#,
    )
    .bind(tenant_id)
    .bind(DEFAULT_TENANT_ID)
    .bind(SEEDED_EVENT_TYPES)
    .execute(pool)
    .await?;

    Ok(())
}

/// Insert an agent user (role `admin`) under the fixture tenant so a
/// developer can sign into the agent panel of that tenant and click
/// "Grant portal access" on a contact. Keyed by (tenant_id, email) so
/// re-running is idempotent and does NOT reset an existing password.
async fn upsert_agent_user(
    pool: &PgPool,
    tenant_id: Uuid,
    slug: &str,
    email: &str,
    inserted: &mut bool,
) -> anyhow::Result<()> {
    let already: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE tenant_id = $1 AND email = $2")
            .bind(tenant_id)
            .bind(email)
            .fetch_optional(pool)
            .await?;
    if already.is_some() {
        return Ok(());
    }

    let hash = crate::utils::crypto::hash_password(AGENT_DEV_PASSWORD)
        .map_err(|e| anyhow!("hash agent seed password: {e}"))?;
    let (first_name, last_name) = derive_agent_name(slug);
    sqlx::query(
        r#"
        INSERT INTO users (
            id, tenant_id, email, password_hash,
            first_name, last_name, role, status, email_verified_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'admin', 'active', NOW())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(email)
    .bind(&hash)
    .bind(&first_name)
    .bind(&last_name)
    .execute(pool)
    .await?;
    *inserted = true;
    Ok(())
}

/// Turn the tenant slug into a display first/last name for the seeded
/// agent user. `acme` -> ("Acme", "Agent"). Keeps the seed output
/// readable in the agent-panel user list.
fn derive_agent_name(slug: &str) -> (String, String) {
    let capitalized = slug
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase().to_string() + &slug[1..])
        .unwrap_or_else(|| "Fixture".to_string());
    (capitalized, "Agent".to_string())
}

/// Insert a portal-enabled contact under the tenant + company. Keyed by
/// `(tenant_id, email)` so re-running does not create duplicates but
/// also does NOT rehash / reset an existing dev password.
async fn upsert_portal_contact(
    pool: &PgPool,
    tenant_id: Uuid,
    company_id: Uuid,
    spec: &FixtureSpec,
    inserted: &mut bool,
) -> anyhow::Result<()> {
    let already: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM contacts WHERE tenant_id = $1 AND email = $2")
            .bind(tenant_id)
            .bind(spec.contact_email)
            .fetch_optional(pool)
            .await?;
    if already.is_some() {
        return Ok(());
    }

    let hash = crate::utils::crypto::hash_password(PORTAL_DEV_PASSWORD)
        .map_err(|e| anyhow!("hash portal seed password: {e}"))?;
    sqlx::query(
        r#"
        INSERT INTO contacts (
            id, tenant_id, company_id, first_name, last_name, email,
            is_portal_user, portal_password_hash
        )
        VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(company_id)
    .bind(spec.contact_first)
    .bind(spec.contact_last)
    .bind(spec.contact_email)
    .bind(&hash)
    .execute(pool)
    .await?;
    *inserted = true;
    Ok(())
}
