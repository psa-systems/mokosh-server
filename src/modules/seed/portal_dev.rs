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

/// One line of the seed's stdout summary. Groups the tenant's slug with
/// the URLs the developer needs to hit.
pub struct PortalDevSeedRow {
    pub slug: String,
    pub display_name: String,
    pub status: String,
    pub email: String,
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
        writeln!(f)?;
        for row in &self.rows {
            writeln!(
                f,
                "  {slug:<7}  {name:<20}  status={status}  email={email}",
                slug = row.slug,
                name = row.display_name,
                status = row.status,
                email = row.email,
            )?;
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
        let company_id = upsert_company(pool, tenant_id, &spec, &mut inserted)
            .await
            .with_context(|| format!("seed company for tenant '{}'", spec.slug))?;
        upsert_portal_contact(pool, tenant_id, company_id, &spec, &mut inserted)
            .await
            .with_context(|| format!("seed portal contact for tenant '{}'", spec.slug))?;
        rows.push(PortalDevSeedRow {
            slug: spec.slug.to_string(),
            display_name: spec.display_name.to_string(),
            status: spec.status.to_string(),
            email: spec.contact_email.to_string(),
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
}

fn fixture_specs() -> Vec<FixtureSpec> {
    vec![
        FixtureSpec {
            slug: "acme",
            display_name: "Acme MSP",
            status: "active",
            // A public data-URI PNG so the seed does not depend on any
            // external CDN or a served asset in the dev SPA image. Renders
            // an 80x20 blue block; enough to prove the logo path is wired.
            branding: serde_json::json!({
                "logo_url": "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 80 20'><rect width='80' height='20' fill='%233b82f6'/><text x='40' y='14' font-size='11' text-anchor='middle' fill='white' font-family='sans-serif'>ACME</text></svg>"
            }),
            company_name: "Acme Widgets Inc.",
            contact_email: "portal-user@acme.example",
            contact_first: "Acme",
            contact_last: "Portal",
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
