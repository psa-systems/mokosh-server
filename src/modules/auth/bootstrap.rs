//! First-run admin bootstrap from environment variables.
//!
//! Mirrors the `ADMIN_EMAIL` / `ADMIN_PASSWORD` pattern documented in
//! `.env.example`. When both are set AND the database has zero user
//! accounts, an admin user is created under the default tenant. Once
//! any user exists these vars are ignored on subsequent startups, so
//! there is no risk of overwriting an admin password by leaving the
//! env vars in place.
//!
//! DEV ONLY. Production deployments should provision the first admin
//! through a real workflow (signup form, IaC, or manual SQL) rather
//! than environment variables.

use uuid::Uuid;

use crate::db::Database;
use crate::utils::crypto::hash_password;
use crate::utils::error::AppResult;

pub async fn maybe_bootstrap_admin(db: &Database) -> AppResult<()> {
    let (email, password) = match (
        std::env::var("ADMIN_EMAIL").ok(),
        std::env::var("ADMIN_PASSWORD").ok(),
    ) {
        (Some(e), Some(p)) if !e.trim().is_empty() && !p.is_empty() => (e, p),
        _ => return Ok(()),
    };

    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db.pool())
        .await?;

    if user_count > 0 {
        tracing::info!(
            users = user_count,
            "ADMIN_EMAIL/ADMIN_PASSWORD set but users already exist; skipping bootstrap"
        );
        return Ok(());
    }

    let default_tenant_id = Uuid::from_u128(1);
    let email = email.trim().to_ascii_lowercase();
    let password_hash = hash_password(&password)?;
    let user_id = Uuid::new_v4();
    let (first_name, last_name) = derive_name(&email);

    sqlx::query(
        r#"
        INSERT INTO users (
            id, tenant_id, email, password_hash,
            first_name, last_name, role, status, email_verified_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'super_admin', 'active', NOW())
        "#,
    )
    .bind(user_id)
    .bind(default_tenant_id)
    .bind(&email)
    .bind(&password_hash)
    .bind(&first_name)
    .bind(&last_name)
    .execute(db.pool())
    .await?;

    tracing::warn!(
        user_id = %user_id,
        email = %email,
        "bootstrapped admin user from ADMIN_EMAIL/ADMIN_PASSWORD (DEV ONLY; do not use in production)"
    );

    Ok(())
}

fn derive_name(email: &str) -> (String, String) {
    let local = email.split('@').next().unwrap_or("");
    let parts: Vec<String> = local
        .split(|c: char| c == '.' || c == '_' || c == '-' || c == '+')
        .filter(|s| !s.is_empty())
        .map(capitalize)
        .collect();

    match parts.as_slice() {
        [] => ("Admin".to_string(), "User".to_string()),
        [first] => (first.clone(), "Admin".to_string()),
        [first, rest @ ..] => (first.clone(), rest.join(" ")),
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_name_simple() {
        assert_eq!(derive_name("admin@example.com"), ("Admin".into(), "Admin".into()));
    }

    #[test]
    fn derive_name_dotted() {
        assert_eq!(derive_name("jane.doe@example.com"), ("Jane".into(), "Doe".into()));
    }

    #[test]
    fn derive_name_multipart() {
        assert_eq!(
            derive_name("john.q.public@example.com"),
            ("John".into(), "Q Public".into())
        );
    }

    #[test]
    fn derive_name_empty() {
        assert_eq!(derive_name("@example.com"), ("Admin".into(), "User".into()));
    }
}
