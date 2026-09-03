//! How this instance is deployed, and what that changes (PMS-902).
//!
//! Mokosh runs in two shapes. A **self-hosted** instance owns its platform
//! identities: `users` rows with `password_hash`, the `/auth/*` local login,
//! and the account email that supports it (password reset, welcome). A
//! **SaaS** instance federates platform identity to Bunyip: the SPA runs the
//! PKCE flow against bunyip-api and mokosh is only a Resource Server for the
//! resulting `at+jwt` (`src/modules/auth/oidc_rs.rs`). There, a mokosh-side
//! password is not the credential anybody signs in with, so mail whose only
//! job is to service that password is mail about an account nobody uses.
//!
//! What this flag does NOT cover:
//!
//! - **Portal identity.** PMS-820 keeps `contacts.portal_password_hash` and
//!   `PortalAuthService` on a plane of their own, and that plane is not
//!   federated through Bunyip in either mode, so portal mail is unaffected.
//! - **Business notifications.** A quote, invoice, ticket, appointment or SLA
//!   email is about work, not about an account, and sends in both modes.
//! - **Whether the local endpoints still answer.** This gates dispatch only.
//!   `/auth/login`'s password branch and `/auth/forgot-password` still exist
//!   in `saas`; restricting them is PMS-905.
//!
//! PMS-903 will read the same flag to pick mail TRANSPORT (Bunyip's shared
//! mailer API instead of direct SMTP). This module deliberately carries no
//! transport knowledge: the two questions are independent, and PMS-903 landing
//! must not need to revisit anything here.

use std::fmt;

/// The deployment shape, from `MOKOSH_DEPLOYMENT_MODE`.
///
/// `self-hosted` is the default, and an unset or unrecognised value resolves
/// to it. That direction is deliberate: the failure this ordering protects
/// against is a self-hosted operator's password-reset mail silently not
/// sending because of a typo in an env var, which presents as "the product is
/// broken and nothing says why". The opposite mistake - a SaaS instance
/// sending a reset mail it did not need to - is a redundant email, not a
/// lockout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeploymentMode {
    /// This instance owns its platform identities and its own mail.
    #[default]
    SelfHosted,
    /// Platform identity is federated to Bunyip SSO.
    Saas,
}

impl DeploymentMode {
    /// Read `MOKOSH_DEPLOYMENT_MODE`.
    ///
    /// Not a `FromStr` returning `Err`, because there is no caller that could
    /// do anything useful with a failure: boot has to continue, and the safe
    /// continuation is the self-hosted default. An unrecognised value is
    /// logged at `warn` so a typo is visible in the log rather than only in
    /// the absence of email a week later.
    pub fn from_env() -> Self {
        match std::env::var("MOKOSH_DEPLOYMENT_MODE") {
            Ok(raw) => Self::parse(&raw),
            Err(_) => Self::SelfHosted,
        }
    }

    /// The pure half of [`from_env`](Self::from_env), so the vocabulary is
    /// testable without touching the process environment.
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            // An empty value is what a forwarded-but-unset compose key looks
            // like (PMS-836), so it means "not configured", not "invalid".
            "" | "self-hosted" | "self_hosted" | "selfhosted" => Self::SelfHosted,
            "saas" => Self::Saas,
            other => {
                tracing::warn!(
                    value = %other,
                    "unrecognised MOKOSH_DEPLOYMENT_MODE; falling back to self-hosted. \
                     Valid values are `self-hosted` and `saas`",
                );
                Self::SelfHosted
            }
        }
    }

    /// Whether platform identity is federated, i.e. whether a mokosh-side
    /// password is something anybody signs in with.
    ///
    /// Read this rather than matching on the variant at call sites: it is the
    /// question every gate is actually asking, and a third mode later would
    /// otherwise have to be added to every `match`.
    pub fn is_saas(self) -> bool {
        matches!(self, Self::Saas)
    }
}

impl fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SelfHosted => "self-hosted",
            Self::Saas => "saas",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_self_hosted() {
        assert_eq!(DeploymentMode::default(), DeploymentMode::SelfHosted);
        assert!(!DeploymentMode::default().is_saas());
    }

    #[test]
    fn saas_is_recognised_however_it_is_cased_or_padded() {
        for raw in ["saas", "SaaS", "SAAS", "  saas  "] {
            assert_eq!(DeploymentMode::parse(raw), DeploymentMode::Saas, "{raw:?}");
        }
    }

    #[test]
    fn the_self_hosted_spellings_all_resolve() {
        for raw in ["self-hosted", "self_hosted", "selfhosted", "SELF-HOSTED"] {
            assert_eq!(
                DeploymentMode::parse(raw),
                DeploymentMode::SelfHosted,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn an_empty_value_is_not_configured_rather_than_invalid() {
        // PMS-836: compose forwards every declared key, so a variable the
        // operator left blank arrives as `""` rather than absent. Treating
        // that as a bad value would log a warning on every boot of a stack
        // that is simply not using the flag.
        assert_eq!(DeploymentMode::parse(""), DeploymentMode::SelfHosted);
        assert_eq!(DeploymentMode::parse("   "), DeploymentMode::SelfHosted);
    }

    #[test]
    fn an_unrecognised_value_falls_back_to_self_hosted_not_saas() {
        // The asymmetry is the point. Falling back to `saas` on a typo would
        // silently stop a self-hosted deployment's password-reset mail, which
        // presents to the operator as a broken product with no error anywhere.
        // Falling back to `self-hosted` costs a SaaS instance a redundant
        // email at worst.
        for raw in ["cloud", "hosted", "sass", "true"] {
            assert_eq!(
                DeploymentMode::parse(raw),
                DeploymentMode::SelfHosted,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn the_display_form_round_trips_through_parse() {
        for mode in [DeploymentMode::SelfHosted, DeploymentMode::Saas] {
            assert_eq!(DeploymentMode::parse(&mode.to_string()), mode);
        }
    }
}
