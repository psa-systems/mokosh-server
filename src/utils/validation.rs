//! Custom validation utilities

use regex::Regex;
use std::sync::LazyLock;
use validator::ValidationError;

// Regex patterns
static EMAIL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

static PHONE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\+?[1-9]\d{1,14}$").unwrap());

static SLUG_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").unwrap());

/// Validate an email address
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if EMAIL_REGEX.is_match(email) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_email"))
    }
}

/// Validate a phone number (E.164 format)
pub fn validate_phone(phone: &str) -> Result<(), ValidationError> {
    if phone.is_empty() || PHONE_REGEX.is_match(phone) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_phone"))
    }
}

/// Validate a URL slug
pub fn validate_slug(slug: &str) -> Result<(), ValidationError> {
    if SLUG_REGEX.is_match(slug) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_slug"))
    }
}

/// Validate password strength
pub fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    let mut errors = Vec::new();

    if password.len() < 8 {
        errors.push("at least 8 characters");
    }
    if password.len() > 128 {
        errors.push("no more than 128 characters");
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        errors.push("a lowercase letter");
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        errors.push("an uppercase letter");
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        errors.push("a number");
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        errors.push("a special character");
    }

    if errors.is_empty() {
        Ok(())
    } else {
        let mut error = ValidationError::new("weak_password");
        error.message = Some(format!("Password must contain: {}", errors.join(", ")).into());
        Err(error)
    }
}

/// Validate a CRON expression
pub fn validate_cron(expr: &str) -> Result<(), ValidationError> {
    match cron::Schedule::try_from(expr) {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::new("invalid_cron")),
    }
}

/// Generate a slug from a string
pub fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<&str>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email() {
        assert!(validate_email("test@example.com").is_ok());
        assert!(validate_email("user.name+tag@domain.co.uk").is_ok());
        assert!(validate_email("invalid").is_err());
        assert!(validate_email("@example.com").is_err());
    }

    #[test]
    fn test_validate_phone() {
        assert!(validate_phone("+14155551234").is_ok());
        assert!(validate_phone("14155551234").is_ok());
        assert!(validate_phone("").is_ok()); // Empty is allowed
        assert!(validate_phone("abc123").is_err());
    }

    #[test]
    fn test_validate_slug() {
        assert!(validate_slug("hello-world").is_ok());
        assert!(validate_slug("hello123").is_ok());
        assert!(validate_slug("HELLO").is_err());
        assert!(validate_slug("hello_world").is_err());
    }

    #[test]
    fn test_validate_password_strength() {
        assert!(validate_password_strength("Str0ng@Pass!").is_ok());
        assert!(validate_password_strength("weak").is_err());
        assert!(validate_password_strength("NoNumber!").is_err());
    }

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("Hello World!"), "hello-world");
        assert_eq!(slugify("  Multiple   Spaces  "), "multiple-spaces");
        assert_eq!(slugify("Special@#Characters"), "special-characters");
    }
}
