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

/// Sanitize HTML content to prevent XSS
pub fn sanitize_html(html: &str) -> String {
    // Basic HTML entity encoding for XSS prevention
    html.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Truncate a string to a maximum length, adding ellipsis if needed.
///
/// `max_len` is a byte budget. Slicing at an arbitrary byte index panics when
/// it lands inside a multi-byte UTF-8 sequence, so the cut point is snapped
/// back to the nearest char boundary via `char_indices` before slicing.
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    // Reserve 3 bytes for the "..." suffix, then find the last char boundary
    // at or before that byte budget so the slice never splits a code point.
    let budget = max_len.saturating_sub(3);
    let cut = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= budget)
        .last()
        .unwrap_or(0);
    format!("{}...", &s[..cut])
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

    #[test]
    fn test_sanitize_html() {
        assert_eq!(sanitize_html("<script>"), "&lt;script&gt;");
        assert_eq!(sanitize_html("\"test\""), "&quot;test&quot;");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("Hello", 10), "Hello");
        assert_eq!(truncate("Hello World", 8), "Hello...");
    }

    #[test]
    fn test_truncate_multibyte_no_panic() {
        // PMS-196: 'ñ' is two bytes, so an odd byte budget lands inside a code
        // point. The old byte-slice (`&s[..n]`) panicked here.
        // "ñññññ" is 10 bytes / 5 chars; budget 5 snaps back to byte 4.
        let s = "ñññññ";
        assert_eq!(truncate(s, 8), "ññ...");
        // 4-byte code points (emoji) must also be safe.
        assert_eq!(truncate("😀😀😀", 8), "😀...");
    }
}
