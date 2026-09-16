//! PMS-1213 (PSA-70 D): how two records are compared.
//!
//! These functions decide whether a Google contact is the same person as a
//! Mokosh contact, so every rule is stated here once and pinned by a test.
//! They produce MATCH KEYS, never stored values: plus-addressing is stripped
//! for comparison only, and nothing here rewrites what a contact holds.
//!
//! The rules, exactly:
//!
//! * **Email**: Unicode-aware lowercase, surrounding whitespace trimmed, and a
//!   `+tag` stripped from the local part (`ops+billing@acme.example` compares
//!   equal to `ops@acme.example`). Dots in the local part are NOT removed:
//!   that equivalence is Gmail's alone, and applying it to a company domain
//!   would merge two different mailboxes. An address without exactly one `@`
//!   has no key and matches nothing.
//! * **Phone**: formatting removed; a leading `+` or `00` makes it E.164 (`+`
//!   and digits); anything else stays digits-only. A national number without a
//!   country code is never guessed into one. Fewer than seven digits has no
//!   key, because a short number (an extension, a PBX code) matches far too
//!   much. Phone matches only ever QUEUE for review (PSA-70 D), so a number
//!   compared digits-only costs a question, never a merge.
//! * **Name**: Unicode lowercase, internal whitespace collapsed, trimmed.
//!   Script is preserved - `Иван Петров` is a valid key - and a name is never
//!   a match on its own.

/// The comparison key for an email address, or `None` when it has none.
pub fn email_key(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_lowercase();
    let (local, domain) = trimmed.split_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return None;
    }
    let local = local.split('+').next().unwrap_or(local);
    if local.is_empty() {
        return None;
    }
    Some(format!("{local}@{domain}"))
}

/// The comparison key for a phone number, or `None` when it has none.
pub fn phone_key(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let international = trimmed.starts_with('+') || trimmed.starts_with("00");
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    let digits = if trimmed.starts_with("00") {
        digits.strip_prefix("00").unwrap_or(&digits).to_string()
    } else {
        digits
    };
    if digits.len() < 7 {
        return None;
    }
    Some(if international {
        format!("+{digits}")
    } else {
        digits
    })
}

/// The comparison key for a person's or company's name.
pub fn name_key(raw: &str) -> Option<String> {
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let key = collapsed.to_lowercase();
    (!key.is_empty()).then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_lowercased_trimmed_and_loses_its_plus_tag() {
        assert_eq!(
            email_key("  Ops+Billing@Acme.Example "),
            Some("ops@acme.example".into())
        );
        assert_eq!(
            email_key("ops@acme.example"),
            Some("ops@acme.example".into())
        );
    }

    /// Dots are the local part's own business. Removing them is a Gmail rule,
    /// and applied to a company domain it would merge two real mailboxes.
    #[test]
    fn email_dots_are_kept() {
        assert_ne!(
            email_key("j.smith@acme.example"),
            email_key("jsmith@acme.example")
        );
    }

    #[test]
    fn a_malformed_email_has_no_key() {
        for bad in [
            "",
            "   ",
            "no-at-sign",
            "@acme.example",
            "ops@",
            "a@b@c",
            "+tag@acme.example",
        ] {
            assert_eq!(email_key(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_unicode_email_lowercases_by_unicode_rules() {
        assert_eq!(
            email_key("ÉLODIE@Exemple.FR"),
            Some("élodie@exemple.fr".into())
        );
    }

    #[test]
    fn an_international_phone_becomes_e164() {
        assert_eq!(phone_key("+1 (415) 555-1234"), Some("+14155551234".into()));
        assert_eq!(phone_key("0044 20 7946 0958"), Some("+442079460958".into()));
    }

    /// A national number is never guessed into a country.
    #[test]
    fn a_national_phone_stays_digits_only() {
        assert_eq!(phone_key("(415) 555-1234"), Some("4155551234".into()));
        assert_ne!(phone_key("(415) 555-1234"), phone_key("+1 415 555 1234"));
    }

    #[test]
    fn a_short_number_has_no_key() {
        for short in ["", "123", "x204", "555 12"] {
            assert_eq!(phone_key(short), None, "{short:?}");
        }
    }

    #[test]
    fn names_keep_their_script_and_collapse_their_whitespace() {
        assert_eq!(name_key("  Иван   Петров "), Some("иван петров".into()));
        assert_eq!(name_key("李 小龙"), Some("李 小龙".into()));
        assert_eq!(name_key("Björk"), Some("björk".into()));
        assert_eq!(name_key("   "), None);
    }
}
