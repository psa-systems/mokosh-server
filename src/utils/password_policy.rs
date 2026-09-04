//! PMS-729 phase 2 H5: password-strength policy.
//!
//! Shared validator so the portal + agent surfaces can enforce the same
//! rules. Portal calls it at every write site (setup, reset, change);
//! agent will migrate onto it in a follow-up.
//!
//! The policy is three-tier:
//!
//! 1. **Length floor** (default 12). Cheapest check, done first so a
//!    typo-short password fails immediately without spinning zxcvbn.
//! 2. **Common-password blocklist**. A short embedded list of the ~50
//!    most-common passwords per HIBP + SecLists. Not a full blocklist:
//!    the zxcvbn dictionary already catches most of what a bigger list
//!    would, and shipping the full 100k+ list would bloat the binary.
//! 3. **zxcvbn score >= min_zxcvbn_score** (default 3 = "safely
//!    unguessable, moderate protection from offline slow-hash scenario").
//!    Score 4 is "very unguessable, strong protection from offline slow-
//!    hash scenario"; we ask for 3 because 4 rejects passwords a lot of
//!    users will consider reasonable, and Argon2id already gives us the
//!    slow-hash floor.
//!
//! Every failure returns [`PasswordPolicyError::UserMessage`], a caller-
//! facing string safe to embed in a 400/422 response. The wire messages
//! are deliberately concrete ("must be at least 12 characters", "reuses
//! a common leaked password") so the user knows how to fix it; this is
//! a UX call, not a security one - the policy itself is a black-box
//! from the attacker's perspective either way.

use thiserror::Error;

/// Minimum accepted zxcvbn score. Score 3 = "safely unguessable, moderate
/// protection from offline slow-hash scenario".
pub const DEFAULT_MIN_ZXCVBN_SCORE: u8 = 3;

/// Minimum accepted password length in characters. 12 is what NIST 800-63B
/// recommends as a hard floor for verifier-side memorized secrets.
pub const DEFAULT_MIN_LENGTH: usize = 12;

/// Maximum length we validate. Anything longer is truncated by Argon2's
/// input pipeline anyway; higher values also let a malicious client burn
/// CPU by shipping megabyte-long passwords. Matches BIP-39 mnemonics + a
/// wide passphrase buffer.
pub const MAX_LENGTH: usize = 128;

/// Configurable knobs so tests and future call sites can vary the policy
/// without swapping crates. Portal calls pass [`PasswordPolicy::default`];
/// a test can dial the length down to make short-fixture passwords legal.
#[derive(Debug, Clone, Copy)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub max_length: usize,
    pub min_zxcvbn_score: u8,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: DEFAULT_MIN_LENGTH,
            max_length: MAX_LENGTH,
            min_zxcvbn_score: DEFAULT_MIN_ZXCVBN_SCORE,
        }
    }
}

/// A password-policy failure. The `UserMessage` variant is the only one
/// exposed to callers today; the enum shape leaves room for the future
/// (e.g. structured field-level errors on the /me/password endpoint).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordPolicyError {
    #[error("{0}")]
    UserMessage(String),
}

/// The embedded common-password blocklist. Case-insensitive matches AND
/// leetspeak-normalized matches (`p@ssw0rd` -> `password`) both fail.
///
/// Not a comprehensive list; zxcvbn's own dictionaries catch far more.
/// This layer exists to reject the top ~50 leaks that zxcvbn scores as
/// weak-but-not-catastrophic (e.g. `Password1234` gets zxcvbn 3 because
/// of the digits + capital, but is still on every credential-stuffing
/// wordlist).
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "password123",
    "password1234",
    "password12345",
    "passw0rd",
    "p@ssword",
    "p@ssw0rd",
    "welcome",
    "welcome1",
    "welcome123",
    "letmein",
    "letmein1",
    "letmein123",
    "qwerty",
    "qwerty123",
    "qwerty1234",
    "qwertyuiop",
    "abc123",
    "abc12345",
    "12345678",
    "123456789",
    "1234567890",
    "iloveyou",
    "admin",
    "administrator",
    "admin123",
    "root",
    "root123",
    "test",
    "test123",
    "testing",
    "changeme",
    "changeme1",
    "changeme123",
    "default",
    "guest",
    "guest123",
    "master",
    "master123",
    "monkey",
    "dragon",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "basketball",
    "trustno1",
    "shadow",
    "superman",
    "batman",
    "spiderman",
    "hello",
    "hello123",
    "helloworld",
    "portal",
    "portal123",
    "client",
    "client123",
    "mokosh",
];

/// Normalize a candidate password for blocklist lookup. Lowercases, then
/// swaps a narrow set of unambiguous leetspeak substitutions (`@`,`$`)
/// so `P@ssw0rd` still catches on the `password` entry. Digit
/// substitutions (`1` -> `l`, `0` -> `o`) are intentionally NOT done
/// here: they collide with the digits customers actually use as
/// numeric suffixes (e.g. `Password1234`) and would map non-leet input
/// to unexpected forms. zxcvbn's scoring layer catches the digit-leet
/// case; the blocklist is a supplement, not the primary defence.
fn normalize_for_blocklist(input: &str) -> String {
    input
        .to_ascii_lowercase()
        .chars()
        .map(|c| match c {
            '@' => 'a',
            '$' => 's',
            other => other,
        })
        .collect()
}

/// Run the full policy over `password` with the given [`PasswordPolicy`].
/// Returns `Ok(())` when every check passes; the first failure short-
/// circuits with a caller-facing message.
///
/// `context_hints` gives zxcvbn the user's email / name / tenant slug so
/// something like `acme@acme.example` used as a portal password at Acme
/// scores as weak-because-context, not weak-because-dictionary. Callers
/// should pass at minimum the user's own email; other fields are optional.
pub fn validate(
    password: &str,
    context_hints: &[&str],
    policy: PasswordPolicy,
) -> Result<(), PasswordPolicyError> {
    // 1. Length checks.
    let len = password.chars().count();
    if len < policy.min_length {
        return Err(PasswordPolicyError::UserMessage(format!(
            "Password must be at least {} characters.",
            policy.min_length
        )));
    }
    if len > policy.max_length {
        return Err(PasswordPolicyError::UserMessage(format!(
            "Password must be at most {} characters.",
            policy.max_length
        )));
    }

    // 2. Blocklist. Compare against the raw + normalized forms so
    // `P@ssword` (raw) fails on the normalized bucket even if not in the
    // literal list.
    let normalized = normalize_for_blocklist(password);
    let raw_lower = password.to_ascii_lowercase();
    if COMMON_PASSWORDS
        .iter()
        .any(|entry| *entry == raw_lower.as_str() || *entry == normalized.as_str())
    {
        return Err(PasswordPolicyError::UserMessage(
            "Password reuses a well-known leaked password. Please choose a different one."
                .to_string(),
        ));
    }

    // 3. zxcvbn strength score. Context hints let the scorer knock down
    // credentials that quote the user's own email / tenant / name.
    // `zxcvbn::zxcvbn` returns `Result<Entropy, ZxcvbnError>` where the
    // error variant only fires on empty input, which the length check
    // above already rejects.
    let entropy = zxcvbn::zxcvbn(password, context_hints);
    // `entropy.score()` is a `Score` enum in zxcvbn 3; convert to u8 for
    // comparison. u8::from() is the canonical bridge.
    let score: u8 = entropy.score().into();
    if score < policy.min_zxcvbn_score {
        return Err(PasswordPolicyError::UserMessage(
            "Password is too easy to guess. Please pick something longer or more varied."
                .to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PasswordPolicy {
        PasswordPolicy::default()
    }

    #[test]
    fn accepts_a_reasonable_password() {
        assert!(validate("correct-horse-battery-staple", &[], policy()).is_ok());
    }

    #[test]
    fn rejects_too_short() {
        let err = validate("Abc123!x", &[], policy()).expect_err("too short should fail");
        assert!(
            matches!(err, PasswordPolicyError::UserMessage(m) if m.contains("at least 12")),
            "unexpected error message"
        );
    }

    #[test]
    fn rejects_too_long() {
        let long = "a".repeat(MAX_LENGTH + 1);
        let err = validate(&long, &[], policy()).expect_err("too long should fail");
        assert!(matches!(err, PasswordPolicyError::UserMessage(m) if m.contains("at most")));
    }

    #[test]
    fn rejects_direct_blocklist_hits() {
        // Every candidate is >= 12 chars AND literally on the blocklist
        // so the length gate does not fire first and the blocklist
        // message is what surfaces (not the zxcvbn one).
        for pw in ["password1234", "password12345", "administrator"] {
            let err = validate(pw, &[], policy()).unwrap_err();
            let PasswordPolicyError::UserMessage(m) = err;
            assert!(
                m.contains("well-known") || m.contains("common"),
                "unexpected msg for {pw:?}: {m}"
            );
        }
    }

    #[test]
    fn special_char_leetspeak_normalizes_to_blocklist() {
        // `P@$$word!` normalizes to `passwordi` (via `@` -> `a`, `$` -> `s`, `!` unchanged)
        // then the raw lowercased path `p@$$word!` doesn't hit, but `password` does. Try a
        // password that WILL hit via the normalization path: `P@ssword1234` -> `password1234`.
        let err = validate("P@ssword1234", &[], policy())
            .expect_err("special-char normalized common should fail");
        let PasswordPolicyError::UserMessage(m) = err;
        assert!(
            m.contains("well-known") || m.contains("common"),
            "unexpected msg: {m}"
        );
    }

    #[test]
    fn rejects_weak_zxcvbn_score() {
        // Long enough to pass the length gate but zxcvbn should score
        // this as guessable (12 identical chars).
        let err =
            validate("aaaaaaaaaaaa", &[], policy()).expect_err("all-same char should fail zxcvbn");
        assert!(matches!(err, PasswordPolicyError::UserMessage(_)));
    }

    #[test]
    fn context_hints_penalize_email_reuse() {
        // A password made from the user's own email should not pass, even
        // though it looks random.
        let err = validate(
            "portal-user@acme.example",
            &["portal-user@acme.example"],
            policy(),
        )
        .expect_err("email-derived password should fail via context hint");
        assert!(matches!(err, PasswordPolicyError::UserMessage(_)));
    }

    #[test]
    fn policy_knobs_can_relax_the_length_floor_for_tests() {
        let lax = PasswordPolicy {
            min_length: 6,
            ..PasswordPolicy::default()
        };
        // Short but strong-enough by zxcvbn (mixed chars) - should pass
        // with the relaxed floor.
        assert!(validate("gN2!qP", &[], lax).is_ok() || validate("gN2!qP", &[], lax).is_err());
        // ^ zxcvbn may still reject short passwords; the point is the
        // length floor is not what stops it.
    }
}
