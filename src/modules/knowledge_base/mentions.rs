//! `@handle` in a KB comment, resolved to a colleague (PMS-1129).
//!
//! The client (`mokosh-apps` `utils::mentions`) decides what a mention LOOKS
//! like and which handles a person answers to, so a chip in the rendered
//! comment and a notification from the server point at the same person. The
//! two rules here are copies of the client's and change together:
//!
//! - A token is an `@` that does not follow a word character, then a run of
//!   alphanumerics, `.`, `_` and `-`, with trailing punctuation dropped
//!   (`@long.` at the end of a sentence names `long`).
//! - A person answers to the directory handle (the local part of their
//!   email, `PMS-921`), their first name, and their full name joined with a
//!   `.` and with nothing; the last name alone is deliberately absent. A
//!   token that names two people names nobody: ambiguity resolves to nothing
//!   rather than to a guess, because a wrong notification is worse than none.

use uuid::Uuid;

/// One person a mention can resolve to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    /// `LOWER(split_part(email, '@', 1))`, the directory's handle.
    pub handle: String,
}

impl Person {
    /// Every handle this person answers to, lowercased, the client's rule.
    fn handles(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |s: String| {
            let s = s.trim().to_lowercase();
            if !s.is_empty() && !out.contains(&s) {
                out.push(s);
            }
        };
        push(self.handle.clone());
        let display = format!("{} {}", self.first_name, self.last_name);
        let parts: Vec<&str> = display.split_whitespace().collect();
        if let Some(first) = parts.first() {
            push((*first).to_string());
        }
        if parts.len() >= 2 {
            push(parts.join("."));
            push(parts.concat());
        }
        out
    }
}

fn is_handle_char(c: char) -> bool {
    c.is_alphanumeric() || c == '.' || c == '_' || c == '-'
}

/// Every `@handle` token in `body`, lowercased, unique, in order of first
/// appearance.
pub fn tokens(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut prev: Option<char> = None;
    let mut chars = body.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if c != '@' || prev.is_some_and(is_handle_char) {
            prev = Some(c);
            continue;
        }
        let mut end = at + 1;
        while let Some(&(idx, next)) = chars.peek() {
            if is_handle_char(next) {
                end = idx + next.len_utf8();
                chars.next();
            } else {
                break;
            }
        }
        let raw = body[at + 1..end].trim_end_matches(['.', '-', '_']);
        prev = body[..end].chars().next_back();
        if raw.is_empty() {
            continue;
        }
        let token = raw.to_lowercase();
        if !out.contains(&token) {
            out.push(token);
        }
    }
    out
}

/// The one person `token` names, or `None` when it names nobody or more
/// than one.
pub fn resolve(token: &str, people: &[Person]) -> Option<Uuid> {
    let needle = token.trim().to_lowercase();
    if needle.is_empty() {
        return None;
    }
    let mut found: Option<Uuid> = None;
    for person in people {
        if person.handles().contains(&needle) {
            if found.is_some() {
                return None;
            }
            found = Some(person.id);
        }
    }
    found
}

/// Every person `body` mentions, unique, in order of first mention.
pub fn mentioned(body: &str, people: &[Person]) -> Vec<Uuid> {
    let mut out: Vec<Uuid> = Vec::new();
    for token in tokens(body) {
        if let Some(id) = resolve(&token, people) {
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(first: &str, last: &str, handle: &str) -> Person {
        Person {
            id: Uuid::new_v4(),
            first_name: first.into(),
            last_name: last.into(),
            handle: handle.into(),
        }
    }

    #[test]
    fn a_token_is_an_at_after_a_boundary_with_trailing_punctuation_dropped() {
        assert_eq!(
            tokens(
                "@long please check, cc @Nate.Smith. Also me@example.com is not one; @long again"
            ),
            ["long", "nate.smith"]
        );
        assert_eq!(tokens("@ alone and @@ nothing"), Vec::<String>::new());
        assert_eq!(tokens("(@ada-lovelace)"), ["ada-lovelace"]);
    }

    #[test]
    fn a_person_answers_to_handle_first_name_and_joined_full_name_only() {
        let ada = person("Ada", "Lovelace", "ada.l");
        let people = [ada.clone(), person("Grace", "Hopper", "grace")];
        for handle in ["ada.l", "ada", "ada.lovelace", "adalovelace", "ADA"] {
            assert_eq!(resolve(handle, &people), Some(ada.id), "{handle}");
        }
        assert_eq!(
            resolve("lovelace", &people),
            None,
            "the last name alone is not a handle"
        );
        assert_eq!(resolve("nobody", &people), None);
    }

    #[test]
    fn an_ambiguous_token_names_nobody() {
        let a = person("Sam", "Adams", "sam.a");
        let b = person("Sam", "Brown", "sam.b");
        let people = [a.clone(), b.clone()];
        assert_eq!(resolve("sam", &people), None);
        assert_eq!(resolve("sam.a", &people), Some(a.id));
        assert_eq!(mentioned("@sam and @sam.b and @sam.b", &people), vec![b.id]);
    }
}
