//! PMS-1298: every `delete` route takes a role extractor, or is listed here.
//!
//! Reads each `src/modules/*/routes.rs`, finds the handler named in every
//! `delete(handler)` registration and checks its arguments for a `Require*`
//! extractor other than plain `RequireAuth`. A new delete route with neither
//! fails this test.

/// Handlers reachable by any authenticated role, each with the reason. These
/// predate PMS-1298 and were not reviewed by it; PMS-1298's follow-up issue
/// tracks auditing the ones that are not an ownership check.
const EXEMPT: &[(&str, &str)] = &[
    ("cancel", "approvals: requester-owned check in the service"),
    ("revoke_api_key", "own API key"),
    ("delete_session", "own session"),
    ("delete_schedule", "owner-scoped report/dashboard schedule"),
    ("delete_one", "owner-scoped dashboard / saved report"),
    (
        "remove_member",
        "team-manage check in the service (assert_can_manage_team)",
    ),
    (
        "soft_delete_team",
        "team-manage check in the service (assert_can_manage_team)",
    ),
];

fn handler_names(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(i) = rest.find("delete(") {
        let (before, after) = rest.split_at(i);
        rest = &after["delete(".len()..];
        if before.ends_with(|c: char| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
            .collect();
        if rest[name.len()..].starts_with(')') {
            out.push(name.rsplit("::").next().unwrap().to_string());
        }
    }
    out
}

fn args_of<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let head = format!("async fn {name}(");
    let start = src.find(&head)? + head.len();
    let end = src[start..].find(") ->")?;
    Some(&src[start..start + end])
}

#[test]
fn every_delete_route_has_a_role_or_an_exemption() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/modules");
    let mut bad = Vec::new();
    let mut seen = 0;
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path().join("routes.rs");
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        for name in handler_names(&src) {
            seen += 1;
            let Some(args) = args_of(&src, &name) else {
                bad.push(format!("{}: {name} (handler not found)", path.display()));
                continue;
            };
            let gated = args
                .split("Require")
                .skip(1)
                .any(|t| !t.starts_with("Auth"));
            if !gated && !EXEMPT.iter().any(|(n, _)| *n == name) {
                bad.push(format!("{}: {name}", path.display()));
            }
        }
    }
    assert!(seen > 20, "scanner found only {seen} delete routes");
    assert!(bad.is_empty(), "delete routes with no role gate: {bad:#?}");
}
