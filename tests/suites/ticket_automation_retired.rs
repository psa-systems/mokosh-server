//! The ticket automation engine is retired: no source file outside `tests/`
//! and `migrations/` may reference its table or module path again.

use std::path::Path;

fn walk(dir: &Path, hits: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk(&path, hits);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("read source");
            for needle in ["ticket_automation_rules", "AutomationEngine", "automation::"] {
                if text.contains(needle) {
                    hits.push(format!("{}: {needle}", path.display()));
                }
            }
        }
    }
}

#[test]
fn no_source_references_the_retired_ticket_automation_engine() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    walk(&root.join("src"), &mut hits);
    walk(&root.join("crates"), &mut hits);
    assert!(
        hits.is_empty(),
        "retired automation engine referenced: {hits:?}"
    );
}
