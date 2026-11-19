//! Tests for files that are part of the published crate and its public tree.

use std::fs;
use std::path::Path;

fn repo_file(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn doc_comment_before(source: &str, signature: &str) -> String {
    let index = source.find(signature).expect("function signature not found");
    let mut lines = Vec::new();
    for line in source[..index].trim_end().lines().rev() {
        let Some(text) = line.trim_start().strip_prefix("///") else {
            break;
        };
        lines.push(text.trim());
    }
    lines.reverse();
    lines.join("\n")
}

fn exclude_block(manifest: &str) -> &str {
    for (index, _) in manifest.match_indices("exclude") {
        let line_prefix = manifest[..index].rsplit('\n').next().unwrap_or("");
        if !line_prefix.trim().is_empty() {
            continue;
        }
        let after = manifest[index + "exclude".len()..].trim_start();
        let Some(after_eq) = after.strip_prefix('=') else {
            continue;
        };
        let after_eq = after_eq.trim_start();
        if after_eq.starts_with('[') {
            let end = after_eq.find(']').expect("unclosed exclude list in Cargo.toml");
            return &after_eq[..=end];
        }
    }
    panic!("Cargo.toml has no exclude list");
}

#[test]
fn published_crate_excludes_development_files() {
    let manifest = repo_file("Cargo.toml");
    let exclude = exclude_block(&manifest);

    for file in [".github/", "fuzz/", "CLAUDE.md", ".mailmap", "deny.toml"] {
        assert!(
            exclude.contains(&format!("\"{file}\"")),
            "Cargo.toml exclude list does not contain {file}: {exclude}"
        );
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if manifest_dir.join("Cargo.toml.orig").exists() {
        for excluded in [".github", "fuzz", "CLAUDE.md", ".mailmap", "deny.toml"] {
            assert!(
                !manifest_dir.join(excluded).exists(),
                "packaged crate unexpectedly contains {excluded}"
            );
        }
    }
}

#[test]
fn development_guide_has_no_machine_specific_notes() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if manifest_dir.join("Cargo.toml.orig").exists() {
        assert!(!manifest_dir.join("CLAUDE.md").exists());
        return;
    }

    let guide = repo_file("CLAUDE.md");

    for needle in ["/Users/", "keychain", "credentials.toml", "account"] {
        assert!(!guide.contains(needle), "CLAUDE.md still contains {needle:?}");
    }
}

#[test]
fn update_documents_monotonic_time() {
    for path in ["src/client.rs", "src/server.rs"] {
        let source = repo_file(path);
        let docs = doc_comment_before(&source, "pub fn update(&mut self, time: f64)");
        assert!(
            docs.contains("monotonically non-decreasing"),
            "{path} update docs do not say time is monotonically non-decreasing: {docs:?}"
        );
    }
}
