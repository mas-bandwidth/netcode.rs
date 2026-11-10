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

#[test]
fn published_crate_excludes_development_files() {
    let manifest = repo_file("Cargo.toml");
    let exclude = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("exclude"))
        .expect("Cargo.toml has no exclude list");

    let development_files = ["CLAUDE.md", ".mailmap", "deny.toml"];
    for file in development_files {
        assert!(
            exclude.contains(&format!("\"{file}\"")),
            "Cargo.toml exclude list does not contain {file}: {exclude}"
        );
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = std::process::Command::new(cargo)
        .args(["package", "--list", "--offline"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run cargo package --list");
    assert!(
        output.status.success(),
        "cargo package --list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listed = String::from_utf8_lossy(&output.stdout);
    for file in development_files {
        assert!(!listed.lines().any(|line| line == file), "published crate contains {file}");
    }
}

#[test]
fn development_guide_has_no_machine_specific_notes() {
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
