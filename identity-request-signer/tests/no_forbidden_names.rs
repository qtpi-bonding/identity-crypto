//! The crate names no service and no allowlist dependency: a grep test
//! that builds its needles from parts so this file itself stays clean.

mod common;

use std::path::{Path, PathBuf};

fn needle(parts: &[&str]) -> String {
    parts.concat()
}

fn files() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for sub in ["src", "tests"] {
        collect(&root.join(sub), &mut out);
    }
    out.push(root.join("Cargo.toml"));
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn no_service_names_in_the_crate() {
    // The service names, built from parts so this file stays clean.
    let forbidden = [
        needle(&["gr", "org"]),
        needle(&["multi", "matrix"]),
        needle(&["access", "-", "control"]),
        needle(&["access", "_", "control"]),
    ];
    let mut hits = Vec::new();
    for file in files() {
        let text = std::fs::read_to_string(&file).expect("read file");
        for (line_no, line) in text.lines().enumerate() {
            for needle_text in &forbidden {
                if line.contains(needle_text.as_str()) {
                    hits.push(format!("{}:{}: {line}", file.display(), line_no + 1));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "forbidden names found in the crate: {hits:?}"
    );
}
