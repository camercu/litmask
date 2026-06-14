//! Guard: every artifact `emit()` writes to disk must have a consumer.
//!
//! The dead `litmask.config` artifact survived for a long time partly
//! because nothing mechanically checked that what the build *writes* is
//! actually *read*. This test derives the artifact filenames from
//! `emit()`'s own source and asserts each is referenced in the consumer
//! crates — `litmask-macros` (reads them at macro expansion) or `litmask`
//! (embeds the wrapper via `include_bytes!`). A new build artifact with no
//! reader fails here, loudly, with a pointer to the fix.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <root>/litmask-build
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Filenames `emit()` writes, scraped from its production source: every
/// `.join("litmask_*")` target. Scoped to the code above the test module
/// so the in-crate tests (which deliberately assert `litmask.config` is
/// *absent*) don't feed phantom artifacts into the check.
fn written_artifacts() -> BTreeSet<String> {
    let full = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("read litmask-build src");
    let src = &full[..full.find("mod tests").unwrap_or(full.len())];

    let mut found = BTreeSet::new();
    let needle = ".join(\"";
    let mut rest = src;
    while let Some(i) = rest.find(needle) {
        rest = &rest[i + needle.len()..];
        if let Some(end) = rest.find('"') {
            let name = &rest[..end];
            if name.starts_with("litmask_") {
                found.insert(name.to_string());
            }
        }
    }
    found
}

/// Concatenate every `.rs` source under `dir`, recursively.
fn all_rs_sources(dir: &Path) -> String {
    let mut out = String::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).expect("read_dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push_str(&fs::read_to_string(&path).expect("read source"));
            }
        }
    }
    out
}

#[test]
fn every_written_artifact_has_a_consumer() {
    let root = workspace_root();
    let consumers = format!(
        "{}{}",
        all_rs_sources(&root.join("litmask-macros/src")),
        all_rs_sources(&root.join("litmask/src")),
    );

    let artifacts = written_artifacts();
    assert!(
        !artifacts.is_empty(),
        "scraper found no `litmask_*` artifacts in emit() source — the scrape broke",
    );

    for name in &artifacts {
        assert!(
            consumers.contains(name.as_str()),
            "litmask-build writes `{name}` but no litmask-macros/litmask source reads it — \
             wire a consumer, or stop writing it (cf. the litmask.config removal)",
        );
    }
}
