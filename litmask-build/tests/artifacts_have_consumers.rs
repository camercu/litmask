//! Guard: every build-artifact filename const is both written and read.
//!
//! The dead `litmask.config` artifact survived for a long time partly
//! because nothing mechanically checked that what the build *writes* is
//! actually *read*. litmask-internal now owns the `*_ARTIFACT` filename
//! consts (the single source of truth for the `OUT_DIR` contract); this
//! test scrapes those const names and asserts each is referenced by the
//! writer (litmask-build's `emit`) AND by at least one reader crate
//! (litmask-macros at expansion time, or litmask via `include_bytes!`).
//! A new artifact const with no writer or no reader fails here, loudly,
//! with a pointer to the fix.

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <root>/litmask-build
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// The `*_ARTIFACT` const names declared in litmask-internal's wire
/// module — the single source of truth for the on-disk filenames.
fn artifact_consts(root: &Path) -> Vec<String> {
    let src = fs::read_to_string(root.join("litmask-internal/src/wire.rs"))
        .expect("read litmask-internal wire.rs");
    src.lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("pub const ")?;
            let (name, _) = rest.split_once(':')?;
            let name = name.trim();
            name.ends_with("_ARTIFACT").then(|| name.to_string())
        })
        .collect()
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
fn every_artifact_const_is_written_and_read() {
    let root = workspace_root();
    let consts = artifact_consts(&root);
    assert!(
        !consts.is_empty(),
        "scraper found no `*_ARTIFACT` consts in litmask-internal/src/wire.rs — the scrape broke",
    );

    let writer = all_rs_sources(&root.join("litmask-build/src"));
    let readers = format!(
        "{}{}",
        all_rs_sources(&root.join("litmask-macros/src")),
        all_rs_sources(&root.join("litmask/src")),
    );

    for name in &consts {
        assert!(
            writer.contains(name.as_str()),
            "litmask-internal declares `{name}` but litmask-build never references it — \
             wire it into emit(), or drop the const",
        );
        assert!(
            readers.contains(name.as_str()),
            "litmask-internal declares `{name}` but no litmask-macros/litmask source reads it — \
             wire a consumer, or stop writing it (cf. the litmask.config removal)",
        );
    }
}
