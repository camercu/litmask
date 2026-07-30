//! Guard: `just ci`'s step list and the GitHub canonical gate agree.
//!
//! The two lists are maintained by hand in different files, and the
//! divergence between them is real but *intentional* and small. It was
//! previously recorded only as prose in `CONTRIBUTING.md`, which is
//! exactly how the "pre-push mirrors CI" claim rotted: prose describing
//! a list cannot notice the list changing. This test makes the claim
//! executable — add a lane to one side and it fails here naming the
//! other side, unless the lane is a declared, justified exception.
//!
//! Lives in litmask-build's test dir because no crate owns the repo
//! gate, and this is where the repo's other mechanical anti-rot guard
//! (`artifacts_have_consumers.rs`) already lives.

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

/// Recipe names invoked as `step <name>` by the `ci` recipe in the
/// justfile. The recipe body is the indented block following the
/// `ci mode="":` header.
fn just_ci_steps(root: &Path) -> BTreeSet<String> {
    let src = fs::read_to_string(root.join("justfile")).expect("read justfile");
    let mut steps = BTreeSet::new();
    let mut in_ci = false;
    for line in src.lines() {
        if line.starts_with("ci mode=") {
            in_ci = true;
            continue;
        }
        if in_ci {
            // A non-indented, non-empty line ends the recipe body.
            if !line.is_empty() && !line.starts_with([' ', '\t']) {
                break;
            }
            if let Some(name) = line.trim().strip_prefix("step ") {
                steps.insert(name.trim().to_string());
            }
        }
    }
    assert!(
        !steps.is_empty(),
        "parsed no `step` lines from the ci recipe"
    );
    steps
}

/// Recipe names invoked as `just <name>` by the `canonical-gate` job in
/// the CI workflow. Scoped to that job: other jobs (stable-advisory,
/// semver-check, mutants-diff) run recipes that are deliberately not
/// part of the gate.
fn workflow_gate_steps(root: &Path) -> BTreeSet<String> {
    let src = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read ci.yml");
    let mut steps = BTreeSet::new();
    let mut in_job = false;
    for line in src.lines() {
        if line == "  canonical-gate:" {
            in_job = true;
            continue;
        }
        if in_job {
            // The next job header (two-space indent, non-space after) ends this job.
            let is_job_header = line.starts_with("  ")
                && !line.starts_with("   ")
                && line.trim_end().ends_with(':')
                && !line.trim().is_empty();
            if is_job_header {
                break;
            }
            if let Some((_, rest)) = line.split_once("run: just ") {
                let name = rest.trim();
                // Skip composite invocations; the gate uses bare recipe names.
                if !name.is_empty() && !name.contains(' ') {
                    steps.insert(name.to_string());
                }
            }
        }
    }
    assert!(
        !steps.is_empty(),
        "parsed no `just` steps from the canonical-gate job"
    );
    steps
}

/// Lanes `just ci` runs that the canonical gate deliberately does not.
/// CI reaches the same code by a different split, so adding them there
/// would only lengthen the gate.
const INTENTIONAL_LOCAL_ONLY: &[(&str, &str)] = &[
    (
        "test-all-features",
        "CI splits the workspace differently: `test-unit` covers the same \
         crates on default features.",
    ),
    (
        "test-machine-id",
        "Needs a host machine-id token; CI's chacha coverage of the \
         integration suite comes from `test-unit` (default features).",
    ),
];

/// Lanes the canonical gate runs that `just ci` deliberately does not.
const INTENTIONAL_REMOTE_ONLY: &[(&str, &str)] = &[
    (
        "test-unit",
        "Workspace tests on default features (so ChaCha20-Poly1305); \
         locally that role is filled by `test-all-features`.",
    ),
    (
        "ci-coverage",
        "Non-gating and slow: instrumenting the workspace stole enough \
         cores to add ~71s to the local gate, so it is `just ci-full` \
         locally and its own CI step remotely.",
    ),
];

fn declared(list: &[(&str, &str)], name: &str) -> bool {
    list.iter().any(|(lane, _)| *lane == name)
}

#[test]
fn ci_gate_and_workflow_run_the_same_lanes() {
    let root = workspace_root();
    let local = just_ci_steps(&root);
    let remote = workflow_gate_steps(&root);

    let local_only: Vec<_> = local
        .difference(&remote)
        .filter(|name| !declared(INTENTIONAL_LOCAL_ONLY, name))
        .cloned()
        .collect();
    let remote_only: Vec<_> = remote
        .difference(&local)
        .filter(|name| !declared(INTENTIONAL_REMOTE_ONLY, name))
        .cloned()
        .collect();

    assert!(
        local_only.is_empty() && remote_only.is_empty(),
        "`just ci` and the GitHub canonical gate have drifted.\n\
         only in `just ci` (justfile): {local_only:?}\n\
         only in canonical-gate (.github/workflows/ci.yml): {remote_only:?}\n\
         Add the lane to the other side, or declare it in INTENTIONAL_* \
         in this test with the reason."
    );
}

/// The exception lists are themselves hand-maintained prose-plus-name,
/// so they can rot the same way: a lane added to both sides, or renamed,
/// would leave a stale entry silently excusing a divergence that no
/// longer exists.
#[test]
fn declared_exceptions_still_diverge() {
    let root = workspace_root();
    let local = just_ci_steps(&root);
    let remote = workflow_gate_steps(&root);

    for (lane, _) in INTENTIONAL_LOCAL_ONLY {
        assert!(
            local.contains(*lane) && !remote.contains(*lane),
            "stale exception: `{lane}` is declared local-only but is no longer \
             so (in `just ci`: {}, in canonical-gate: {}). Drop the entry.",
            local.contains(*lane),
            remote.contains(*lane),
        );
    }
    for (lane, _) in INTENTIONAL_REMOTE_ONLY {
        assert!(
            remote.contains(*lane) && !local.contains(*lane),
            "stale exception: `{lane}` is declared CI-only but is no longer \
             so (in `just ci`: {}, in canonical-gate: {}). Drop the entry.",
            local.contains(*lane),
            remote.contains(*lane),
        );
    }
}
