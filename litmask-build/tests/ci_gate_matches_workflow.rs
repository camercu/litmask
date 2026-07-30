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

mod common;

use common::workspace_root;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Recipe names invoked as `step <name>` by the `ci` recipe in the
/// justfile. The recipe body is the indented block following the
/// `ci mode="":` header.
fn just_ci_steps(root: &Path) -> BTreeSet<String> {
    let src = fs::read_to_string(root.join("justfile")).expect("read justfile");
    let steps = ci_steps_from(&src);
    assert!(
        !steps.is_empty(),
        "parsed no `step` lines from the ci recipe"
    );
    steps
}

/// Pure core of [`just_ci_steps`], so the parsing rules are testable
/// against synthetic input rather than only the live justfile.
fn ci_steps_from(src: &str) -> BTreeSet<String> {
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
    steps
}

/// Recipe names invoked as `just <name>` by the `canonical-gate` job in
/// the CI workflow. Scoped to that job: other jobs (stable-advisory,
/// semver-check, mutants-diff) run recipes that are deliberately not
/// part of the gate.
fn workflow_gate_steps(root: &Path) -> BTreeSet<String> {
    let src = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read ci.yml");
    let steps = gate_steps_from(&src);
    assert!(
        !steps.is_empty(),
        "parsed no `just` steps from the canonical-gate job"
    );
    steps
}

/// Pure core of [`workflow_gate_steps`], testable against synthetic
/// input.
fn gate_steps_from(src: &str) -> BTreeSet<String> {
    gate_job_lines(src)
        .iter()
        .filter_map(|line| just_recipe(line))
        .map(str::to_string)
        .collect()
}

/// Lines belonging to the `canonical-gate` job, up to the next job.
fn gate_job_lines(src: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut in_job = false;
    for line in src.lines() {
        if line == "  canonical-gate:" {
            in_job = true;
            continue;
        }
        if !in_job {
            continue;
        }
        if is_job_header(line) {
            break;
        }
        lines.push(line);
    }
    lines
}

/// A sibling job header: a key at two-space indent. Comments are
/// excluded deliberately — a `# ...:` line at that indentation would
/// otherwise end the job early and report every later lane as missing.
fn is_job_header(line: &str) -> bool {
    let trimmed = line.trim_end();
    trimmed.starts_with("  ")
        && !trimmed.starts_with("   ")
        && !trimmed.trim_start().starts_with('#')
        && trimmed.ends_with(':')
}

/// The recipe name a `run: just <name>` line invokes.
///
/// Anchored at the start of the (trimmed) line rather than matched
/// anywhere in it: an unanchored match counts a commented-out step as
/// still running, which is the most plausible way a lane silently
/// leaves the gate.
fn just_recipe(line: &str) -> Option<&str> {
    let name = line.trim().strip_prefix("run: just ")?.trim();
    // Composite invocations are not bare lanes; the gate uses bare names.
    (!name.is_empty() && !name.contains(' ')).then_some(name)
}

/// Step blocks within the job, each starting at its `- name:` line.
fn gate_step_blocks(src: &str) -> Vec<Vec<&str>> {
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    for line in gate_job_lines(src) {
        if line.trim_start().starts_with("- ") {
            blocks.push(Vec::new());
        }
        if let Some(block) = blocks.last_mut() {
            block.push(line);
        }
    }
    blocks
}

/// Gate steps that parse as present but do not unconditionally gate.
///
/// Name presence cannot distinguish "runs" from "runs on Tuesdays" or
/// "runs and its failure is ignored", so those modifiers are refused on
/// a lane rather than tolerated and measured wrongly.
fn gate_step_violations(src: &str) -> Vec<String> {
    const SOFTENERS: [&str; 2] = ["if:", "continue-on-error:"];
    let mut violations = Vec::new();
    for block in gate_step_blocks(src) {
        let Some(recipe) = block.iter().find_map(|line| just_recipe(line)) else {
            continue;
        };
        for key in SOFTENERS {
            if block.iter().any(|line| line.trim_start().starts_with(key)) {
                violations.push(format!(
                    "gate step `just {recipe}` carries `{key}`, so it no longer \
                     unconditionally gates"
                ));
            }
        }
    }
    violations
}

/// Strip the leading newline from a raw-string YAML fixture. Raw
/// strings keep the indentation that `\`-continuation would eat, which
/// matters here because every parsing rule under test is
/// indentation-sensitive.
fn indented(fixture: &str) -> String {
    fixture.strip_prefix('\n').unwrap_or(fixture).to_string()
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

#[test]
fn no_gate_step_is_conditional_or_soft_failing() {
    let root = workspace_root();
    let src = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read ci.yml");
    let violations = gate_step_violations(&src);
    assert!(
        violations.is_empty(),
        "the canonical gate must gate unconditionally:\n{}",
        violations.join("\n")
    );
}

/// A step that is commented out is a step CI no longer runs. Matching
/// the token anywhere in the line would keep counting it, letting the
/// most plausible de-gating edit there is slip past silently.
#[test]
fn commented_out_workflow_step_is_not_counted() {
    let yaml = indented(
        r"
  canonical-gate:
    steps:
      - name: Doc
        run: just doc
      # TODO: re-enable once the cross toolchain is fixed
      # - name: Check (cross)
      #   run: just check-cross
  next-job:
",
    );
    let steps = gate_steps_from(&yaml);
    assert!(steps.contains("doc"), "live step should parse: {steps:?}");
    assert!(
        !steps.contains("check-cross"),
        "commented-out step must not count as present: {steps:?}"
    );
}

/// A gate step carrying `if:` or `continue-on-error:` still parses as
/// present but no longer unconditionally gates. Name-presence alone
/// cannot see that, so it is rejected outright.
#[test]
fn conditional_or_soft_failing_gate_steps_are_rejected() {
    let yaml = indented(
        r"
  canonical-gate:
    steps:
      - name: Check (cross)
        if: github.event_name == 'push'
        run: just check-cross
      - name: Doc
        continue-on-error: true
        run: just doc
  next-job:
",
    );
    let violations = gate_step_violations(&yaml);
    assert!(
        violations.iter().any(|v| v.contains("if:")),
        "should reject a conditional gate step: {violations:?}"
    );
    assert!(
        violations.iter().any(|v| v.contains("continue-on-error:")),
        "should reject a soft-failing gate step: {violations:?}"
    );
}

/// The end-of-job detector keys on indentation, so a comment that
/// happens to end in a colon must not read as the next job header and
/// silently truncate the step list.
#[test]
fn comment_inside_job_does_not_end_it() {
    let yaml = indented(
        r"
  canonical-gate:
    steps:
      - name: Lint
        run: just lint
  # Everything below is the heavy half of the gate:
      - name: Doc
        run: just doc
  next-job:
",
    );
    let steps = gate_steps_from(&yaml);
    assert!(
        steps.contains("lint") && steps.contains("doc"),
        "comment must not truncate the job: {steps:?}"
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
