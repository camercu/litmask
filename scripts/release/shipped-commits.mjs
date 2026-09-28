// semantic-release plugin: commit-analyzer and release-notes-generator that
// see only commits touching a file shipped in a published crate. A `fix` to
// CI or a just recipe then neither cuts a release nor fills the notes, with
// no scope list to maintain: `cargo package --list` is the source of truth.
// Takes the same config as the two plugins it wraps.

import { execFileSync } from "node:child_process";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";

import * as commitAnalyzer from "@semantic-release/commit-analyzer";
import * as notesGenerator from "@semantic-release/release-notes-generator";

import { assertPackageSources, consumerView, followRenames, partitionCommits, sourcePaths } from "./shipped.mjs";

const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: "utf8", maxBuffer: 1 << 26 });
const lines = (text) => text.split("\n").filter(Boolean);

function packageSources(root) {
  const meta = JSON.parse(run("cargo", ["metadata", "--no-deps", "--format-version", "1"], root));
  const resolve = (p) => relative(meta.workspace_root, realpathSync(`${meta.workspace_root}/${p}`));
  const shipped = new Set();
  // `publish: null` means any registry; `[]` (publish = false) means none.
  for (const pkg of meta.packages.filter((p) => p.publish === null || p.publish.length > 0)) {
    const entries = lines(run("cargo", ["package", "--list", "--locked", "--allow-dirty", "-p", pkg.name], root));
    const dir = relative(meta.workspace_root, dirname(pkg.manifest_path));
    const paths = sourcePaths({ dir, readme: pkg.readme, entries }, resolve);
    assertPackageSources(dir, paths);
    for (const path of paths) shipped.add(path);
  }
  return shipped;
}

function atRevision(cwd, rev, fn) {
  const tree = mkdtempSync(join(tmpdir(), "litmask-release-"));
  run("git", ["worktree", "add", "--quiet", "--detach", tree, rev], cwd);
  try {
    return fn(tree);
  } finally {
    run("git", ["worktree", "remove", "--force", tree], cwd);
  }
}

const packageSourcesAt = (cwd, rev) => atRevision(cwd, rev, packageSources);

// Only dependency-only commits need this, so it runs a handful of times per
// release, not once per commit.
function viewAt(cwd, rev) {
  return atRevision(cwd, rev, (tree) =>
    consumerView(JSON.parse(run("cargo", ["metadata", "--format-version", "1", "--locked"], tree))),
  );
}

// A path counts if consumers had it at the last release or get it now, or
// if a rename in between carries it to one of those.
function shippedFiles(cwd, lastHead) {
  const shipped = packageSources(cwd);
  if (!lastHead) return shipped;
  for (const path of packageSourcesAt(cwd, lastHead)) shipped.add(path);
  const renames = lines(
    run("git", ["log", "--diff-filter=R", "--name-status", "--format=", `${lastHead}..HEAD`], cwd),
  ).map((l) => l.split("\t").slice(1));
  return followRenames(shipped, renames);
}

// analyzeCommits and generateNotes run in one semantic-release process;
// package the workspace once per repo and release window.
const shippedCache = new Map();

export function selectShipped(context) {
  const lastHead = context.lastRelease?.gitHead;
  const key = `${context.cwd}\0${lastHead ?? ""}`;
  if (!shippedCache.has(key)) shippedCache.set(key, shippedFiles(context.cwd, lastHead));
  // --no-renames lists a rename's old path too, so moving a file out of a
  // package still counts as touching it. A clean merge's combined diff is
  // empty; its first-parent diff is what it brings to the release branch.
  const filesOf = (hash) =>
    lines(
      run(
        "git",
        ["show", "--no-renames", "--diff-merges=first-parent", "--name-only", "--format=", hash],
        context.cwd,
      ),
    );
  // History cannot be repaired, so a commit whose metadata will not resolve
  // (a stale lock, a yanked crate, no network) is kept, as before this check
  // existed, rather than failing every later release.
  const viewChanged = (hash) => {
    try {
      return viewAt(context.cwd, `${hash}^`) !== viewAt(context.cwd, hash);
    } catch (error) {
      context.logger.log("Keep %s: cannot compare its dependencies (%s)", hash.slice(0, 7), error.message.split("\n")[0]);
      return true;
    }
  };
  return partitionCommits(context.commits, filesOf, shippedCache.get(key), viewChanged);
}

function shippedOnly(context) {
  const { kept, dropped } = selectShipped(context);
  for (const c of dropped) {
    context.logger.log("Skip %s (changes nothing a published crate ships or resolves): %s", c.hash.slice(0, 7), c.message.split("\n")[0]);
  }
  return { ...context, commits: kept };
}

export async function analyzeCommits(pluginConfig, context) {
  return commitAnalyzer.analyzeCommits(pluginConfig, shippedOnly(context));
}

export async function generateNotes(pluginConfig, context) {
  return notesGenerator.generateNotes(pluginConfig, shippedOnly(context));
}
