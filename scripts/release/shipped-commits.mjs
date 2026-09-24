// semantic-release plugin: commit-analyzer and release-notes-generator that
// see only commits touching a file shipped in a published crate. A `fix` to
// CI or a just recipe then neither cuts a release nor fills the notes, with
// no scope list to maintain: `cargo package --list` is the source of truth.
// Takes the same config as the two plugins it wraps.

import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { relative } from "node:path";

import * as commitAnalyzer from "@semantic-release/commit-analyzer";
import * as notesGenerator from "@semantic-release/release-notes-generator";

import { partitionCommits, sourcePaths } from "./shipped.mjs";

const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, encoding: "utf8", maxBuffer: 1 << 26 });
const lines = (text) => text.split("\n").filter(Boolean);

function shippedFiles(cwd) {
  const meta = JSON.parse(run("cargo", ["metadata", "--no-deps", "--format-version", "1"], cwd));
  const root = meta.workspace_root;
  const resolve = (p) => relative(root, realpathSync(`${root}/${p}`));
  const shipped = new Set();
  // `publish: null` means any registry; `[]` (publish = false) means none.
  for (const pkg of meta.packages.filter((p) => p.publish === null || p.publish.length > 0)) {
    const entries = lines(run("cargo", ["package", "--list", "--allow-dirty", "-p", pkg.name], root));
    const dir = relative(root, pkg.manifest_path.replace(/\/Cargo\.toml$/, ""));
    for (const path of sourcePaths({ dir, readme: pkg.readme, entries }, resolve)) shipped.add(path);
  }
  return shipped;
}

// analyzeCommits and generateNotes run in one semantic-release process;
// package the workspace once.
let shippedCache;

export function selectShipped(context) {
  shippedCache ??= shippedFiles(context.cwd);
  const filesOf = (hash) => lines(run("git", ["show", "--name-only", "--format=", hash], context.cwd));
  return partitionCommits(context.commits, filesOf, shippedCache);
}

function shippedOnly(context) {
  const { kept, dropped } = selectShipped(context);
  for (const c of dropped) {
    context.logger.log("Skip %s (touches no published file): %s", c.hash.slice(0, 7), c.message.split("\n")[0]);
  }
  return { ...context, commits: kept };
}

export async function analyzeCommits(pluginConfig, context) {
  return commitAnalyzer.analyzeCommits(pluginConfig, shippedOnly(context));
}

export async function generateNotes(pluginConfig, context) {
  return notesGenerator.generateNotes(pluginConfig, shippedOnly(context));
}
