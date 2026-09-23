// Acceptance tests: run the release plugin over real tagged history, so
// they exercise git, `cargo package --list` and the delegated
// semantic-release plugins together. Needs full history (tags) and cargo.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";

import { analyzeCommits, generateNotes } from "./shipped-commits.mjs";

const config = {
  preset: "conventionalcommits",
  releaseRules: [{ breaking: true, release: "minor" }],
};

function commitsBetween(from, to) {
  const out = execFileSync("git", ["log", "--no-merges", "--format=%H%x1f%B%x1e", `${from}..${to}`], {
    encoding: "utf8",
  });
  return out
    .split("\x1e")
    .map((r) => r.trim())
    .filter(Boolean)
    .map((r) => {
      const [hash, message] = r.split("\x1f");
      return { hash, message: message.trim() };
    });
}

function context(from, to) {
  return {
    cwd: process.cwd(),
    options: { repositoryUrl: "https://github.com/camercu/litmask.git" },
    commits: commitsBetween(from, to),
    lastRelease: { gitTag: from, version: from.slice(1) },
    nextRelease: { gitTag: to, version: to.slice(1) },
    logger: { log() {}, error() {} },
  };
}

test("GIVEN only maintainer-tooling fixes WHEN analyzed THEN no release", async () => {
  // v0.21.4 was cut only by `fix(setup)`, which touches no published file.
  assert.equal(await analyzeCommits(config, context("v0.21.3", "v0.21.4")), null);
});

test("GIVEN a published-crate fix WHEN analyzed THEN patch", async () => {
  assert.equal(await analyzeCommits(config, context("v0.21.0", "v0.21.1")), "patch");
});

test("GIVEN a published-crate fix WHEN notes render THEN it is listed", async () => {
  const notes = await generateNotes(config, context("v0.21.0", "v0.21.1"));
  assert.match(notes, /scope the Embedded-floor warning to the sealing crate/);
});

test("GIVEN a tooling-only fix beside it WHEN notes render THEN it is left out", async () => {
  // 8525223 fix(examples) changed only scripts/test-examples.sh.
  const notes = await generateNotes(config, context("v0.21.0", "v0.21.1"));
  assert.doesNotMatch(notes, /glob expansion/);
});
