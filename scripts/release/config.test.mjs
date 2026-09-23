// Runs synthetic commits through the stock semantic-release plugins with the
// exact config .releaserc.json passes to shipped-commits.mjs. The commit
// filter is covered by shipped-commits.test.mjs; this file covers what the
// wrapped plugins make of the commits that survive it.
//
// Why render real notes: conventional-changelog-conventionalcommits 10 ships
// JS-function templates that only conventional-changelog-writer 9 reads,
// while release-notes-generator 14 still runs writer 8. The mismatch
// renders a header with an empty body and raises no error, so
// v0.21.0..v0.21.5 shipped blank CHANGELOG entries and GitHub releases.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, test } from "node:test";

import { analyzeCommits } from "@semantic-release/commit-analyzer";
import { generateNotes } from "@semantic-release/release-notes-generator";

const PLUGIN = "./scripts/release/shipped-commits.mjs";
const entry = JSON.parse(readFileSync(".releaserc.json", "utf8")).plugins.find(
  (p) => Array.isArray(p) && p[0] === PLUGIN,
);
const config = entry?.[1];

const EMPTY_NOTES_HINT =
  "Empty notes usually mean the conventional-changelog-conventionalcommits major no " +
  "longer matches the writer that release-notes-generator bundles; see this file's header.";

let n = 0;
const commit = (message) => ({ hash: String(++n).padStart(40, "0"), message });

function context(messages) {
  return {
    cwd: process.cwd(),
    options: { repositoryUrl: "https://github.com/camercu/litmask.git" },
    commits: messages.map(commit),
    lastRelease: { gitTag: "v0.0.0", version: "0.0.0" },
    nextRelease: { gitTag: "v0.1.0", version: "0.1.0" },
    logger: { log() {}, error() {} },
  };
}

const release = (message) => analyzeCommits(config, context([message]));

test("GIVEN .releaserc.json WHEN loaded THEN it routes commits through the shipped filter", () => {
  assert.ok(config, `${PLUGIN} is not a configured plugin`);
});

test("GIVEN a feat WHEN analyzed THEN minor", async () => {
  assert.equal(await release("feat(litmask): x"), "minor");
});

test("GIVEN a fix WHEN analyzed THEN patch", async () => {
  assert.equal(await release("fix(litmask): x"), "patch");
});

test("GIVEN a perf WHEN analyzed THEN patch", async () => {
  assert.equal(await release("perf(litmask): x"), "patch");
});

test("GIVEN a breaking change before 1.0 WHEN analyzed THEN minor, not major", async () => {
  assert.equal(await release("feat(litmask)!: x\n\nBREAKING CHANGE: y"), "minor");
});

test("GIVEN a chore WHEN analyzed THEN no release", async () => {
  assert.equal(await release("chore(litmask): x"), null);
});

let notes;
before(async () => {
  notes = await generateNotes(
    config,
    context([
      "feat(litmask): add a probe feature",
      "fix(litmask): repair a probe bug",
      "feat(litmask)!: change a probe API\n\nBREAKING CHANGE: probe migration note",
      "refactor(litmask)!: reshape a probe type\n\nBREAKING CHANGE: probe refactor note",
      "refactor(litmask): tidy a probe internal",
    ]),
  );
});

test("GIVEN a feat WHEN notes render THEN it is under Features", () => {
  assert.match(notes, /### Features\n\n(\* .*\n)*\* \*\*litmask:\*\* add a probe feature/, EMPTY_NOTES_HINT);
});

test("GIVEN a fix WHEN notes render THEN it is under Bug Fixes", () => {
  assert.match(notes, /### Bug Fixes\n\n\* \*\*litmask:\*\* repair a probe bug/, EMPTY_NOTES_HINT);
});

test("GIVEN a BREAKING CHANGE footer WHEN notes render THEN it is under BREAKING CHANGES", () => {
  assert.match(notes, /BREAKING CHANGES\n\n(\* .*\n)*\* \*\*litmask:\*\* probe migration note/, EMPTY_NOTES_HINT);
});

test("GIVEN a breaking refactor WHEN notes render THEN it has its own heading", () => {
  // Without a section the preset appends it headingless to BREAKING CHANGES.
  assert.match(notes, /### Code Refactoring\n\n\* \*\*litmask:\*\* reshape a probe type/, EMPTY_NOTES_HINT);
});

test("GIVEN a non-breaking refactor WHEN notes render THEN it is left out", () => {
  assert.doesNotMatch(notes, /tidy a probe internal/);
});
