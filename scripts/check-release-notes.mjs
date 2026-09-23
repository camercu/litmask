// Renders release notes for synthetic commits through the exact
// release-notes-generator config in .releaserc.json and fails unless every
// consumer-facing section appears.
//
// Why: conventional-changelog-conventionalcommits 10 ships JS-function
// templates that only conventional-changelog-writer 9 understands, while
// @semantic-release/release-notes-generator 14 still runs writer 8. The
// mismatch renders a header with an empty body and raises no error, so
// v0.21.0..v0.21.5 shipped blank CHANGELOG entries and GitHub releases.
// Only rendering real notes catches that class of silent break.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(`${process.cwd()}/package.json`);
const { generateNotes } = await import(
  require.resolve("@semantic-release/release-notes-generator")
);

const plugin = JSON.parse(readFileSync(".releaserc.json", "utf8")).plugins.find(
  (p) => Array.isArray(p) && p[0] === "@semantic-release/release-notes-generator",
);
if (!plugin) {
  console.error("release-notes-generator not configured in .releaserc.json");
  process.exit(1);
}

const commits = [
  { hash: "a".repeat(40), message: "feat(litmask): add a probe feature" },
  { hash: "b".repeat(40), message: "fix(litmask): repair a probe bug" },
  {
    hash: "c".repeat(40),
    message: "feat(litmask)!: change a probe API\n\nBREAKING CHANGE: probe migration note",
  },
  {
    hash: "d".repeat(40),
    message: "refactor(litmask)!: reshape a probe type\n\nBREAKING CHANGE: probe refactor note",
  },
  { hash: "e".repeat(40), message: "refactor(litmask): tidy a probe internal" },
];

const notes = await generateNotes(plugin[1], {
  cwd: process.cwd(),
  options: { repositoryUrl: "https://github.com/camercu/litmask.git" },
  commits,
  lastRelease: { gitTag: "v0.0.0", version: "0.0.0" },
  nextRelease: { gitTag: "v0.1.0", version: "0.1.0" },
  logger: { log() {}, error: console.error },
});

const expected = [
  "### Features",
  "add a probe feature",
  "### Bug Fixes",
  "repair a probe bug",
  "BREAKING CHANGES",
  "probe migration note",
  // A breaking refactor must sit under its own heading, not as a
  // headingless list tacked onto BREAKING CHANGES.
  "### Code Refactoring\n\n* **litmask:** reshape a probe type",
  "probe refactor note",
];
// Non-breaking internal work stays out of consumer notes.
const unexpected = ["tidy a probe internal"];
const missing = expected.filter((s) => !notes.includes(s));
const leaked = unexpected.filter((s) => notes.includes(s));
if (missing.length > 0 || leaked.length > 0) {
  console.error(
    `release notes are missing: [${missing.join(", ")}]; leak: [${leaked.join(", ")}]\n` +
      "Empty notes usually mean the conventional-changelog-conventionalcommits major no longer " +
      "matches the writer that release-notes-generator bundles; see this script's header.\n" +
      `--- rendered:\n${notes}`,
  );
  process.exit(1);
}
console.log("release notes render all sections");
