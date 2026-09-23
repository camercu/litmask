import assert from "node:assert/strict";
import { test } from "node:test";

import { partitionCommits, sourcePaths } from "./shipped.mjs";

test("GIVEN a commit touching a shipped file WHEN partitioned THEN it is kept", () => {
  const commit = { hash: "a", message: "fix(litmask): x" };
  const { kept } = partitionCommits([commit], () => ["litmask/src/lib.rs"], new Set(["litmask/src/lib.rs"]));
  assert.deepEqual(kept, [commit]);
});

test("GIVEN a commit touching only unshipped files WHEN partitioned THEN it is dropped", () => {
  const commit = { hash: "a", message: "fix(ci): x" };
  const { dropped } = partitionCommits([commit], () => [".github/workflows/ci.yml"], new Set(["litmask/src/lib.rs"]));
  assert.deepEqual(dropped, [commit]);
});

const identity = (p) => p;

test("GIVEN an ordinary packaged file WHEN mapped THEN it is the file under the package dir", () => {
  const pkg = { dir: "litmask", readme: null, entries: ["src/lib.rs"] };
  assert.deepEqual(sourcePaths(pkg, identity), ["litmask/src/lib.rs"]);
});

test("GIVEN cargo-generated entries WHEN mapped THEN they have no source", () => {
  const pkg = { dir: "litmask", readme: null, entries: [".cargo_vcs_info.json", "Cargo.toml"] };
  assert.deepEqual(sourcePaths(pkg, identity), []);
});

test("GIVEN a symlinked packaged file WHEN mapped THEN the resolver names its target", () => {
  const pkg = { dir: "litmask", readme: null, entries: ["LICENSE-MIT"] };
  assert.deepEqual(sourcePaths(pkg, () => "LICENSE-MIT"), ["LICENSE-MIT"]);
});

test("GIVEN the packaged manifest source WHEN mapped THEN crate and workspace manifests feed it", () => {
  // The published Cargo.toml inlines `*.workspace = true` keys from the root.
  const pkg = { dir: "litmask", readme: null, entries: ["Cargo.toml.orig"] };
  assert.deepEqual(sourcePaths(pkg, identity), ["litmask/Cargo.toml", "Cargo.toml"]);
});

test("GIVEN a packaged Cargo.lock WHEN mapped THEN the workspace lock feeds it", () => {
  const pkg = { dir: "litmask-cli", readme: null, entries: ["Cargo.lock"] };
  assert.deepEqual(sourcePaths(pkg, identity), ["Cargo.lock"]);
});

test("GIVEN a readme outside the package WHEN mapped THEN the packaged copy maps to it", () => {
  const pkg = { dir: "litmask-cli", readme: "../README.md", entries: ["README.md"] };
  assert.deepEqual(sourcePaths(pkg, identity), ["README.md"]);
});
