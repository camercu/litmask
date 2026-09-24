// Runs the release filter against a throwaway git repo holding a tiny cargo
// workspace (no registry deps, so cargo works offline). Each scenario commit
// lands after the `v0.1.0` tag; the tests assert which ones the filter keeps.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";

import { analyzeCommits, generateNotes, selectShipped } from "./shipped-commits.mjs";

// A released fixture: a workspace with publishable crate `a` (readme from
// the root, symlinked license) and unpublished `tools`, tagged `v0.1.0`.
function releasedWorkspace() {
  const repo = mkdtempSync(join(tmpdir(), "litmask-release-"));
  const git = (...args) =>
    execFileSync("git", ["-c", "user.name=fixture", "-c", "user.email=fixture@invalid", ...args], {
      cwd: repo,
      encoding: "utf8",
    }).trim();
  const write = (path, text) => {
    mkdirSync(dirname(join(repo, path)), { recursive: true });
    writeFileSync(join(repo, path), text);
  };
  const commit = (message) => {
    git("add", "-A");
    git("commit", "-q", "--allow-empty", "-m", message);
  };
  const context = () => ({
    cwd: repo,
    options: { repositoryUrl: "https://example.invalid/fixture.git" },
    commits: git("log", "--format=%H%x1f%B%x1e", "v0.1.0..HEAD")
      .split("\x1e")
      .map((r) => r.trim())
      .filter(Boolean)
      .map((r) => {
        const [hash, message] = r.split("\x1f");
        return { hash, message: message.trim() };
      }),
    lastRelease: { gitTag: "v0.1.0", gitHead: git("rev-parse", "v0.1.0^{commit}"), version: "0.1.0" },
    nextRelease: { gitTag: "v0.1.1", version: "0.1.1" },
    logger: { log() {}, error() {} },
  });

  git("init", "-q", "-b", "main");
  write(
    "Cargo.toml",
    '[workspace]\nmembers = ["a", "tools"]\nresolver = "3"\n\n' +
      '[workspace.package]\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\n',
  );
  write(
    "a/Cargo.toml",
    '[package]\nname = "a"\ndescription = "fixture"\nreadme = "../README.md"\n' +
      "version.workspace = true\nedition.workspace = true\nlicense.workspace = true\n",
  );
  write("a/src/lib.rs", "pub fn a() {}\n");
  write("a/src/old.rs", "// removed after the release\n");
  write("a/src/f.rs", "// renamed after the release\n");
  write(
    "tools/Cargo.toml",
    '[package]\nname = "tools"\npublish = false\nversion.workspace = true\nedition.workspace = true\n',
  );
  write("tools/src/main.rs", "fn main() {}\n");
  write("README.md", "fixture\n");
  write("LICENSE-MIT", "MIT\n");
  symlinkSync("../LICENSE-MIT", join(repo, "a/LICENSE-MIT"));
  write(".github/ci.yml", "on: push\n");
  execFileSync("cargo", ["generate-lockfile", "--offline"], { cwd: repo, stdio: "ignore" });
  commit("chore: initial");
  git("tag", "v0.1.0");
  return { repo, git, write, commit, context };
}

const fixtures = [];
after(() => {
  for (const f of fixtures) rmSync(f.repo, { recursive: true, force: true });
});

let context;
let kept;
let dropped;
const subjects = (commits) => commits.map((c) => c.message.split("\n")[0]);

before(() => {
  const f = releasedWorkspace();
  fixtures.push(f);
  const { git, write, commit } = f;
  context = f.context;

  write("a/src/lib.rs", "pub fn a() { /* fixed */ }\n");
  commit("fix(a): repair lib");
  write(".github/ci.yml", "on: [push, pull_request]\n");
  commit("fix(ci): tweak ci");
  write("tools/src/main.rs", "fn main() { /* fixed */ }\n");
  commit("fix(tools): tweak unpublished tool");
  write("README.md", "fixture, clearer\n");
  commit("docs: reword the crate readme");
  write("LICENSE-MIT", "MIT License\n");
  commit("chore: reword the license");
  git("rm", "-q", "a/src/old.rs");
  commit("fix(a)!: remove old module");
  write("a/src/f.rs", "// renamed after the release, fixed\n");
  commit("fix(a): repair f");
  git("mv", "a/src/f.rs", "a/src/g.rs");
  commit("refactor(a): rename f to g");
  write("a/src/h.rs", "// added after the release\n");
  commit("feat(a): add h");
  write("a/src/h.rs", "// added after the release, fixed\n");
  commit("fix(a): repair h");
  git("mv", "a/src/h.rs", "a/src/i.rs");
  commit("refactor(a): rename h to i");
  git("switch", "-q", "-c", "topic");
  write("a/src/lib.rs", "pub fn a() { /* fixed on a branch */ }\n");
  commit("wip");
  git("switch", "-q", "main");
  git("merge", "-q", "--no-ff", "-m", "fix(a): merged fix (#1)", "topic");

  ({ kept, dropped } = selectShipped(context()));
});

test("GIVEN a fix to a published source WHEN filtered THEN kept", () => {
  assert.ok(subjects(kept).includes("fix(a): repair lib"));
});

test("GIVEN a fix to CI only WHEN filtered THEN dropped", () => {
  assert.ok(subjects(dropped).includes("fix(ci): tweak ci"));
});

test("GIVEN a fix to an unpublished crate WHEN filtered THEN dropped", () => {
  assert.ok(subjects(dropped).includes("fix(tools): tweak unpublished tool"));
});

test("GIVEN a change to a readme packaged from outside the crate WHEN filtered THEN kept", () => {
  assert.ok(subjects(kept).includes("docs: reword the crate readme"));
});

test("GIVEN a change to a symlinked packaged file's target WHEN filtered THEN kept", () => {
  assert.ok(subjects(kept).includes("chore: reword the license"));
});

test("GIVEN a commit deleting a published file WHEN filtered THEN kept", () => {
  assert.ok(subjects(kept).includes("fix(a)!: remove old module"));
});

test("GIVEN a fix to a published file renamed later WHEN filtered THEN kept", () => {
  assert.ok(subjects(kept).includes("fix(a): repair f"));
});

test("GIVEN a fix to a new file renamed later WHEN filtered THEN kept", () => {
  // h.rs exists at neither the last release nor HEAD; only the rename links it to i.rs.
  assert.ok(subjects(kept).includes("fix(a): repair h"));
});

test("GIVEN a merge whose title carries the fix WHEN filtered THEN kept", () => {
  // A clean merge has an empty combined diff; its first-parent diff is what it brings to main.
  assert.ok(subjects(kept).includes("fix(a): merged fix (#1)"));
});

const PRESET = { preset: "conventionalcommits" };
const only = (...wanted) => {
  const ctx = context();
  ctx.commits = ctx.commits.filter((c) => wanted.includes(c.message.split("\n")[0]));
  return ctx;
};

test("GIVEN tooling-only fixes WHEN analyzed THEN no release", async () => {
  assert.equal(await analyzeCommits(PRESET, only("fix(ci): tweak ci", "fix(tools): tweak unpublished tool")), null);
});

test("GIVEN a published fix among tooling fixes WHEN analyzed THEN patch", async () => {
  assert.equal(await analyzeCommits(PRESET, only("fix(a): repair lib", "fix(ci): tweak ci", "fix(tools): tweak unpublished tool")), "patch");
});

test("GIVEN a published fix WHEN notes render THEN it is listed", async () => {
  assert.match(await generateNotes(PRESET, context()), /repair lib/);
});

test("GIVEN a tooling fix WHEN notes render THEN it is left out", async () => {
  assert.doesNotMatch(await generateNotes(PRESET, context()), /tweak ci/);
});

test("GIVEN a committed Cargo.lock that is stale WHEN filtered THEN it fails instead of rewriting the lock", () => {
  // The release commit ships the lock, so a quiet rewrite would publish an unreviewed lock.
  const f = releasedWorkspace();
  fixtures.push(f);
  f.write("Cargo.toml", '[workspace]\nmembers = ["a", "tools", "b"]\nresolver = "3"\n\n' +
    '[workspace.package]\nversion = "0.1.0"\nedition = "2021"\nlicense = "MIT"\n');
  f.write("b/Cargo.toml", '[package]\nname = "b"\ndescription = "fixture"\n' +
    "version.workspace = true\nedition.workspace = true\nlicense.workspace = true\n");
  f.write("b/src/lib.rs", "\n");
  f.commit("feat(b): add crate b without updating the lock");
  assert.throws(() => selectShipped(f.context()), /lock/i);
});
