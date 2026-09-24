import assert from "node:assert/strict";
import { test } from "node:test";

import { assertPackageSources, consumerView, followRenames, partitionCommits, sourcePaths } from "./shipped.mjs";

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

test("GIVEN a chain of renames ending at a shipped path WHEN followed THEN every earlier name ships", () => {
  // Renames arrive newest first, as `git log` lists them.
  const renames = [
    ["a/src/h2.rs", "a/src/i.rs"],
    ["a/src/h.rs", "a/src/h2.rs"],
  ];
  const shipped = followRenames(new Set(["a/src/i.rs"]), renames);
  assert.deepEqual([...shipped].sort(), ["a/src/h.rs", "a/src/h2.rs", "a/src/i.rs"]);
});

test("GIVEN a rename ending at an unshipped path WHEN followed THEN the old name stays out", () => {
  const shipped = followRenames(new Set(["a/src/lib.rs"]), [["a/src/x.rs", "scripts/x.rs"]]);
  assert.deepEqual([...shipped], ["a/src/lib.rs"]);
});

test("GIVEN sources inside the repo and the package WHEN checked THEN accepted", () => {
  assert.doesNotThrow(() => assertPackageSources("a", ["a/Cargo.toml", "Cargo.toml", "a/src/lib.rs", "LICENSE-MIT"]));
});

test("GIVEN a source resolved outside the repo WHEN checked THEN it throws", () => {
  // A path that can never match `git show` output would silently drop every commit.
  assert.throws(() => assertPackageSources("a", ["a/src/lib.rs", "../elsewhere/LICENSE"]), /outside the repository/);
});

test("GIVEN an absolute source path WHEN checked THEN it throws", () => {
  assert.throws(() => assertPackageSources("a", ["a/src/lib.rs", "/tmp/x"]), /outside the repository/);
});

test("GIVEN a package with no source file of its own WHEN checked THEN it throws", () => {
  // e.g. cargo's list layout changed and nothing maps under the package dir.
  assert.throws(() => assertPackageSources("a", ["a/Cargo.toml", "Cargo.toml"]), /no source file/);
});

const SHIPPED = new Set(["a/Cargo.toml", "Cargo.toml", "Cargo.lock", "a/src/lib.rs"]);

test("GIVEN a dependency-only commit that changes no consumer view WHEN partitioned THEN dropped", () => {
  const commit = { hash: "a", message: "fix(deps): bump a dev-dependency" };
  const { dropped } = partitionCommits([commit], () => ["a/Cargo.toml", "Cargo.lock"], SHIPPED, () => false);
  assert.deepEqual(dropped, [commit]);
});

test("GIVEN a dependency-only commit that changes the consumer view WHEN partitioned THEN kept", () => {
  const commit = { hash: "a", message: "fix(deps): bump a dependency" };
  const { kept } = partitionCommits([commit], () => ["Cargo.lock"], SHIPPED, () => true);
  assert.deepEqual(kept, [commit]);
});

test("GIVEN a commit touching shipped source too WHEN partitioned THEN kept without a view check", () => {
  const commit = { hash: "a", message: "fix(a): x" };
  const { kept } = partitionCommits([commit], () => ["a/src/lib.rs", "Cargo.lock"], SHIPPED, () => {
    throw new Error("view check must not run");
  });
  assert.deepEqual(kept, [commit]);
});

// Minimal `cargo metadata` (with resolve) for one workspace, rooted at `root`
// so two checkouts of the same tree differ only in paths.
function metadata({ root = "/w", devReq = "1", normReq = "1", normVersion = "1.0.0", devVersion = "1.0.0", toolsVersion = "0.1.0" } = {}) {
  const pkg = (name, extra) => ({
    name,
    version: "0.1.0",
    id: `path+file://${root}/${name}#0.1.0`,
    manifest_path: `${root}/${name}/Cargo.toml`,
    publish: null,
    features: {},
    dependencies: [],
    targets: [{ name, kind: ["lib"], src_path: `${root}/${name}/src/lib.rs` }],
    ...extra,
  });
  // Full metadata also lists every resolved registry package; they have
  // `publish: null` too but are not ours.
  const registry = (name, version) => ({
    name,
    version,
    id: `registry+x#${name}@${version}`,
    manifest_path: `/cargo/registry/${name}-${version}/Cargo.toml`,
    publish: null,
    features: {},
    dependencies: [],
    targets: [{ name, kind: ["lib"], src_path: `/cargo/registry/${name}-${version}/src/lib.rs` }],
  });
  return {
    workspace_root: root,
    workspace_members: [`path+file://${root}/app#0.1.0`, `path+file://${root}/tools#0.1.0`],
    packages: [
      registry("norm", normVersion),
      registry("dev", devVersion),
      pkg("app", {
        dependencies: [
          { name: "norm", req: normReq, kind: null, optional: false, path: `${root}/norm` },
          { name: "dev", req: devReq, kind: "dev", optional: false },
        ],
        targets: [{ name: "app", kind: ["bin"], src_path: `${root}/app/src/main.rs` }],
      }),
      pkg("tools", { publish: [], version: toolsVersion }),
    ],
    resolve: {
      nodes: [
        {
          id: `path+file://${root}/app#0.1.0`,
          deps: [
            { name: "norm", pkg: `registry+x#norm@${normVersion}`, dep_kinds: [{ kind: null }] },
            { name: "dev", pkg: `registry+x#dev@${devVersion}`, dep_kinds: [{ kind: "dev" }] },
          ],
        },
        { id: `registry+x#norm@${normVersion}`, deps: [] },
        { id: `registry+x#dev@${devVersion}`, deps: [] },
      ],
    },
  };
}

test("GIVEN two checkouts of one tree WHEN viewed THEN the views are equal", () => {
  assert.equal(consumerView(metadata({ root: "/w1" })), consumerView(metadata({ root: "/w2" })));
});

test("GIVEN a dev-dependency requirement change WHEN viewed THEN the view is unchanged", () => {
  assert.equal(consumerView(metadata()), consumerView(metadata({ devReq: "2" })));
});

test("GIVEN a normal dependency requirement change WHEN viewed THEN the view changes", () => {
  assert.notEqual(consumerView(metadata()), consumerView(metadata({ normReq: "2" })));
});

test("GIVEN a locked normal dependency bump in a crate with a binary WHEN viewed THEN the view changes", () => {
  // `cargo install --locked` builds the binary from the packaged lock.
  assert.notEqual(consumerView(metadata()), consumerView(metadata({ normVersion: "1.0.1" })));
});

test("GIVEN a locked dev-dependency bump WHEN viewed THEN the view is unchanged", () => {
  assert.equal(consumerView(metadata()), consumerView(metadata({ devVersion: "1.0.1" })));
});

test("GIVEN a change to an unpublished package WHEN viewed THEN the view is unchanged", () => {
  assert.equal(consumerView(metadata()), consumerView(metadata({ toolsVersion: "0.2.0" })));
});
