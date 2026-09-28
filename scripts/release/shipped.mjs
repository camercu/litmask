// Pure decisions for the release filter: which repo files feed a published
// crate, and which commits touched one. The git/cargo shell lives in
// shipped-commits.mjs.

import { posix } from "node:path";

const isDependencyFile = (path) => /(^|\/)Cargo\.(toml|lock)$/.test(path);

// A commit ships if it touches a shipped file. When every such file is a
// manifest or lock, it ships only if `viewChanged(hash)` says the
// dependencies consumers resolve changed (a dev-dependency bump does not).
export function partitionCommits(commits, filesOf, shipped, viewChanged) {
  const kept = [];
  const dropped = [];
  for (const commit of commits) {
    const touched = filesOf(commit.hash).filter((f) => shipped.has(f));
    const ships = touched.length > 0 && (!touched.every(isDependencyFile) || viewChanged(commit.hash));
    (ships ? kept : dropped).push(commit);
  }
  return { kept, dropped };
}

// Entries cargo writes into the .crate itself; no repo file backs them.
const GENERATED = new Set([".cargo_vcs_info.json", "Cargo.toml"]);

// `resolve` maps a repo-relative path through symlinks (the shell uses
// realpath), so a crate's LICENSE link counts as the workspace file.
export function sourcePaths(pkg, resolve) {
  const readme = pkg.readme && posix.normalize(`${pkg.dir}/${pkg.readme}`);
  return pkg.entries.flatMap((e) => {
    if (GENERATED.has(e)) return [];
    // cargo normalizes the crate manifest and inlines `*.workspace = true`
    // keys from the root manifest into the published Cargo.toml.
    if (e === "Cargo.toml.orig") return [`${pkg.dir}/Cargo.toml`, "Cargo.toml"];
    // A packaged lock is cut from the workspace lock.
    if (e === "Cargo.lock") return ["Cargo.lock"];
    // cargo copies a readme from anywhere to the package root.
    if (readme && e === posix.basename(readme)) return [readme];
    return [resolve(`${pkg.dir}/${e}`)];
  });
}

// A file added and renamed within one release window exists at neither end,
// so a commit that edited it under its old name must inherit the new name's
// shipped status. `renames` is [old, new] pairs, newest first (git log
// order), so one pass walks each chain back from its shipped end.
export function followRenames(shipped, renames) {
  const out = new Set(shipped);
  for (const [from, to] of renames) if (out.has(to)) out.add(from);
  return out;
}

// A wrong mapping fails quietly: paths that never match `git show` output
// drop every commit, so the release just stops. Refuse such a set instead.
export function assertPackageSources(dir, paths) {
  const outside = paths.filter((p) => posix.isAbsolute(p) || p === ".." || p.startsWith("../"));
  if (outside.length > 0) {
    throw new Error(`package ${dir}: sources outside the repository: ${outside.join(", ")}`);
  }
  if (!paths.some((p) => p.startsWith(`${dir}/`) && p !== `${dir}/Cargo.toml`)) {
    throw new Error(`package ${dir}: no source file maps under the package directory`);
  }
}

// The workspace's own packages that go to a registry. Full metadata also
// lists every resolved registry package, each with `publish: null`, so
// membership is checked first; `publish = false` reads as `[]`.
export function publishedMembers(meta) {
  const members = new Set(meta.workspace_members);
  return meta.packages.filter((p) => members.has(p.id) && (p.publish === null || p.publish.length > 0));
}
const notDev = (dep) => dep.kind !== "dev";

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, canonical(value[k])]));
  }
  return value;
}

// What consumers of the published crates resolve, as a comparable string:
// each published package's metadata without dev-dependencies or checkout
// paths, plus, for a package with a binary, the locked non-dev dependency
// closure (`cargo install --locked` builds from the packaged lock), plus
// its packaged file list, since include/exclude never reach metadata.
// `meta` is full `cargo metadata` output, resolve graph included;
// `packageLists` maps a package name to its `cargo package --list` lines.
export function consumerView(meta, packageLists = {}) {
  const label = new Map(meta.packages.map((p) => [p.id, `${p.name}@${p.version}`]));
  const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
  // cargo resolves one graph for the whole workspace, so a dev-dependency
  // bump that turns on a feature of a shared crate can add an edge here and
  // keep the commit. That errs toward releasing, which is the safe side.
  const lockedClosure = (root) => {
    const seen = new Set();
    const todo = [root];
    while (todo.length > 0) {
      for (const dep of nodes.get(todo.pop())?.deps ?? []) {
        if (!dep.dep_kinds.some(notDev) || seen.has(dep.pkg)) continue;
        seen.add(dep.pkg);
        todo.push(dep.pkg);
      }
    }
    return [...seen].map((id) => label.get(id) ?? id).sort();
  };
  const view = publishedMembers(meta)
    .map(({ id, manifest_path, source, dependencies, targets, ...rest }) => ({
      ...rest,
      dependencies: dependencies.filter(notDev).map(({ path, ...dep }) => dep),
      targets: targets.map(({ src_path, ...target }) => target),
      locked: targets.some((t) => t.kind.includes("bin")) ? lockedClosure(id) : null,
      files: [...(packageLists[rest.name] ?? [])].sort(),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return JSON.stringify(canonical(view));
}
