// Pure decisions for the release filter: which repo files feed a published
// crate, and which commits touched one. The git/cargo shell lives in
// shipped-commits.mjs.

import { posix } from "node:path";

export function partitionCommits(commits, filesOf, shipped) {
  const kept = [];
  const dropped = [];
  for (const commit of commits) {
    (filesOf(commit.hash).some((f) => shipped.has(f)) ? kept : dropped).push(commit);
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
