# The pinned nixpkgs revision below determines the versions of every
# tool in `packages` except the Rust toolchain. Pin a revision that
# ships versions matching `.tool-versions` (the single source of truth
# for CI), and run `just check-tool-versions` to verify the active
# shell matches.
#
# The Rust toolchain comes from `rust-overlay` (not nixpkgs/rustup): it
# materializes an immutable toolchain from `rust-toolchain.toml`, so the
# dev shell has exactly CI's channel, profile, components, and targets —
# independent of any mutable `~/.rustup` state. This keeps local builds
# byte-for-byte aligned with CI (e.g. `rust-src` is absent, matching the
# `dtolnay/rust-toolchain` provisioning in `.github/workflows/ci.yml`).
let
  pinned_nixpkgs = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/566acc07c54dc807f91625bb286cb9b321b5f42a.tar.gz";
    sha256 = "19mppaiq05h4xrpch4i0jkkca4nnfdksc2fkhssplawggsj57id6";
  };
  rust_overlay = builtins.fetchTarball {
    url = "https://github.com/oxalica/rust-overlay/archive/d286e9691bb03045febbf8304a658eab1487d1b5.tar.gz";
    sha256 = "0darpyzxsfi4zcvg327dj4j4hr3rzr1ah05msspcakkz1cg8cnxm";
  };
  pkgs = import pinned_nixpkgs { overlays = [ (import rust_overlay) ]; };
  # Reads channel/profile/components/targets straight from the same
  # `rust-toolchain.toml` that `.tool-versions` generates and that
  # `just check-tool-versions` validates.
  rust_toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
in
pkgs.mkShell {
  packages = with pkgs; [
    rust_toolchain
    just
    pre-commit
    cargo-deny
    cargo-nextest
    typos
    taplo
    markdownlint-cli2
    actionlint
    nodejs_22
    # cargo-llvm-cov is omitted: the nixpkgs derivation is marked broken
    # (depends on a Rust nightly feature gate). Install locally via
    # `cargo install cargo-llvm-cov` or rely on CI's taiki-e/install-action.
    # cargo-semver-checks is omitted: pinned nixpkgs ships 0.41.0 but
    # .tool-versions pins 0.44.0. Install locally via
    # `cargo install cargo-semver-checks` or rely on CI's taiki-e/install-action.
  ];
}
