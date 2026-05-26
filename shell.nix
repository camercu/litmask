# The pinned nixpkgs revision below determines the versions of every
# tool listed in `packages`. Pin a revision that ships versions
# matching `.tool-versions` (the single source of truth for CI), and
# run `just check-tool-versions` to verify the active shell matches.
let
  pinned_nixpkgs = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/566acc07c54dc807f91625bb286cb9b321b5f42a.tar.gz";
    sha256 = "19mppaiq05h4xrpch4i0jkkca4nnfdksc2fkhssplawggsj57id6";
  };
  pkgs = import pinned_nixpkgs { };
in
pkgs.mkShell {
  packages = with pkgs; [
    rustup
    just
    pre-commit
    cargo-deny
    cargo-nextest
    typos
    taplo
    nodejs_22
    # cargo-llvm-cov is omitted: the nixpkgs derivation is marked broken
    # (depends on a Rust nightly feature gate). Install locally via
    # `cargo install cargo-llvm-cov` or rely on CI's taiki-e/install-action.
  ];
}
