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

  # Upstream prebuilt binaries for the two tools the pinned nixpkgs ships
  # at the wrong version (it has cargo-llvm-cov 0.8.5 and
  # cargo-semver-checks 0.47.0; `.tool-versions` pins 0.8.7 and 0.50.0).
  #
  # Prebuilt rather than built from source: this nixpkgs revision's
  # `fetchCargoVendor` downloads crates through crates.io's API endpoint,
  # which now answers 403, so any from-source override fails to vendor.
  # These are the same release artifacts CI's `taiki-e/install-action`
  # installs, so the dev shell and CI run identical binaries.
  #
  # Bumping either version means replacing every hash below — get them
  # with `nix-prefetch-url <url>` piped through `nix hash to-sri`.
  releaseBinary =
    {
      pname,
      version,
      url,
      hashes,
      binaries,
    }:
    let
      system = pkgs.stdenv.hostPlatform.system;
      target =
        {
          aarch64-darwin = "aarch64-apple-darwin";
          x86_64-darwin = "x86_64-apple-darwin";
          aarch64-linux = "aarch64-unknown-linux-gnu";
          x86_64-linux = "x86_64-unknown-linux-gnu";
        }
        .${system}
          or (throw "${pname}: no prebuilt binary wired up for ${system}; add its target and hash in shell.nix");
    in
    pkgs.stdenv.mkDerivation {
      inherit pname version;
      src = pkgs.fetchurl {
        url = url target;
        hash = hashes.${target};
      };
      sourceRoot = ".";
      # The tarballs hold bare executables that need no build step and no
      # interpreter patching on Darwin.
      dontBuild = true;
      installPhase = ''
        runHook preInstall
        mkdir -p "$out/bin"
        for b in ${builtins.concatStringsSep " " binaries}; do
          install -m755 "$b" "$out/bin/$b"
        done
        runHook postInstall
      '';
    };

  cargo_llvm_cov = releaseBinary {
    pname = "cargo-llvm-cov";
    version = "0.8.7";
    url =
      target: "https://github.com/taiki-e/cargo-llvm-cov/releases/download/v0.8.7/cargo-llvm-cov-${target}.tar.gz";
    binaries = [ "cargo-llvm-cov" ];
    hashes = {
      aarch64-apple-darwin = "sha256-Pv7nMu1+mmU+INlskw4Ox5mQEonM6Q9GuyD2J+LA0uk=";
      x86_64-apple-darwin = "sha256-KIzgy5diB6mhrVr01+yaBsmvEWcnBm+yKH342dECa+k=";
      aarch64-unknown-linux-gnu = "sha256-jzmdhJk9E5mLY/vhCEN3cTxxmwBlXH2I1bVsjCkQXZA=";
      x86_64-unknown-linux-gnu = "sha256-mnX+KVONOACz2lf29u+2TLpccgole/DLi1HznUlakWg=";
    };
  };

  cargo_semver_checks = releaseBinary {
    pname = "cargo-semver-checks";
    version = "0.50.0";
    url =
      target: "https://github.com/obi1kenobi/cargo-semver-checks/releases/download/v0.50.0/cargo-semver-checks-${target}.tar.gz";
    binaries = [ "cargo-semver-checks" ];
    hashes = {
      aarch64-apple-darwin = "sha256-+Z+SjWdQHCnoQQAm8npUz3mfsTYRw7SmpY8ncs9+N5k=";
      x86_64-apple-darwin = "sha256-4yD3Noo9N6ltZQnA1d0dab3k6O9fy3bWC1paCuS3Vb4=";
      aarch64-unknown-linux-gnu = "sha256-419DXqMiZZOB9S5wNLtPBHAQj1smfSnxPPCBUvpK8ps=";
      x86_64-unknown-linux-gnu = "sha256-UqZdyI3FP6i1fWCHlU61LNoUnKA7z8p4zj/ezSP4k8Q=";
    };
  };
  # Reads channel/profile/components/targets straight from the same
  # `rust-toolchain.toml` that `.tool-versions` generates and that
  # `just check-tool-versions` validates.
  rust_toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

  # A second toolchain, for `just fuzz` only: cargo-fuzz needs a nightly
  # rustc for its `-Z` sanitizer flags. It is deliberately NOT in
  # `packages` — two toolchains cannot share PATH, since both ship
  # `cargo` and `rustc`, and the pinned stable one has to stay primary so
  # every other recipe builds at the MSRV. `RUST_NIGHTLY_BIN` below hands
  # `just fuzz` its path so it can put nightly in front for that one
  # command, which is also why no `+nightly` (a rustup-only spelling)
  # appears anywhere: there is no rustup in this shell.
  #
  # Date read from `.tool-versions` rather than written here, so the pin
  # has one home and `just check-tool-versions` can hold this shell to it.
  nightly_date =
    let
      lines = pkgs.lib.splitString "\n" (builtins.readFile ./.tool-versions);
      line = pkgs.lib.findFirst (l: pkgs.lib.hasPrefix "rust-nightly " l) null lines;
    in
    if line == null then
      throw "shell.nix: .tool-versions has no `rust-nightly <date>` line"
    else
      pkgs.lib.removePrefix "rust-nightly " line;
  rust_nightly = pkgs.rust-bin.nightly.${nightly_date}.default;
in
pkgs.mkShell {
  packages = with pkgs; [
    rust_toolchain
    just
    pre-commit
    cargo-deny
    cargo-machete
    cargo-mutants
    cargo-nextest
    typos
    taplo
    markdownlint-cli2
    actionlint
    nodejs_22
    # The pinned nixpkgs revision already ships these at the pinned
    # versions, so they need no override.
    cargo-fuzz
    hyperfine
    # Pinned-version prebuilt binaries; see the derivations above.
    cargo_llvm_cov
    cargo_semver_checks
  ];

  # Not a package: see `rust_nightly` above for why nightly stays off
  # PATH and is reached by path instead.
  RUST_NIGHTLY_BIN = "${rust_nightly}/bin";
}
