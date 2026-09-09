{
  description = "Dev environment for co-snarks (coCircom / coNoir)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # co-snarks is a pure-Rust workspace (see Cargo.toml). Pull in a
        # recent stable toolchain plus the components clippy/rustfmt/etc.
        # that CONTRIBUTING.md and the justfile expect.
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "co-snarks";

          packages = with pkgs; [
            rustToolchain

            # Build-time deps for crates in the workspace that link native libs
            # (e.g. via reqwest/openssl-sys, protobuf, etc.)
            pkg-config
            openssl
            cmake
            protobuf

            # Task runner used by the repo's justfile
            just

            # Linting/CI helpers referenced by CONTRIBUTING.md / deny.toml / .typos.toml
            cargo-nextest
            cargo-deny
            cargo-audit
            typos

            # coCircom needs circom to compile circuits, and snarkjs (npm) to
            # generate/verify proofs interoperably.
            circom
            nodejs_22
          ];

          shellHook = ''
            export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export RUST_SRC_PATH="${rustToolchain}/lib/rustlib/src/rust/library"

            # snarkjs isn't packaged in nixpkgs in a way that matches upstream
            # closely, so install it locally via npm on first entry.
            if ! command -v snarkjs >/dev/null 2>&1 && [ ! -x node_modules/.bin/snarkjs ]; then
              echo "Installing snarkjs locally via npm (first run only)..."
              npm install --no-save snarkjs >/dev/null 2>&1 || true
            fi
            export PATH="$PWD/node_modules/.bin:$PATH"

            echo "=============================================================="
            echo "Welcome to co-snarks devenv by TACEO 🔐"
            echo "=============================================================="
            rustc --version
            cargo --version
            circom --version 2>/dev/null || true
            echo "--------------------------------------------------------------"
            just --list
            echo "--------------------------------------------------------------"
          '';
        };
      });
}
