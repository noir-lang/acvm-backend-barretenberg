{
  description = "Build Barretenberg wrapper";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };

    barretenberg = {
      url = "github:AztecProtocol/barretenberg";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs =
    { self, nixpkgs, crane, flake-utils, rust-overlay, barretenberg, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            rust-overlay.overlays.default
            barretenberg.overlays.default
          ];
        };

        rustToolchain = pkgs.rust-bin.stable."1.66.0".default;

        craneLibScope = (crane.mkLib pkgs).overrideScope' (final: prev: {
          # As per https://discourse.nixos.org/t/gcc11stdenv-and-clang/17734/7
          stdenv = with pkgs;
            if (stdenv.targetPlatform.isGnu && stdenv.targetPlatform.isAarch64) then
              overrideCC llvmPackages.stdenv (llvmPackages.clang.override { gccForLibs = gcc11.cc; })
            else
              llvmPackages.stdenv;
              # overrideCC llvmPackages.stdenv (wrapCCWith {
              #   cc = llvmPackages.clang.override {
              #      gccForLibs = gcc11.cc;
              #   };
              #   bintools = llvmPackages.bintools;
              # });
        });

        craneLib = craneLibScope.overrideToolchain rustToolchain;

        environment = {
          # rust-bindgen needs to know the location of libclang
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          # We set the environment variable because requiring 2 versions of bb collide when pkg-config searches for it
          BARRETENBERG_BIN_DIR = "${pkgs.pkgsCross.wasi32.barretenberg}/bin";

          # We fetch the transcript as a dependency and provide it to the build.
          # This is necessary because the Nix sandbox is read-only and downloading during tests would fail
          BARRETENBERG_TRANSCRIPT = pkgs.fetchurl {
            url = "http://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/sealed/transcript00.dat";
            sha256 = "sha256-ryR/d+vpOCxa3gM0lze2UVUKNUinj0nN3ScCfysN84k=";
          };
        };

        commonArgs = {
          pname = "barretenberg-backend";
          version = "0.1.0";

          src = ./.;

          doCheck = false;

          nativeBuildInputs = [
            # This provides the pkg-config tool to find barretenberg & other native libraries
            pkgs.pkg-config
            # This provides the `lld` linker to cargo
            pkgs.llvmPackages.bintools
          ];

          buildInputs = [
            pkgs.llvmPackages.openmp
            pkgs.barretenberg
            pkgs.openssl
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            # Need libiconv and apple Security on Darwin. See https://github.com/ipetkov/crane/issues/156
            pkgs.libiconv
            pkgs.darwin.apple_sdk.frameworks.Security
          ];
        } // environment;

        # Build *just* the cargo dependencies, so we can reuse all of that work between runs
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        barretenberg-backend = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });
      in rec {
        checks = {
          cargo-check = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;

            doCheck = true;
          });

          cargo-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;

            cargoClippyExtraArgs = "--all-targets --workspace -- -D warnings";

            doCheck = true;
          });

          cargo-test = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;

            cargoTestArgs = "--workspace -- --test-threads=1";

            doCheck = true;
          });
        };

        packages.default = barretenberg-backend;

        # llvmPackages should be aligned to selection from libbarretenberg
        # better if we get rid of llvm targets and override them from input
        devShells.default = pkgs.mkShell.override { stdenv = pkgs.llvmPackages.stdenv; } ({
          inputsFrom = builtins.attrValues self.checks;

          buildInputs = packages.default.buildInputs;
          nativeBuildInputs = with pkgs; packages.default.nativeBuildInputs ++ [
            which
            starship
            git
            cargo
            rustc
          ];

          shellHook = ''
            eval "$(starship init bash)"
          '';

        } // environment);
      });
}
