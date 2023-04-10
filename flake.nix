{
  description = "Build the Barretenberg acvm backend";

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

      craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

      environment = {
        # rust-bindgen needs to know the location of libclang
        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

        # We set the environment variable because barretenberg must be compiled in a special way for wasm
        BARRETENBERG_BIN_DIR = "${pkgs.barretenberg-wasm}/bin";

        # We provide `barretenberg-transcript00` from the overlay to the build.
        # This is necessary because the Nix sandbox is read-only and downloading during tests would fail
        BARRETENBERG_TRANSCRIPT = pkgs.barretenberg-transcript00;
      };

      # We use `include_str!` macro to embed the solidity verifier template so we need to create a special
      # source filter to include .sol files in addition to usual rust/cargo source files
      solidityFilter = path: _type: builtins.match ".*sol$" path != null;
      sourceFilter = path: type:
        (solidityFilter path type) || (craneLib.filterCargoSources path type);

      commonArgs = {
        # TODO: Rename repository
        pname = "acvm-backend-barretenberg";
        # TODO: Add release-please
        version = "0.0.0";

        # As per https://discourse.nixos.org/t/gcc11stdenv-and-clang/17734/7 since it seems that aarch64-linux uses
        # gcc9 instead of gcc11 for the C++ stdlib, while all other targets we support provide the correct libstdc++
        stdenv = with pkgs;
          if (stdenv.targetPlatform.isGnu && stdenv.targetPlatform.isAarch64) then
            overrideCC llvmPackages.stdenv (llvmPackages.clang.override { gccForLibs = gcc11.cc; })
          else
            llvmPackages.stdenv;

        src = pkgs.lib.cleanSourceWith {
          src = craneLib.path ./.;
          filter = sourceFilter;
        };

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
        ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
          # Need libiconv and apple Security on Darwin. See https://github.com/ipetkov/crane/issues/156
          pkgs.libiconv
          pkgs.darwin.apple_sdk.frameworks.Security
        ];
      } // environment;

      # Build *just* the cargo dependencies, so we can reuse all of that work between runs
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;

      acvm-backend-barretenberg = craneLib.buildPackage (commonArgs // {
        inherit cargoArtifacts;
      });
    in
    rec {
      checks = {
        cargo-clippy = craneLib.cargoClippy (commonArgs // {
          inherit cargoArtifacts;

          cargoClippyExtraArgs = "--all-targets --workspace -- -D warnings";

          doCheck = true;
        });

        cargo-test = craneLib.cargoTest (commonArgs // {
          inherit cargoArtifacts;

          cargoTestExtraArgs = "--workspace -- --test-threads=1";

          doCheck = true;
        });
      };

      packages.default = acvm-backend-barretenberg;

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
