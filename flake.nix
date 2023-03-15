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
        });

        craneLib = craneLibScope.overrideToolchain rustToolchain;

        environment = {
          # rust-bindgen needs to know the location of libclang
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          # We set the environment variable because requiring 2 versions of bb collide when pkg-config searches for it
          BARRETENBERG_WASM = "${pkgs.pkgsCross.wasi32.barretenberg}/bin/barretenberg.wasm";

          NOIR_TRANSCRIPT = pkgs.fetchurl {
            url = "http://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/sealed/transcript00.dat";
            sha256 = "sha256-ryR/d+vpOCxa3gM0lze2UVUKNUinj0nN3ScCfysN84k=";
          };
        };

        barretenberg-backend = craneLib.buildPackage({
          pname = "aztec_backend";
          version = "0.1.0";

          src = craneLib.cleanCargoSource ./.;

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
        } // environment);
      in rec {
        checks = { inherit barretenberg-backend; };

        packages.default = barretenberg-backend;

        devShells.default = pkgs.mkShell ({
          inputsFrom = builtins.attrValues self.checks;

          buildInputs = packages.default.buildInputs;
          nativeBuildInputs = packages.default.nativeBuildInputs;
        } // environment);
      });
}
