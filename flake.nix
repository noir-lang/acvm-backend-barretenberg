{
  inputs = {

    nixpkgs.url = "nixpkgs/nixpkgs-unstable";

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    utils = {
      url = "github:numtide/flake-utils";
      inputs.nixpkgs.follows = "nixpkgs";
    };

  };

  outputs = inputs@{ self, nixpkgs, utils, ... }:
    utils.lib.eachDefaultSystem (system:
      let
        
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import inputs.rust-overlay)
          ];
        };

        wasm_pack = pkgs.callPackage ./nix/wasm-pack/default.nix {};

        rust-toolchain = pkgs.rust-bin.stable.latest.default.override {
          targets = [
            "wasm32-unknown-unknown"
          ];
        };
        craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rust-toolchain;

        # craneLib.cleanCargoSources 
        src = ./.;
        
        cargoArtifacts = craneLib.buildDepsOnly {
          inherit src;
          cargoExtraArgs = "--package aztec_backend_wasm --target wasm32-unknown-unknown";
          doCheck = false;
        };
      in
      rec {
        packages.default = craneLib.mkCargoDerivation {
          pname = "aztec_backend";
          # name = "aztec_backend";
          version = "0.8.0";
          inherit cargoArtifacts src;

          WASM_PACK_VAR = wasm_pack;
          buildPhaseCargoCommand = ''
            echo "WASM_PACK = $WASM_PACK_VAR"
            wasm-pack build --dev --scope noir-lang --target nodejs --out-dir nodejs aztec_backend_wasm 
            wasm-pack build --dev --scope noir-lang --target web --out-dir web aztec_backend_wasm
          '';

          installPhaseCommand = ''
            # Install whatever is needed
            mkdir -p $out/nodejs
            mkdir -p $out/web
            find aztec_backend_wasm/nodejs -type f \( -name "*.js" -o -name "*.ts" -o -name "*.wasm" \) -exec cp {} $out/nodejs \;
            find aztec_backend_wasm/web -type f \( -name "*.js" -o -name "*.ts" -o -name "*.wasm" \) -exec cp {} $out/web \;
            jq '{ name: .name, version: .version, main: ("nodejs/" + .module), module: ("web/" + .module), files: [ "nodejs", "web", "package.json"], types: ("web/" + .types), repository: { "type" : "git", "url" : "https://github.com/noir-lang/aztec-backend.git" } }' aztec_backend_wasm/web/package.json > $out/package.json;
          '';

          nativeBuildInputs = with pkgs; [
            binaryen
            # Use forked version of wasm-pack to work around bin/bin problem
            # https://github.com/rustwasm/wasm-pack/issues/1263
            # wasm-pack
            wasm_pack
            wasm-bindgen-cli
            jq
          ];
        };
      }
    );
}
