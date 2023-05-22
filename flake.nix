{
  description = "An ACVM backend which allows proving/verifying ACIR circuits against Aztec Lab's Barretenberg library.";

  inputs = {
    nixpkgs = {
      url = "github:NixOS/nixpkgs/nixos-22.11";
    };

    flake-utils = {
      url = "github:numtide/flake-utils";
    };

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      # All of these inputs (a.k.a. dependencies) need to align with inputs we
      # use so they use the `inputs.*.follows` syntax to reference our inputs
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };

    crane = {
      url = "github:ipetkov/crane";
      # All of these inputs (a.k.a. dependencies) need to align with inputs we
      # use so they use the `inputs.*.follows` syntax to reference our inputs
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
        flake-compat.follows = "flake-compat";
        rust-overlay.follows = "rust-overlay";
      };
    };

    barretenberg = {
      url = "github:AztecProtocol/barretenberg";
      # All of these inputs (a.k.a. dependencies) need to align with inputs we
      # use so they use the `inputs.*.follows` syntax to reference our inputs
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

      rustToolchain = pkgs.rust-bin.stable."1.66.0".default.override {
        # We include rust-src to ensure rust-analyzer works.
        # See https://discourse.nixos.org/t/rust-src-not-found-and-other-misadventures-of-developing-rust-on-nixos/11570/4
        extensions = [ "rust-src" ];
        targets = [ "wasm32-unknown-unknown" ]
          ++ pkgs.lib.optional (pkgs.hostPlatform.isx86_64 && pkgs.hostPlatform.isLinux) "x86_64-unknown-linux-gnu"
          ++ pkgs.lib.optional (pkgs.hostPlatform.isAarch64 && pkgs.hostPlatform.isLinux) "aarch64-unknown-linux-gnu"
          ++ pkgs.lib.optional (pkgs.hostPlatform.isx86_64 && pkgs.hostPlatform.isDarwin) "x86_64-apple-darwin"
          ++ pkgs.lib.optional (pkgs.hostPlatform.isAarch64 && pkgs.hostPlatform.isDarwin) "aarch64-apple-darwin";
      };

      craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

      wasm-bindgen-cli = craneLib.buildPackage rec {
        pname = "wasm-bindgen-cli";
        version = "0.2.86";

        src = pkgs.fetchCrate {
          inherit pname version;
          sha256 = "sha256-56EOiLbdgAcoTrkyvB3t9TjtLaRvGxFUXx4haLwE2QY=";
        };

        nativeBuildInputs = [
          pkgs.pkg-config
        ];

        buildInputs = [
          pkgs.openssl
        ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.curl
          pkgs.darwin.apple_sdk.frameworks.Security
        ];

        doCheck = false;
      };

      nativeEnvironment = {
        # rust-bindgen needs to know the location of libclang
        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
      };

      wasmEnvironment = {
        # We set the environment variable because barretenberg must be compiled in a special way for wasm
        BARRETENBERG_BIN_DIR = "${pkgs.barretenberg-wasm}/bin";
      };

      testEnvironment = {
        # Barretenberg fails if tests are run on multiple threads, so we set the test thread
        # count to 1 throughout the entire project
        #
        # Note: Setting this allows for consistent behavior across build and shells, but is mostly
        # hidden from the developer - i.e. when they see the command being run via `nix flake check`
        RUST_TEST_THREADS = "1";

        CHROMEDRIVER="${pkgs.chromedriver}/bin/chromedriver";
        WASM_BINDGEN_TEST_TIMEOUT = "3000";
      };

      # We use `include_str!` macro to embed the solidity verifier template so we need to create a special
      # source filter to include .sol files in addition to usual rust/cargo source files
      solidityFilter = path: _type: builtins.match ".*sol$" path != null;
      webdriverJsonFilter = path: _type: builtins.match ".*json$" path != null;
      sourceFilter = path: type:
        (solidityFilter path type) || (webdriverJsonFilter path type) || (craneLib.filterCargoSources path type);

      # As per https://discourse.nixos.org/t/gcc11stdenv-and-clang/17734/7 since it seems that aarch64-linux uses
      # gcc9 instead of gcc11 for the C++ stdlib, while all other targets we support provide the correct libstdc++
      stdenv =
        if (pkgs.stdenv.targetPlatform.isGnu && pkgs.stdenv.targetPlatform.isAarch64) then
          pkgs.overrideCC pkgs.llvmPackages.stdenv (pkgs.llvmPackages.clang.override { gccForLibs = pkgs.gcc11.cc; })
        else
          pkgs.llvmPackages.stdenv;

      extraBuildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
        # Need libiconv and apple Security on Darwin. See https://github.com/ipetkov/crane/issues/156
        pkgs.libiconv
        pkgs.darwin.apple_sdk.frameworks.Security
      ];

      commonArgs = {
        # x-release-please-start-version
        version = "0.2.0";
        # x-release-please-end

        src = pkgs.lib.cleanSourceWith {
          src = craneLib.path ./.;
          filter = sourceFilter;
        };

        # Running checks don't do much more than compiling itself and increase
        # the build time by a lot, so we disable them throughout all our flakes
        doCheck = false;
      };

      # Combine the environment and other configuration needed for crane to build with the native feature
      nativeArgs = nativeEnvironment // commonArgs // {
        pname = "native";

        # Use our custom stdenv to build and test our Rust project
        inherit stdenv;

        nativeBuildInputs = [
          # This provides the pkg-config tool to find barretenberg & other native libraries
          pkgs.pkg-config
          # This provides the `lld` linker to cargo
          pkgs.llvmPackages.bintools
        ];

        buildInputs = [
          pkgs.llvmPackages.openmp
          pkgs.barretenberg
        ] ++ extraBuildInputs;
      };

      # Combine the environment and other configuration needed for crane to build with the wasm feature
      wasmArgs = wasmEnvironment // commonArgs // {
        pname = "wasm";

        # We disable the default "native" feature and enable the "wasm" feature
        cargoExtraArgs = "--no-default-features --features='wasm'";

        buildInputs = [ ] ++ extraBuildInputs;
      };

      # Combine the environment and other configuration needed for crane to build to the JS environment
      jsArgs = wasmEnvironment // commonArgs // {
        pname = "js";

        # We disable the default "native" feature and enable the "wasm" feature
        cargoExtraArgs = "--no-default-features --target wasm32-unknown-unknown";

        nativeBuildInputs = [
          wasm-bindgen-cli
          # pkgs.firefox-bin
          pkgs.ungoogled-chromium
        ];

        buildInputs = [ ] ++ extraBuildInputs;
      };

      # The `port` is parameterized to support parallel test runs without colliding static servers
      networkTestArgs = port: testEnvironment // {
        # We provide `barretenberg-transcript00` from the overlay to the tests as a URL hosted via a static server
        # This is necessary because the Nix sandbox has no network access and downloading during tests would fail
        TRANSCRIPT_URL = "http://0.0.0.0:${toString port}/${builtins.baseNameOf pkgs.barretenberg-transcript00}";

        # This copies the `barretenberg-transcript00` from the Nix store into this sandbox
        # which avoids exposing the entire Nix store to the static server it starts
        # The static server is moved to the background and killed after checks are completed
        preCheck = ''
          cp ${pkgs.barretenberg-transcript00} .
          echo "Starting simple static server"
          ${pkgs.simple-http-server}/bin/simple-http-server --port ${toString port} --silent &
          HTTP_SERVER_PID=$!
        '';

        postCheck = ''
          kill $HTTP_SERVER_PID
        '';
      };

      # Build *just* the cargo dependencies, so we can reuse all of that work between runs
      native-cargo-artifacts = craneLib.buildDepsOnly nativeArgs;
      wasm-cargo-artifacts = craneLib.buildDepsOnly wasmArgs;
      js-cargo-artifacts = craneLib.buildDepsOnly jsArgs;

      acvm-backend-barretenberg-native = craneLib.buildPackage (nativeArgs // {
        pname = "acvm-backend-barretenberg-native";

        cargoArtifacts = native-cargo-artifacts;
      });
      acvm-backend-barretenberg-wasm = craneLib.buildPackage (wasmArgs // {
        pname = "acvm-backend-barretenberg-wasm";

        cargoArtifacts = native-cargo-artifacts;
      });
    in
    rec {
      checks = {
        cargo-clippy-native = craneLib.cargoClippy (nativeArgs // {
          cargoArtifacts = native-cargo-artifacts;

          cargoClippyExtraArgs = "--all-targets -- -D warnings";
        });

        cargo-test-native = craneLib.cargoTest (nativeArgs // (networkTestArgs 8000) // {
          cargoArtifacts = native-cargo-artifacts;

          # It's unclear why doCheck needs to be enabled for tests to run but not clippy
          doCheck = true;
        });

        cargo-clippy-wasm = craneLib.cargoClippy (wasmArgs // {
          cargoArtifacts = wasm-cargo-artifacts;

          cargoClippyExtraArgs = "--all-targets -- -D warnings";
        });

        cargo-test-wasm = craneLib.cargoTest (wasmArgs // (networkTestArgs 8001) // {
          cargoArtifacts = wasm-cargo-artifacts;

          # It's unclear why doCheck needs to be enabled for tests to run but not clippy
          doCheck = true;
        });

        cargo-clippy-js = craneLib.cargoClippy (jsArgs // {
          cargoArtifacts = js-cargo-artifacts;

          cargoClippyExtraArgs = "--all-targets -- -D warnings";
        });

        cargo-test-js = craneLib.cargoTest (jsArgs // (networkTestArgs 8002) // {
          cargoArtifacts = js-cargo-artifacts;

          # It's unclear why doCheck needs to be enabled for tests to run but not clippy
          doCheck = true;
        });
      };

      packages = {
        inherit acvm-backend-barretenberg-native;
        inherit acvm-backend-barretenberg-wasm;

        default = acvm-backend-barretenberg-native;

        # We expose the `*-cargo-artifacts` derivations so we can cache our cargo dependencies in CI
        inherit native-cargo-artifacts;
        inherit wasm-cargo-artifacts;
      };

      # Setup the environment to match the stdenv from `nix build` & `nix flake check`, and
      # combine it with the environment settings, the inputs from our checks derivations,
      # and extra tooling via `nativeBuildInputs`
      devShells.default = pkgs.mkShell.override { inherit stdenv; } (nativeEnvironment // wasmEnvironment // testEnvironment // {
        inputsFrom = builtins.attrValues checks;

        nativeBuildInputs = with pkgs; [
          which
          starship
          git
          nil
          nixpkgs-fmt
          llvmPackages.lldb # This ensures the right lldb is in the environment for running rust-lldb
        ];

        shellHook = ''
          eval "$(starship init bash)"
        '';
      });
    });
}
