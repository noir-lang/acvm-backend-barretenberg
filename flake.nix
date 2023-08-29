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
  };

  outputs =
    { self, nixpkgs, crane, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [
          rust-overlay.overlays.default
        ];
      };

      rustToolchain = pkgs.rust-bin.stable."1.66.0".default.override {
        # We include rust-src to ensure rust-analyzer works.
        # See https://discourse.nixos.org/t/rust-src-not-found-and-other-misadventures-of-developing-rust-on-nixos/11570/4
        extensions = [ "rust-src" ];
      };

      craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

      sharedEnvironment = {
        BARRETENBERG_ARCHIVE = builtins.fetchurl {
          url = "https://github.com/AztecProtocol/barretenberg/releases/download/barretenberg-v0.4.6/acvm_backend.wasm.tar.gz";
          sha256 = "sha256:1xpycikqlvsjcryi3hkbc4mwmmdz7zshw6f76vyf1qssq53asyfx";
        };
      };

      # We use `include_str!` macro to embed the solidity verifier template so we need to create a special
      # source filter to include .sol files in addition to usual rust/cargo source files.
      solidityFilter = path: _type: builtins.match ".*sol$" path != null;
      # We use `.bytecode` and `.tr` files to test interactions with `bb` so we add a source filter to include these.
      bytecodeFilter = path: _type: builtins.match ".*bytecode$" path != null;
      witnessFilter = path: _type: builtins.match ".*tr$" path != null;
      sourceFilter = path: type:
        (solidityFilter path type) || (bytecodeFilter path type)|| (witnessFilter path type) || (craneLib.filterCargoSources path type);

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
      ] ++ [
        # Need to install various packages used by the `bb` binary.
        pkgs.curl
        stdenv.cc.cc.lib
        pkgs.gcc.cc.lib
        pkgs.gzip
      ];

      commonArgs = {
        pname = "acvm-backend-barretenberg";
        # x-release-please-start-version
        version = "0.11.0";
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
      nativeArgs = sharedEnvironment // commonArgs // {
        # Use our custom stdenv to build and test our Rust project
        inherit stdenv;

        nativeBuildInputs = pkgs.lib.optionals stdenv.isLinux [
          # This is linux specific and used to patch the rpath and interpreter of the bb binary
          pkgs.patchelf
        ];

        buildInputs = [
          pkgs.llvmPackages.openmp
        ] ++ extraBuildInputs;
      };
      
      # Conditionally download the binary based on whether it is linux or mac
      bb_binary = let
        platformSpecificUrl = if stdenv.hostPlatform.isLinux then
          "https://github.com/AztecProtocol/barretenberg/releases/download/barretenberg-v0.4.3/bb-ubuntu.tar.gz"
        else if stdenv.hostPlatform.isDarwin then
          "https://github.com/AztecProtocol/barretenberg/releases/download/barretenberg-v0.4.3/barretenberg-x86_64-apple-darwin.tar.gz"
        else
          throw "Unsupported platform";

        platformSpecificHash = if stdenv.hostPlatform.isLinux then
          "sha256:0rcsjws87f4v28cw9734c10pg7c49apigf4lg3m0ji5vbhhmfnhr"
        else if stdenv.hostPlatform.isDarwin then
          "sha256:0pnsd56z0vkai7m0advawfgcvq9jbnpqm7lk98n5flqj583x3w35"
        else
          throw "Unsupported platform";
      in builtins.fetchurl {
        url = platformSpecificUrl;
        sha256 = platformSpecificHash;
      };


      # The `port` is parameterized to support parallel test runs without colliding static servers
      networkTestArgs = port: {
        BB_BINARY_PATH = "./backend_binary";

        BB_BINARY_URL = "http://0.0.0.0:${toString port}/${builtins.baseNameOf bb_binary}";

        BARRETENBERG_TRANSCRIPT_URL = "http://0.0.0.0:${toString port}/${builtins.baseNameOf pkgs.barretenberg-transcript00}";

        preCheck = ''
          echo "Extracting bb binary"
          mkdir extracted
          tar -xf ${bb_binary} -C extracted

          # Conditionally patch the binary for Linux
          ${if stdenv.hostPlatform.isLinux then ''

            cp extracted/cpp/build/bin/bb ./backend_binary
          
            echo "Patching bb binary for Linux"
            patchelf --set-rpath "${stdenv.cc.cc.lib}/lib:${pkgs.gcc.cc.lib}/lib" ./backend_binary
            patchelf --set-interpreter ${stdenv.cc.libc}/lib/ld-linux-x86-64.so.2 ./backend_binary
          '' else if stdenv.hostPlatform.isDarwin then ''
            cp extracted/bb ./backend_binary
          '' else
            throw "Unsupported platform"
          }

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
     
      acvm-backend-barretenberg-native = craneLib.buildPackage (nativeArgs // {
        cargoArtifacts = native-cargo-artifacts;
      });
    in
    rec {
      checks = {
        cargo-clippy-native = craneLib.cargoClippy (nativeArgs // {
          # Crane appends "clippy"
          pname = "native";

          cargoArtifacts = native-cargo-artifacts;

          cargoClippyExtraArgs = "--all-targets -- -D warnings";
        });

        cargo-test-native = craneLib.cargoTest (nativeArgs // (networkTestArgs 8000) // {
          # Crane appends "test"
          pname = "native";

          cargoArtifacts = native-cargo-artifacts;

          # It's unclear why doCheck needs to be enabled for tests to run but not clippy
          doCheck = true;
        });
      };

      packages = {
        inherit acvm-backend-barretenberg-native;

        default = acvm-backend-barretenberg-native;

        # We expose the `*-cargo-artifacts` derivations so we can cache our cargo dependencies in CI
        inherit native-cargo-artifacts;
      };

      # Setup the environment to match the stdenv from `nix build` & `nix flake check`, and
      # combine it with the environment settings, the inputs from our checks derivations,
      # and extra tooling via `nativeBuildInputs`
      devShells.default = pkgs.mkShell.override { inherit stdenv; } (sharedEnvironment // {
        inputsFrom = builtins.attrValues checks;

        nativeBuildInputs = with pkgs; [
          curl
          gzip
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
