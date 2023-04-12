# aztec_backend

## Building from source

Building `aztec_backend` requires a variety of native dependencies, but we've bundled up everything you need with [Nix](https://nixos.org/).

To work on `aztec_backend`, you'll want to:
1. Install Nix following [their guide](https://nixos.org/download.html) for your operating system
2. Create the file `~/.config/nix/nix.conf` with the contents:
```
experimental-features = nix-command
extra-experimental-features = flakes
```
3. Clone the project with `git clone git@github.com:noir-lang/aztec_backend`
4. Run `nix build . -L` in the `aztec_backend` directory
5. Run `nix flake check -L` to run clippy and the tests
