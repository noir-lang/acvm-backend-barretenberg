# Aztec Backend wasm

Exposes functions for:

- solving an intermediate witness
- transforming an ACIR into a barretenberg circuit

Whether this functionailty should be exposed to the browser via the `aztec_backend` project is still up for debate.

## Dependencies

In order to build the wasm package, the following must be installed:

- [wasm-pack](https://github.com/rustwasm/wasm-pack)
- [jq](https://github.com/stedolan/jq)

## Build

The wasm package can be built using the command below:

```bash
./build-aztec-backend-wasm
```

Using `wasm-pack` directly isn't recommended as it doesn't generate a complete `package.json` file, resulting in files being omitted from the published package.
