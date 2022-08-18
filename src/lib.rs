#[cfg(sys)]
pub mod barretenberg_rs;
#[cfg(any(wasm, sys))]
pub mod barretenberg_wasm;

mod contract;
pub mod serialiser;
pub use serialiser::serialise_circuit;
pub mod acvm_interop;
pub use acvm_interop::Plonk;
