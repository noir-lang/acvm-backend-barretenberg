#[cfg(feature = "sys")]
pub mod barretenberg_rs;
#[cfg(feature = "sys")]
pub use barretenberg_rs::Barretenberg;

pub mod barretenberg_wasm;
#[cfg(all(feature = "wasm", not(feature = "sys")))]
pub use barretenberg_wasm::Barretenberg;

mod contract;
pub mod serialiser;
pub use serialiser::serialise_circuit;
pub mod acvm_interop;
pub use acvm_interop::Plonk;
mod barretenberg_structures;
