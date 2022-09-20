#[cfg(not(feature = "wasm"))]
pub mod proof_system;
pub mod pwg;
#[cfg(not(feature = "wasm"))]
mod smart_contract;
pub struct Plonk;
#[cfg(not(feature = "wasm"))]
impl acvm::Backend for Plonk {}
