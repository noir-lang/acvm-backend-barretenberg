#[cfg(feature = "sys")]
pub mod proof_system;
pub mod pwg;
#[cfg(feature = "sys")]
mod smart_contract;
pub struct Plonk;

#[cfg(feature = "sys")]
impl acvm::Backend for Plonk {}
