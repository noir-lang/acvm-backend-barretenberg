pub mod proof_system;
pub mod pwg;

mod smart_contract;
pub struct Plonk;

impl common::acvm::Backend for Plonk {}
