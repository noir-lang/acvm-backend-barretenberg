pub mod proof_system;
pub mod pwg;

mod smart_contract;
#[derive(Default)]
pub struct Plonk;

impl common::acvm::Backend for Plonk {}
