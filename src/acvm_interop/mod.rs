use crate::Barretenberg;

mod proof_system;
mod pwg;
mod reference_string;
mod smart_contract;

impl acvm::Backend for Barretenberg {}
