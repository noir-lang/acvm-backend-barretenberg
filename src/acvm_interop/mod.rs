use crate::Barretenberg;

mod common_reference_string;
mod info;
mod proof_system;
mod pwg;
mod smart_contract;

impl acvm::Backend for Barretenberg {}
