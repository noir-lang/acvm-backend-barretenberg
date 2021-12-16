pub use acvm::{Backend, PartialWitnessGenerator, ProofSystemCompiler, SmartContract};

pub mod proof_system;
pub mod pwg;
mod smart_contract;
pub struct Plonk;

impl Backend for Plonk {}
