use super::Plonk;
use crate::Barretenberg;
use common::acvm::acir::{circuit::Circuit, native_types::Witness};
use common::acvm::FieldElement;
use common::acvm::{Language, ProofSystemCompiler};
use common::proof;
use std::collections::BTreeMap;

impl ProofSystemCompiler for Plonk {
    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    fn get_exact_circuit_size(&self, circuit: &Circuit) -> u32 {
        let barretenberg = Barretenberg::new();
        barretenberg.get_exact_circuit_size(&circuit.into())
    }

    fn black_box_function_supported(&self, opcode: &common::acvm::acir::BlackBoxFunc) -> bool {
        match opcode {
            common::acvm::acir::BlackBoxFunc::AES => false,
            common::acvm::acir::BlackBoxFunc::AND => true,
            common::acvm::acir::BlackBoxFunc::XOR => true,
            common::acvm::acir::BlackBoxFunc::RANGE => true,
            common::acvm::acir::BlackBoxFunc::SHA256 => true,
            common::acvm::acir::BlackBoxFunc::Blake2s => true,
            common::acvm::acir::BlackBoxFunc::MerkleMembership => true,
            common::acvm::acir::BlackBoxFunc::SchnorrVerify => true,
            common::acvm::acir::BlackBoxFunc::Pedersen => true,
            common::acvm::acir::BlackBoxFunc::HashToField128Security => true,
            common::acvm::acir::BlackBoxFunc::EcdsaSecp256k1 => true,
            common::acvm::acir::BlackBoxFunc::FixedBaseScalarMul => true,
            common::acvm::acir::BlackBoxFunc::Keccak256 => false,
        }
    }

    fn preprocess(&self, circuit: &Circuit) -> (Vec<u8>, Vec<u8>) {
        let barretenberg = Barretenberg::new();
        let constraint_system = &circuit.into();

        let proving_key = barretenberg.compute_proving_key(constraint_system);
        let verification_key =
            barretenberg.compute_verification_key(constraint_system, &proving_key);

        (proving_key, verification_key)
    }

    fn prove_with_pk(
        &self,
        circuit: &Circuit,
        witness_values: BTreeMap<Witness, FieldElement>,
        proving_key: &[u8],
    ) -> Vec<u8> {
        let barretenberg = Barretenberg::new();

        let assignments = proof::flatten_witness_map(circuit, witness_values);

        barretenberg.create_proof_with_pk(&circuit.into(), assignments, proving_key)
    }

    fn verify_with_vk(
        &self,
        proof: &[u8],
        public_inputs: BTreeMap<Witness, FieldElement>,
        circuit: &Circuit,
        verification_key: &[u8],
    ) -> bool {
        let barretenberg = Barretenberg::new();

        // Unlike when proving, we omit any unassigned witnesses.
        // Witness values should be ordered by their index but we skip over any indices without an assignment.
        let flattened_public_inputs: Vec<FieldElement> = public_inputs.into_values().collect();

        barretenberg.verify_with_vk(
            &circuit.into(),
            proof,
            flattened_public_inputs.into(),
            verification_key,
        )
    }
}
