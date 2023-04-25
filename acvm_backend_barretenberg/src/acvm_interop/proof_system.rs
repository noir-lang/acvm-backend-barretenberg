use crate::composer::Composer;
use crate::Barretenberg;
use common::acvm::acir::{circuit::Circuit, native_types::Witness, BlackBoxFunc};
use common::acvm::FieldElement;
use common::acvm::{Language, ProofSystemCompiler};
use common::proof;
use std::collections::BTreeMap;

impl ProofSystemCompiler for Barretenberg {
    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    fn get_exact_circuit_size(&self, circuit: &Circuit) -> u32 {
        Composer::get_exact_circuit_size(self, &circuit.into())
    }

    fn black_box_function_supported(&self, opcode: &BlackBoxFunc) -> bool {
        match opcode {
            BlackBoxFunc::AND
            | BlackBoxFunc::XOR
            | BlackBoxFunc::RANGE
            | BlackBoxFunc::SHA256
            | BlackBoxFunc::Blake2s
            | BlackBoxFunc::MerkleMembership
            | BlackBoxFunc::SchnorrVerify
            | BlackBoxFunc::Pedersen
            | BlackBoxFunc::HashToField128Security
            | BlackBoxFunc::EcdsaSecp256k1
            | BlackBoxFunc::FixedBaseScalarMul => true,

            BlackBoxFunc::AES | BlackBoxFunc::Keccak256 => false,
        }
    }

    fn preprocess(&self, circuit: &Circuit) -> (Vec<u8>, Vec<u8>) {
        let constraint_system = &circuit.into();

        let proving_key = self.compute_proving_key(constraint_system);
        let verification_key = self.compute_verification_key(constraint_system, &proving_key);

        (proving_key, verification_key)
    }

    fn prove_with_pk(
        &self,
        circuit: &Circuit,
        witness_values: BTreeMap<Witness, FieldElement>,
        proving_key: &[u8],
    ) -> Vec<u8> {
        let assignments = proof::flatten_witness_map(circuit, witness_values);

        self.create_proof_with_pk(&circuit.into(), assignments, proving_key)
    }

    fn verify_with_vk(
        &self,
        proof: &[u8],
        public_inputs: BTreeMap<Witness, FieldElement>,
        circuit: &Circuit,
        verification_key: &[u8],
    ) -> bool {
        // Unlike when proving, we omit any unassigned witnesses.
        // Witness values should be ordered by their index but we skip over any indices without an assignment.
        let flattened_public_inputs: Vec<FieldElement> = public_inputs.into_values().collect();

        Composer::verify_with_vk(
            self,
            &circuit.into(),
            proof,
            flattened_public_inputs.into(),
            verification_key,
        )
    }
}
