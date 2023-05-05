use acvm::acir::{circuit::Circuit, native_types::Witness, BlackBoxFunc};
use acvm::FieldElement;
use acvm::{Language, ProofSystemCompiler};
use std::collections::BTreeMap;

use crate::barretenberg_structures::Assignments;
use crate::composer::Composer;
use crate::Barretenberg;

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
            | BlackBoxFunc::Keccak256
            | BlackBoxFunc::ComputeMerkleRoot
            | BlackBoxFunc::SchnorrVerify
            | BlackBoxFunc::Pedersen
            | BlackBoxFunc::HashToField128Security
            | BlackBoxFunc::EcdsaSecp256k1
            | BlackBoxFunc::FixedBaseScalarMul => true,

            BlackBoxFunc::AES  => false,
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
        let assignments = flatten_witness_map(circuit, witness_values);

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

/// Flatten a witness map into a vector of witness assignments.
fn flatten_witness_map(
    circuit: &Circuit,
    witness_values: BTreeMap<Witness, FieldElement>,
) -> Assignments {
    let num_witnesses = circuit.num_vars();

    // Note: The witnesses are sorted via their witness index
    // witness_values may not have all the witness indexes, e.g for unused witness which are not solved by the solver
    let witness_assignments: Vec<FieldElement> = (1..num_witnesses)
        .map(|witness_index| {
            // Get the value if it exists. If i does not, then we fill it with the zero value
            witness_values
                .get(&Witness(witness_index))
                .map_or(FieldElement::zero(), |field| *field)
        })
        .collect();

    Assignments::from(witness_assignments)
}
