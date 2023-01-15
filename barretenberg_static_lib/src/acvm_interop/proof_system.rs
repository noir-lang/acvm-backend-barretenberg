use super::Plonk;
use crate::composer::{remove_public_inputs, StandardComposer};
use common::acvm::acir::{circuit::Circuit, native_types::Witness};
use common::acvm::FieldElement;
use common::acvm::{Language, ProofSystemCompiler};
use common::barretenberg_structures::Assignments;
use common::serialiser::serialise_circuit;
use std::collections::BTreeMap;

impl ProofSystemCompiler for Plonk {
    fn prove_with_meta(
        &self,
        circuit: Circuit,
        witness_values: BTreeMap<Witness, FieldElement>,
    ) -> Vec<u8> {
        let constraint_system = serialise_circuit(&circuit);

        let mut composer = StandardComposer::new(constraint_system);

        // Add witnesses in the correct order
        // Note: The witnesses are sorted via their witness index
        // witness_values may not have all the witness indexes, e.g for unused witness which are not solved by the solver
        let mut sorted_witness = Assignments::new();
        let num_witnesses = circuit.num_vars();
        for i in 1..num_witnesses {
            // Get the value if it exists. If i does not, then we fill it with the zero value
            let value = match witness_values.get(&Witness(i)) {
                Some(value) => *value,
                None => FieldElement::zero(),
            };

            sorted_witness.push(value);
        }

        remove_public_inputs(
            circuit.public_inputs.0.len(),
            composer.create_proof(sorted_witness),
        )
    }

    fn verify_from_cs(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: Circuit,
    ) -> bool {
        let constraint_system = serialise_circuit(&circuit);

        let mut composer = StandardComposer::new(constraint_system);

        composer.verify(proof, Some(Assignments::from_vec(public_inputs)))
    }

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    fn get_exact_circuit_size(&self, circuit: Circuit) -> u32 {
        let constraint_system = serialise_circuit(&circuit);

        let composer = StandardComposer::new(constraint_system);

        let circuit_size = composer.get_exact_circuit_size();

        circuit_size
    }

    fn blackbox_function_supported(&self, opcode: &common::acvm::acir::BlackBoxFunc) -> bool {
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
        }
    }
}
