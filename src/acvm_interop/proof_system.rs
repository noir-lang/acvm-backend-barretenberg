use acvm::acir::circuit::Opcode;
use acvm::acir::{circuit::Circuit, native_types::WitnessMap, BlackBoxFunc};
use acvm::FieldElement;
use acvm::{Language, ProofSystemCompiler};

use crate::{barretenberg_structures::Assignments, composer::Composer, BackendError, Barretenberg};

impl ProofSystemCompiler for Barretenberg {
    type Error = BackendError;

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    fn get_exact_circuit_size(&self, circuit: &Circuit) -> Result<u32, Self::Error> {
        Ok(Composer::get_exact_circuit_size(
            self,
            &circuit.try_into()?,
        )?)
    }

    fn supports_opcode(&self, opcode: &Opcode) -> bool {
        match opcode {
            Opcode::Arithmetic(_) => true,
            Opcode::Directive(_) => true,
            Opcode::Block(_) => false,
            Opcode::ROM(_) => true,
            Opcode::RAM(_) => true,
            Opcode::Oracle(_) => true,
            Opcode::BlackBoxFuncCall(func) => match func.get_black_box_func() {
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

                BlackBoxFunc::AES => false,
            },
        }
    }

    fn preprocess(
        &self,
        common_reference_string: &[u8],
        circuit: &Circuit,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        let crs = common_reference_string.try_into()?;
        let constraint_system = &circuit.try_into()?;

        let proving_key = self.compute_proving_key(constraint_system)?;
        let verification_key = self.compute_verification_key(&crs, &proving_key)?;

        Ok((proving_key, verification_key))
    }

    fn prove_with_pk(
        &self,
        common_reference_string: &[u8],
        circuit: &Circuit,
        witness_values: WitnessMap,
        proving_key: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let crs = common_reference_string.try_into()?;
        let assignments = flatten_witness_map(circuit, witness_values);

        Ok(self.create_proof_with_pk(&crs, &circuit.try_into()?, assignments, proving_key)?)
    }

    fn verify_with_vk(
        &self,
        common_reference_string: &[u8],
        proof: &[u8],
        public_inputs: WitnessMap,
        circuit: &Circuit,
        verification_key: &[u8],
    ) -> Result<bool, Self::Error> {
        let crs = common_reference_string.try_into()?;
        // Unlike when proving, we omit any unassigned witnesses.
        // Witness values should be ordered by their index but we skip over any indices without an assignment.
        let flattened_public_inputs: Vec<FieldElement> =
            public_inputs.into_iter().map(|(_, el)| el).collect();

        Ok(Composer::verify_with_vk(
            self,
            &crs,
            &circuit.try_into()?,
            proof,
            flattened_public_inputs.into(),
            verification_key,
        )?)
    }
}

/// Flatten a witness map into a vector of witness assignments.
fn flatten_witness_map(circuit: &Circuit, witness_values: WitnessMap) -> Assignments {
    let num_witnesses = circuit.num_vars();

    // Note: The witnesses are sorted via their witness index
    // witness_values may not have all the witness indexes, e.g for unused witness which are not solved by the solver
    let witness_assignments: Vec<FieldElement> = (1..num_witnesses)
        .map(|witness_index| {
            // Get the value if it exists. If i does not, then we fill it with the zero value
            witness_values
                .get_index(witness_index)
                .map_or(FieldElement::zero(), |field| *field)
        })
        .collect();

    witness_assignments.into()
}
