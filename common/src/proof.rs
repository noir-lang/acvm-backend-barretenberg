use std::collections::BTreeMap;

use acvm::{
    acir::{circuit::Circuit, native_types::Witness},
    FieldElement,
};

use crate::barretenberg_structures::Assignments;

pub fn remove_public_inputs(num_pub_inputs: usize, proof: &[u8]) -> Vec<u8> {
    // This is only for public inputs and for Barretenberg.
    // Barretenberg only used bn254, so each element is 32 bytes.
    // To remove the public inputs, we need to remove (num_pub_inputs * 32) bytes
    let num_bytes_to_remove = 32 * num_pub_inputs;
    proof[num_bytes_to_remove..].to_vec()
}

pub fn prepend_public_inputs(proof: Vec<u8>, public_inputs: Assignments) -> Vec<u8> {
    if public_inputs.0.is_empty() {
        return proof;
    }

    let public_inputs_bytes = public_inputs
        .0
        .into_iter()
        .flat_map(|assignment| assignment.to_be_bytes());

    public_inputs_bytes.chain(proof.into_iter()).collect()
}

/// Flatten a witness map into a vector of witness assignments.
pub fn flatten_witness_map(
    circuit: &Circuit,
    witness_values: BTreeMap<Witness, FieldElement>,
) -> Assignments {
    let num_witnesses = circuit.num_vars();

    // Note: The witnesses are sorted via their witness index
    // witness_values may not have all the witness indexes, e.g for unused witness which are not solved by the solver
    let witness_assignments = (1..num_witnesses)
        .map(|witness_index| {
            // Get the value if it exists. If i does not, then we fill it with the zero value
            witness_values
                .get(&Witness(witness_index))
                .map_or(FieldElement::zero(), |field| *field)
        })
        .collect();

    Assignments::from_vec(witness_assignments)
}
