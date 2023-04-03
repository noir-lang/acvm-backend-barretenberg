#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]

use common::acvm::acir::{circuit::Circuit, native_types::Witness};
use common::proof::flatten_witness_map;
use common::serializer::serialize_circuit;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn serialize_acir_to_barretenberg_circuit(acir_bytes: Vec<u8>) -> Vec<u8> {
    console_error_panic_hook::set_once();

    let circuit = Circuit::read(&*acir_bytes).expect("could not deserialize circuit");
    serialize_circuit(&circuit).to_bytes()
}

/// Returns the uncompressed flattened witness format expected by Barretenberg.
///
/// This function is necessary as witness maps are saved to disk in a compressed format;
/// Barretenberg doesn't expect a compressed witness map however so it must be converted.
///
/// # Panics
///
/// Panics if `witness_bytes` cannot be deserialized to a valid `WitnessMap`.
///
/// Panics if `acir_bytes` cannot be deserialized to a valid `Circuit`.
#[wasm_bindgen]
pub fn decompress_witness_map(witness_bytes: Vec<u8>, acir_bytes: Vec<u8>) -> Vec<u8> {
    console_error_panic_hook::set_once();

    let witness_map = Witness::from_bytes(&witness_bytes);
    let circuit = Circuit::read(&*acir_bytes).expect("could not deserialize circuit");

    flatten_witness_map(witness_map, circuit.num_vars()).to_bytes()
}
