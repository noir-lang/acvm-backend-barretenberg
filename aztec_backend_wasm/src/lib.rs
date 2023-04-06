#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]

use common::acvm::acir::circuit::Circuit;
use common::serializer::serialize_circuit;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn serialize_acir_to_barretenberg_circuit(acir_bytes: Vec<u8>) -> Vec<u8> {
    console_error_panic_hook::set_once();

    let circuit = Circuit::read(&*acir_bytes).unwrap();
    serialize_circuit(&circuit).to_bytes()
}
