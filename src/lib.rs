#[cfg(feature = "sys")]
pub mod barretenberg_rs;
#[cfg(feature = "sys")]
pub use barretenberg_rs::Barretenberg;

pub mod barretenberg_wasm;
#[cfg(all(any(feature = "wasm-base", feature = "wasm"), not(feature = "sys")))]
pub use barretenberg_wasm::Barretenberg;

mod contract;
pub mod serialiser;
pub use serialiser::serialise_circuit;
pub mod acvm_interop;
pub use acvm_interop::Plonk;
mod barretenberg_structures;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use acvm::{
    acir::circuit::Circuit, acir::native_types::Witness, FieldElement, PartialWitnessGenerator,
};
#[cfg(feature = "wasm")]
use std::collections::BTreeMap;

// Flattened
pub type ComputedWitness = Vec<u8>;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn compute_witnesses(
    circuit: JsValue,
    initial_js_witness: Vec<js_sys::JsString>,
) -> ComputedWitness {
    let circuit: Circuit = circuit.into_serde().unwrap();

    let mut initial_witness = Vec::new();
    for js_val in initial_js_witness {
        initial_witness.push(String::from(js_val))
    }

    // Convert initial witness vector to a BTreeMap and add the zero witness as the first one
    let mut witness_map: BTreeMap<Witness, FieldElement> = BTreeMap::new();
    let num_wits = circuit.current_witness_index;
    for (index, element) in initial_witness.into_iter().enumerate() {
        witness_map.insert(
            Witness((index + 1) as u32),
            FieldElement::from_hex(&element).expect("expected hex strings"),
        );
    }
    debug_assert_eq!((num_wits + 1) as usize, witness_map.len());

    // Now use the partial witness generator to fill in the rest of the witnesses
    // which are possible

    let plonk = Plonk;
    match plonk.solve(&mut witness_map, circuit.gates) {
        Ok(_) => {}
        Err(opcode) => panic!("solver came across an error with opcode {}", opcode),
    };

    // let field_values_as_bytes: Vec<_> =
    //     witness_map.into_iter().map(|(_, field_val)| field_val.to_bytes()).flatten().collect();
    // field_values_as_bytes

    // Serialise the witness in a way that the C++ codebase can deserialise
    let assignments = crate::barretenberg_structures::Assignments::from_vec(
        witness_map
            .into_iter()
            .map(|(_, field_val)| field_val)
            .collect(),
    );

    assignments.to_bytes()
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn serialise_acir_to_barrtenberg_circuit(acir: JsValue) -> Vec<u8> {
    let circuit: Circuit = acir.into_serde().unwrap();
    serialise_circuit(&circuit).to_bytes()
}
