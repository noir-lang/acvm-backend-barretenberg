pub use barretenberg_wasm::Barretenberg;

use wasm_bindgen::prelude::*;

use common::acvm::{
    acir::circuit::Circuit, acir::native_types::Witness, FieldElement, PartialWitnessGenerator,
};

use std::collections::BTreeMap;

// Flattened
pub type ComputedWitness = Vec<u8>;

#[wasm_bindgen]
pub fn compute_witnesses(
    circuit: JsValue,
    initial_js_witness: Vec<js_sys::JsString>,
) -> ComputedWitness {
    console_error_panic_hook::set_once();

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
    match plonk.solve(&mut witness_map, circuit.opcodes) {
        Ok(_) => {}
        Err(opcode) => panic!("solver came across an error with opcode {}", opcode),
    };

    // Serialise the witness in a way that the C++ codebase can deserialise
    let assignments = crate::barretenberg_structures::Assignments::from_vec(
        witness_map
            .into_iter()
            .map(|(_, field_val)| field_val)
            .collect(),
    );

    assignments.to_bytes()
}

#[wasm_bindgen]
pub fn serialise_acir_to_barrtenberg_circuit(acir: JsValue) -> Vec<u8> {
    console_error_panic_hook::set_once();

    let circuit: Circuit = acir.into_serde().unwrap();
    serialise_circuit(&circuit).to_bytes()
}

#[wasm_bindgen]
pub fn packed_witness_to_witness(acir: JsValue, witness_arr: Vec<u8>) -> Vec<u8> {
    console_error_panic_hook::set_once();

    use common::barretenberg_structures::Assignments;
    let circuit: Circuit = acir.into_serde().unwrap();
    let witness_values = Witness::from_bytes(&witness_arr);
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
    sorted_witness.to_bytes()
}

#[wasm_bindgen]
pub fn eth_contract_from_cs(vk_method: String) -> String {
    crate::contract::turbo_verifier::create(&vk_method)
}

#[wasm_bindgen]
pub fn serialise_public_inputs(pub_inputs_js_string: Vec<js_sys::JsString>) -> Vec<u8> {
    console_error_panic_hook::set_once();

    use common::acvm::FieldElement;

    let mut pub_inputs_string = Vec::new();
    for val in pub_inputs_js_string {
        pub_inputs_string.push(String::from(val))
    }

    let mut pub_inputs = Vec::new();
    for string in pub_inputs_string {
        let field = FieldElement::from_hex(&string).expect("unexpected hex string");
        pub_inputs.push(field)
    }

    pub_inputs
        .into_iter()
        .map(|field| field.to_bytes())
        .flatten()
        .collect()
}
