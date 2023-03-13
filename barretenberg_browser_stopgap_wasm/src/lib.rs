use barretenberg_wasm;
use common::acvm::{
    acir::circuit::Circuit, acir::native_types::Witness, FieldElement, PartialWitnessGenerator,
};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

fn js_map_to_witness_map(js_map: js_sys::Map) -> BTreeMap<Witness, FieldElement> {
    let mut witness_skeleton: BTreeMap<Witness, FieldElement> = BTreeMap::new();
    for key_result in js_map.keys() {
        let key = key_result.expect("bad key");
        let idx;
        unsafe {
            idx = key
                .as_f64()
                .expect("not a number")
                .to_int_unchecked::<u32>();
        }
        let hex_str = js_map.get(&key).as_string().expect("not a string");
        let field_element = FieldElement::from_hex(&hex_str).expect("bad hex str");
        witness_skeleton.insert(Witness(idx), field_element);
    }
    witness_skeleton
}

fn witness_map_to_js_map(witness_map: BTreeMap<Witness, FieldElement>) -> js_sys::Map {
    let js_map = js_sys::Map::new();
    for (witness, field_value) in witness_map.iter() {
        let js_idx = js_sys::Number::from(witness.0);
        let mut hex_str = "0x".to_owned();
        hex_str.push_str(&field_value.to_hex());
        let js_hex_str = js_sys::JsString::from(hex_str);
        js_map.set(&js_idx, &js_hex_str);
    }
    js_map
}

fn read_circuit(circuit: js_sys::Uint8Array) -> Circuit {
    let circuit: Vec<u8> = circuit.to_vec();
    match Circuit::read(&*circuit) {
        Ok(circuit) => circuit,
        Err(err) => panic!("Circuit read err: {}", err),
    }
}

#[wasm_bindgen]
pub fn solve_intermediate_witness(
    circuit: js_sys::Uint8Array,
    initial_witness: js_sys::Map,
) -> js_sys::Map {
    console_error_panic_hook::set_once();

    let circuit = read_circuit(circuit);
    let mut witness_skeleton = js_map_to_witness_map(initial_witness);

    use barretenberg_wasm::Plonk;
    let plonk = Plonk;
    match plonk.solve(&mut witness_skeleton, circuit.opcodes) {
        Ok(_) => {}
        Err(opcode) => panic!("solver came across an error with opcode {}", opcode),
    };
    witness_map_to_js_map(witness_skeleton)
}
