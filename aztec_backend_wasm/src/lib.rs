use barretenberg_wasm;
use common::acvm::{
    acir::circuit::{opcodes::OracleData, Circuit, Opcode},
    acir::native_types::Witness,
    pwg::block::Blocks,
    FieldElement, PartialWitnessGenerator,
};
use js_sys::JsString;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

type JsErrorString = JsString;
type WitnessMap = BTreeMap<Witness, FieldElement>;

fn js_value_to_field_element(js_value: JsValue) -> Result<FieldElement, JsErrorString> {
    let hex_str = match js_value.as_string() {
        Some(str) => str,
        None => return Err("failed to parse field element from non-string".into()),
    };
    match FieldElement::from_hex(&hex_str) {
        Some(field_element) => Ok(field_element),
        None => Err(format!("Invalid hex string: '{}'", hex_str).into()),
    }
}

fn js_map_to_witness_map(js_map: js_sys::Map) -> Result<WitnessMap, JsErrorString> {
    let mut witness_assignments: BTreeMap<Witness, FieldElement> = BTreeMap::new();
    for key_result in js_map.keys() {
        let key = match key_result {
            Ok(key) => key,
            Err(_) => return Err("bad key".into()),
        };
        let idx;
        unsafe {
            idx = match key.as_f64() {
                Some(value) => value.to_int_unchecked::<u32>(),
                None => return Err("not a number".into()),
            }
        }
        let field_element = js_value_to_field_element(js_map.get(&key))?;
        witness_assignments.insert(Witness(idx), field_element);
    }
    Ok(witness_assignments)
}

fn field_element_to_js_string(field_element: &FieldElement) -> JsString {
    format!("0x{}", field_element.to_hex()).into()
}

fn witness_map_to_js_map(witness_map: BTreeMap<Witness, FieldElement>) -> js_sys::Map {
    let js_map = js_sys::Map::new();
    for (witness, field_value) in witness_map.iter() {
        let js_idx = js_sys::Number::from(witness.0);
        let js_hex_str = field_element_to_js_string(field_value);
        js_map.set(&js_idx, &js_hex_str);
    }
    js_map
}

fn read_circuit(circuit: js_sys::Uint8Array) -> Result<Circuit, JsErrorString> {
    let circuit: Vec<u8> = circuit.to_vec();
    match Circuit::read(&*circuit) {
        Ok(circuit) => Ok(circuit),
        Err(err) => Err(format!("Circuit read err: {}", err).into()),
    }
}

fn format_js_err(err: JsValue) -> String {
    match err.as_string() {
        Some(str) => str,
        None => "Unknown".to_owned(),
    }
}

async fn resolve_oracle(
    oracle_resolver: &js_sys::Function,
    mut oracle_data: OracleData,
) -> Result<OracleData, JsErrorString> {
    // Prepare to call
    let this = JsValue::null();
    let name = JsValue::from(oracle_data.name.clone());
    let inputs = js_sys::Array::default();
    for input_value in &oracle_data.input_values {
        let hex_js_string = field_element_to_js_string(input_value);
        inputs.push(&JsValue::from(hex_js_string));
    }

    // Call and await
    let ret_js_val = oracle_resolver
        .call2(&this, &name, &inputs)
        .map_err(|err| format!("Error calling oracle_resolver: {}", format_js_err(err)))?;
    let ret_js_prom: js_sys::Promise = ret_js_val.into();
    let ret_future: wasm_bindgen_futures::JsFuture = ret_js_prom.into();
    let js_resolution = ret_future
        .await
        .map_err(|err| format!("Error awaiting oracle_resolver: {}", format_js_err(err)))?;
    if !js_resolution.is_array() {
        return Err("oracle_resolver must return a Promise<string[]>".into());
    }

    // Handle and apply result
    let js_arr = js_sys::Array::from(&js_resolution);
    for elem in js_arr.iter() {
        if !elem.is_string() {
            return Err("Non-string element in oracle_resolver return".into());
        }
        oracle_data
            .output_values
            .push(js_value_to_field_element(elem)?)
    }
    Ok(oracle_data)
}

#[wasm_bindgen]
pub async fn solve_intermediate_witness(
    circuit: js_sys::Uint8Array,
    initial_witness: js_sys::Map,
    oracle_resolver: js_sys::Function,
) -> Result<js_sys::Map, JsErrorString> {
    console_error_panic_hook::set_once();

    let mut opcodes_to_solve = read_circuit(circuit)?.opcodes;
    let mut witness_assignments = js_map_to_witness_map(initial_witness)?;
    let mut blocks = Blocks::default();

    use barretenberg_wasm::Plonk;
    let plonk = Plonk;
    while !opcodes_to_solve.is_empty() {
        let (unresolved_opcodes, oracles) = plonk
            .solve(&mut witness_assignments, &mut blocks, opcodes_to_solve)
            .map_err(|err| JsString::from(format!("solver opcode resolution error: {}", err)))?;
        let oracle_futures: Vec<_> = oracles
            .into_iter()
            .map(|oracle| resolve_oracle(&oracle_resolver, oracle))
            .collect();
        opcodes_to_solve = Vec::new();
        for oracle_future in oracle_futures {
            let filled_oracle = oracle_future.await?;
            opcodes_to_solve.push(Opcode::Oracle(filled_oracle));
        }
        opcodes_to_solve.extend_from_slice(&unresolved_opcodes);
    }

    Ok(witness_map_to_js_map(witness_assignments))
}

#[wasm_bindgen]
pub fn intermediate_witness_to_assignment_bytes(
    intermediate_witness: js_sys::Map,
) -> Result<js_sys::Uint8Array, JsErrorString> {
    console_error_panic_hook::set_once();

    let intermediate_witness = js_map_to_witness_map(intermediate_witness)?;

    // Add witnesses in the correct order
    // Note: The witnesses are sorted via their witness index
    // witness_values may not have all the witness indexes, e.g for unused witness which are not solved by the solver
    let num_witnesses = intermediate_witness.len();
    let mut sorted_witness = common::barretenberg_structures::Assignments::new();
    for i in 1..num_witnesses {
        let value = match intermediate_witness.get(&Witness(i as u32)) {
            Some(value) => *value,
            None => return Err(format!("Missing witness element at idx {}", i).into()),
        };

        sorted_witness.push(value);
    }

    let bytes = sorted_witness.to_bytes();
    Ok(js_sys::Uint8Array::from(&bytes[..]))
}

#[wasm_bindgen]
pub fn acir_to_constraints_system(
    circuit: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsErrorString> {
    console_error_panic_hook::set_once();

    let circuit = read_circuit(circuit)?;
    let bytes = common::serializer::serialize_circuit(&circuit).to_bytes();
    Ok(js_sys::Uint8Array::from(&bytes[..]))
}

#[wasm_bindgen]
pub fn public_input_length(circuit: js_sys::Uint8Array) -> Result<js_sys::Number, JsErrorString> {
    console_error_panic_hook::set_once();

    let circuit = read_circuit(circuit)?;
    let length = circuit.public_inputs().0.len() as u32;
    Ok(js_sys::Number::from(length))
}

#[wasm_bindgen]
pub fn public_input_as_bytes(
    public_witness: js_sys::Map,
) -> Result<js_sys::Uint8Array, JsErrorString> {
    console_error_panic_hook::set_once();

    let public_witness = js_map_to_witness_map(public_witness)?;
    let mut buffer = Vec::new();
    // Implicitly ordered by index
    for assignment in public_witness.values() {
        buffer.extend_from_slice(&assignment.to_be_bytes());
    }
    Ok(js_sys::Uint8Array::from(&buffer[..]))
}
