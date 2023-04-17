use barretenberg_wasm;
use common::acvm::{
    acir::brillig_bytecode, acir::circuit::opcodes::Brillig, acir::circuit::Opcode,
    acir::native_types::Witness, pwg::block::Blocks, PartialWitnessGenerator, UnresolvedBrillig,
    UnresolvedData,
};
use js_sys::JsString;
use js_transforms::{
    field_element_to_js_string, format_js_err, js_map_to_witness_map, js_value_to_field_element,
    read_circuit, witness_map_to_js_map, JsErrorString,
};
use wasm_bindgen::prelude::*;

mod js_transforms;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

async fn resolve_oracle(
    oracle_resolver: &js_sys::Function,
    mut unresolved_brillig: UnresolvedBrillig,
) -> Result<Brillig, JsErrorString> {
    let mut oracle_data = unresolved_brillig.oracle_wait_info.data;

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
    // TODO: re-enable length check once the opcode supports it again
    // let ouput_len = js_arr.length() as usize;
    // let expected_output_len = oracle_data.outputs.len();
    // if ouput_len != expected_output_len {
    //     return Err(format!(
    //         "Expected output from oracle '{}' of {} elements, but instead received {}",
    //         oracle_data.name, expected_output_len, ouput_len
    //     )
    //     .into());
    // }
    for elem in js_arr.iter() {
        if !elem.is_string() {
            return Err("Non-string element in oracle_resolver return".into());
        }
        oracle_data
            .output_values
            .push(js_value_to_field_element(elem)?)
    }

    // Insert updated brillig oracle into bytecode
    unresolved_brillig.brillig.bytecode[unresolved_brillig.oracle_wait_info.program_counter] =
        brillig_bytecode::Opcode::Oracle(oracle_data);

    Ok(unresolved_brillig.brillig)
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
        let UnresolvedData {
            mut unresolved_opcodes,
            unresolved_brilligs,
            ..
        } = plonk
            .solve(&mut witness_assignments, &mut blocks, opcodes_to_solve)
            .map_err(|err| JsString::from(format!("solver opcode resolution error: {}", err)))?;
        let brillig_futures: Vec<_> = unresolved_brilligs
            .into_iter()
            .map(|unresolved_brillig| resolve_oracle(&oracle_resolver, unresolved_brillig))
            .collect();
        opcodes_to_solve = Vec::new();
        for brillig_future in brillig_futures {
            let filled_brillig = brillig_future.await?;
            unresolved_opcodes.push(Opcode::Brillig(filled_brillig));
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
