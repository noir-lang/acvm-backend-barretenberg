use common::acvm::{acir::circuit::Circuit, acir::native_types::Witness, FieldElement};
use js_sys::JsString;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

pub type JsErrorString = JsString;
pub type WitnessMap = BTreeMap<Witness, FieldElement>;

pub fn js_value_to_field_element(js_value: JsValue) -> Result<FieldElement, JsErrorString> {
    let hex_str = match js_value.as_string() {
        Some(str) => str,
        None => return Err("failed to parse field element from non-string".into()),
    };
    match FieldElement::from_hex(&hex_str) {
        Some(field_element) => Ok(field_element),
        None => Err(format!("Invalid hex string: '{}'", hex_str).into()),
    }
}

pub fn js_map_to_witness_map(js_map: js_sys::Map) -> Result<WitnessMap, JsErrorString> {
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

pub fn field_element_to_js_string(field_element: &FieldElement) -> JsString {
    format!("0x{}", field_element.to_hex()).into()
}

pub fn witness_map_to_js_map(witness_map: BTreeMap<Witness, FieldElement>) -> js_sys::Map {
    let js_map = js_sys::Map::new();
    for (witness, field_value) in witness_map.iter() {
        let js_idx = js_sys::Number::from(witness.0);
        let js_hex_str = field_element_to_js_string(field_value);
        js_map.set(&js_idx, &js_hex_str);
    }
    js_map
}

pub fn read_circuit(circuit: js_sys::Uint8Array) -> Result<Circuit, JsErrorString> {
    let circuit: Vec<u8> = circuit.to_vec();
    match Circuit::read(&*circuit) {
        Ok(circuit) => Ok(circuit),
        Err(err) => Err(format!("Circuit read err: {}", err).into()),
    }
}

pub fn format_js_err(err: JsValue) -> String {
    match err.as_string() {
        Some(str) => str,
        None => "Unknown".to_owned(),
    }
}
