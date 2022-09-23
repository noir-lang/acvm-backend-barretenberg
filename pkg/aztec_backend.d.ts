/* tslint:disable */
/* eslint-disable */
/**
* @param {any} circuit
* @param {(string)[]} initial_js_witness
* @returns {Uint8Array}
*/
export function compute_witnesses(circuit: any, initial_js_witness: (string)[]): Uint8Array;
/**
* @param {any} acir
* @returns {Uint8Array}
*/
export function serialise_acir_to_barrtenberg_circuit(acir: any): Uint8Array;
/**
* @param {any} acir
* @param {Uint8Array} witness_arr
* @returns {Uint8Array}
*/
export function packed_witness_to_witness(acir: any, witness_arr: Uint8Array): Uint8Array;
/**
* @param {string} vk_method
* @returns {string}
*/
export function eth_contract_from_cs(vk_method: string): string;
/**
* @param {(string)[]} pub_inputs_js_string
* @returns {Uint8Array}
*/
export function serialise_public_inputs(pub_inputs_js_string: (string)[]): Uint8Array;
/**
* A struct representing an aborted instruction execution, with a message
* indicating the cause.
*/
export class WasmerRuntimeError {
  free(): void;
}
