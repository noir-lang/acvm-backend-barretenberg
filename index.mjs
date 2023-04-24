// import('node-fetch').then(fetch => {
//     global.fetch = fetch;
//     global.Headers = fetch.Headers;
//     global.Request = fetch.Request;
//     global.Response = fetch.Response;
// var assert = require('assert')
import assert from 'assert'
import A from './barretenberg_wasm/pkg/barretenberg_wasm.js'
// var A = require('./barretenberg_wasm/pkg/barretenberg_wasm.js')


async function fetchCRSData(start, end) {

    const response = await fetch('http://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/monomial/transcript00.dat', {
        headers: {
            Range: `bytes=${start}-${end}`,
        },
    });

    return response.arrayBuffer()
}


A.init_log_level("debug");

var cs = new A.ConstraintSystem()
// });
var sc = new A.StandardComposer(cs)

const circuitSize = sc.get_circ_size();
console.log("Circuit size is", circuitSize);

const g1Start = 28;
const g1End = g1Start + ((circuitSize + 1) * 64) - 1;

const g2Start = 28 + (5040000 * 64);
const g2End = g2Start + 128 - 1;

const circuitG1Data = await fetchCRSData(g1Start, g1End);
const circuitG2Data = await fetchCRSData(g2Start, g2End);

console.log("G1 Data:", circuitG1Data);
console.log("G2 Data:", circuitG2Data);

sc.init_crs_data(circuitSize, new Uint8Array(circuitG1Data), new Uint8Array(circuitG2Data));
sc.create_pippenger();

var pk = sc.compute_proving_key()
var vk = sc.compute_verification_key(pk)
var proof = sc.create_proof_with_pk(new A.Assignments(), pk)
var verified = sc.verify_with_vk(proof, new A.Assignments(), vk);
assert(verified);
console.log("verified!")
