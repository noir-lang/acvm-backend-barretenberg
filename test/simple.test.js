import { expect } from '@open-wc/testing';

import initBackend, { init_log_level, ConstraintSystem, StandardComposer } from '../barretenberg_wasm/pkg-web/barretenberg_wasm.js'

async function fetchCRSData(start, end) {

    const response = await fetch('http://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/monomial/transcript00.dat', {
        headers: {
            Range: `bytes=${start}-${end}`,
        },
    });

    return response.arrayBuffer()
}

await initBackend();
debugger;
await init_log_level("debug");

const cs = new ConstraintSystem();

const sc = new StandardComposer(cs);

const circuitSize = sc.get_circ_size();
console.log("Circuit size is", circuitSize);
