var assert = require('assert')

var A = require('./barretenberg_wasm/pkg/barretenberg_wasm.js')
var cs = new A.ConstraintSystem()
var sc = new A.StandardComposer(cs)
var pk = sc.compute_proving_key()
var vk = sc.compute_verification_key(pk)
var proof = sc.create_proof_with_pk(new A.Assignments(), pk)
var verified = sc.verify_with_vk(proof, new A.Assignments(), vk);
assert(verified);
console.log("verified!")
