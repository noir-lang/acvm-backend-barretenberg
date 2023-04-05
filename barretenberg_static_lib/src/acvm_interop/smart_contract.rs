use common::acvm::acir::circuit::Circuit;
use common::acvm::SmartContract;
use common::crs::G2;
use common::ULTRA_VERIFIER_CONTRACT;
use std::slice;

use super::Plonk;

impl SmartContract for Plonk {
    fn eth_contract_from_vk(&self, verification_key: &[u8]) -> String {
        let g2 = G2::new();
        let mut contract_ptr: *mut u8 = std::ptr::null_mut();
        let p_contract_ptr = &mut contract_ptr as *mut *mut u8;
        let verification_key = verification_key.to_vec();
        let sc_as_bytes;
        let contract_size;
        unsafe {
            contract_size = barretenberg_sys::composer::get_solidity_verifier(
                &g2.data,
                &verification_key,
                p_contract_ptr,
            );
            sc_as_bytes = slice::from_raw_parts(contract_ptr, contract_size)
        }

        let verification_key_library: String = sc_as_bytes.iter().map(|b| *b as char).collect();
        format!("{ULTRA_VERIFIER_CONTRACT}{verification_key_library}")
    }

    fn eth_contract_from_cs(&self, _circuit: Circuit) -> String {
        unimplemented!("use `eth_contract_from_vk`");
    }
}

#[test]
fn test_smart_contract() {
    use crate::composer::StandardComposer;
    use common::barretenberg_structures::*;

    let constraint = Constraint {
        a: 1,
        b: 2,
        c: 3,
        qm: Scalar::zero(),
        ql: Scalar::one(),
        qr: Scalar::one(),
        qo: -Scalar::one(),
        qc: Scalar::zero(),
    };

    let constraint_system = ConstraintSystem {
        var_num: 4,
        public_inputs: vec![1, 2],
        logic_constraints: vec![],
        range_constraints: vec![],
        sha256_constraints: vec![],
        merkle_membership_constraints: vec![],
        schnorr_constraints: vec![],
        blake2s_constraints: vec![],
        pedersen_constraints: vec![],
        hash_to_field_constraints: vec![],
        constraints: vec![constraint],
        ecdsa_secp256k1_constraints: vec![],
        fixed_base_scalar_mul_constraints: vec![],
    };

    let sc = StandardComposer::new(constraint_system);

    let proving_key = sc.compute_proving_key();
    let verification_key = sc.compute_verification_key(&proving_key);

    let plonk = Plonk;
    let contract = plonk.eth_contract_from_vk(&verification_key);

    assert!(contract.contains("contract BaseUltraVerifier"));
    assert!(contract.contains("contract UltraVerifier"));
    assert!(contract.contains("library UltraVerificationKey"));
}
