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
        format!("{verification_key_library}{ULTRA_VERIFIER_CONTRACT}")
    }
}
use rusty_fork::rusty_fork_test;
rusty_fork_test! {

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

    let constraint_system = ConstraintSystem::new()
        .var_num(4)
        .public_inputs(vec![1, 2])
        .constraints(vec![constraint]);

    let sc = StandardComposer::new(constraint_system);

    let proving_key = sc.compute_proving_key();
    let verification_key = sc.compute_verification_key(&proving_key);

    let plonk = Plonk;
    let contract = plonk.eth_contract_from_vk(&verification_key);

    assert!(contract.contains("contract BaseUltraVerifier"));
    assert!(contract.contains("contract UltraVerifier"));
    assert!(contract.contains("library UltraVerificationKey"));
}
}
