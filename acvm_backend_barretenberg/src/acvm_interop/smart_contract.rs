use common::acvm::SmartContract;
use common::crs::G2;
use common::ULTRA_VERIFIER_CONTRACT;

use crate::Barretenberg;

impl SmartContract for Barretenberg {
    fn eth_contract_from_vk(&self, verification_key: &[u8]) -> String {
        let g2 = G2::new();

        cfg_if::cfg_if! {
            if #[cfg(feature = "native")] {
                use std::slice;

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
                };
            } else {
                use wasmer::Value;

                let g2_ptr = self.allocate(&g2.data);
                let vk_ptr = self.allocate(verification_key);

                let contract_size = self
                    .call_multiple(
                        "acir_proofs_get_solidity_verifier",
                        vec![&g2_ptr, &vk_ptr, &Value::I32(0)],
                    )
                    .value();
                let contract_ptr = self.slice_memory(0, 4);
                let contract_ptr = u32::from_le_bytes(contract_ptr[0..4].try_into().unwrap());

                let sc_as_bytes = self.slice_memory(
                    contract_ptr as usize,
                    contract_ptr as usize + contract_size.unwrap_i32() as usize,
                );
            }
        }

        let verification_key_library: String = sc_as_bytes.iter().map(|b| *b as char).collect();
        format!("{verification_key_library}{ULTRA_VERIFIER_CONTRACT}")
    }
}

#[test]
fn test_smart_contract() {
    use crate::Barretenberg;
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

    let bb = Barretenberg::new();

    let proving_key = bb.compute_proving_key(&constraint_system);
    let verification_key = bb.compute_verification_key(&constraint_system, &proving_key);

    let contract = bb.eth_contract_from_vk(&verification_key);

    assert!(contract.contains("contract BaseUltraVerifier"));
    assert!(contract.contains("contract UltraVerifier"));
    assert!(contract.contains("library UltraVerificationKey"));
}
