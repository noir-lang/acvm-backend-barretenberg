use common::acvm::SmartContract;
use common::crs::G2;
use common::ULTRA_VERIFIER_CONTRACT;
use wasmer::Value;

use crate::{Barretenberg, POINTER_BYTES};

use super::Plonk;

impl SmartContract for Plonk {
    fn eth_contract_from_vk(&self, verification_key: &[u8]) -> String {
        // TODO: Don't create an entire new wasm instance for one function call
        let mut barretenberg = Barretenberg::new();
        let g2 = G2::new();

        let g2_ptr = barretenberg.allocate(&g2.data);
        let vk_ptr = barretenberg.allocate(verification_key);
        let result_ptr: usize = 0;

        let contract_size = barretenberg
            .call_multiple(
                "acir_proofs_get_solidity_verifier",
                vec![&g2_ptr, &vk_ptr, &Value::I32(result_ptr as i32)],
            )
            .value();
        let contract_size: usize = contract_size.unwrap_i32() as usize;

        let contract_ptr = barretenberg.slice_memory(result_ptr, POINTER_BYTES);
        let contract_ptr: usize =
            u32::from_le_bytes(contract_ptr[0..POINTER_BYTES].try_into().unwrap()) as usize;

        let sc_as_bytes = barretenberg.slice_memory(contract_ptr, contract_size);

        let verification_key_library: String = sc_as_bytes.iter().map(|b| *b as char).collect();
        format!("{verification_key_library}{ULTRA_VERIFIER_CONTRACT}")
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

    let constraint_system = ConstraintSystem::new()
        .var_num(4)
        .public_inputs(vec![1, 2])
        .constraints(vec![constraint]);

    let mut sc = StandardComposer::new(constraint_system);

    let proving_key = sc.compute_proving_key();
    let verification_key = sc.compute_verification_key(&proving_key);

    let plonk = Plonk;
    let contract = plonk.eth_contract_from_vk(&verification_key);

    assert!(contract.contains("contract BaseUltraVerifier"));
    assert!(contract.contains("contract UltraVerifier"));
    assert!(contract.contains("library UltraVerificationKey"));
}
