use common::acvm::acir::circuit::Circuit;
use common::acvm::SmartContract;
use common::crs::G2;
use wasmer::Value;

use crate::Barretenberg;

use super::Plonk;

/// Embed the Solidity verifier file
const CONTRACT: &str = include_str!("contract.sol");

impl SmartContract for Plonk {
    fn eth_contract_from_vk(&self, verification_key: &[u8]) -> String {
        let mut barretenberg = Barretenberg::new();
        let g2 = G2::new();

        let g2_ptr = barretenberg.allocate(&g2.data);
        let vk_ptr = barretenberg.allocate(verification_key);

        let contract_size = barretenberg
            .call_multiple(
                "acir_proofs_get_solidity_verifier",
                vec![&g2_ptr, &vk_ptr, &Value::I32(0)],
            )
            .value();
        let contract_ptr = barretenberg.slice_memory(0, 4);
        let contract_ptr = u32::from_le_bytes(contract_ptr[0..4].try_into().unwrap());

        let sc_as_bytes = barretenberg.slice_memory(
            contract_ptr as usize,
            contract_ptr as usize + contract_size.unwrap_i32() as usize,
        );

        let verification_key_library: String = sc_as_bytes.iter().map(|b| *b as char).collect();
        format!("{CONTRACT}{verification_key_library}")
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

    let mut sc = StandardComposer::new(constraint_system);

    let proving_key = sc.compute_proving_key();
    let verification_key = sc.compute_verification_key(&proving_key);

    let plonk = Plonk;
    let contract = plonk.eth_contract_from_vk(&verification_key);

    assert!(contract.contains("contract BaseUltraVerifier"));
    assert!(contract.contains("contract UltraVerifier"));
    assert!(contract.contains("library UltraVerificationKey"));
}
