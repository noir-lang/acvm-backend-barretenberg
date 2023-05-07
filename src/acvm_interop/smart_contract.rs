use acvm::SmartContract;

use crate::crs::G2;
use crate::Barretenberg;

/// Embed the Solidity verifier file
const ULTRA_VERIFIER_CONTRACT: &str = include_str!("contract.sol");

#[cfg(feature = "native")]
impl SmartContract for Barretenberg {
    fn eth_contract_from_vk(&self, verification_key: &[u8]) -> String {
        use std::slice;

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
        };

        let verification_key_library: String = sc_as_bytes.iter().map(|b| *b as char).collect();
        format!("{verification_key_library}{ULTRA_VERIFIER_CONTRACT}")
    }
}

#[cfg(not(feature = "native"))]
impl SmartContract for Barretenberg {
    fn eth_contract_from_vk(&self, verification_key: &[u8]) -> String {
        use crate::wasm::POINTER_BYTES;

        let g2 = G2::new();

        let g2_ptr = self.allocate(&g2.data);
        let vk_ptr = self.allocate(verification_key);

        // The smart contract string is not actually written to this pointer.
        // `contract_ptr_ptr` is a pointer to a pointer which holds the smart contract string.
        let contract_ptr_ptr: usize = 0;

        let contract_size = self
            .call_multiple(
                "acir_proofs_get_solidity_verifier",
                vec![&g2_ptr, &vk_ptr, &contract_ptr_ptr.into()],
            )
            .value();
        let contract_size: usize = contract_size.unwrap_i32() as usize;

        // We then need to read the pointer at `contract_ptr_ptr` to get the smart contract's location
        // and then slice memory again at `contract_ptr_ptr` to get the smart contract string.
        let contract_ptr: [u8; POINTER_BYTES] = self.read_memory(contract_ptr_ptr);
        let contract_ptr: usize = u32::from_le_bytes(contract_ptr) as usize;

        let sc_as_bytes = self.read_memory_variable_length(contract_ptr, contract_size);

        let verification_key_library: String = sc_as_bytes.iter().map(|b| *b as char).collect();
        format!("{verification_key_library}{ULTRA_VERIFIER_CONTRACT}")
    }
}

#[test]
fn test_smart_contract() {
    use crate::barretenberg_structures::{Constraint, ConstraintSystem};
    use crate::composer::Composer;
    use crate::Barretenberg;
    use acvm::FieldElement;

    let constraint = Constraint {
        a: 1,
        b: 2,
        c: 3,
        qm: FieldElement::zero(),
        ql: FieldElement::one(),
        qr: FieldElement::one(),
        qo: -FieldElement::one(),
        qc: FieldElement::zero(),
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
