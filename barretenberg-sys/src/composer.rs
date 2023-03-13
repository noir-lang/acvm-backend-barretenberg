use crate::*;

/// # Safety
/// pippenger must point to a valid Pippenger object
pub unsafe fn smart_contract(
    _pippenger: *mut ::std::os::raw::c_void,
    _g2_ptr: &[u8],
    _cs_ptr: &[u8],
    _output_buf: *mut *mut u8,
) -> u32 {
    unimplemented!()
}

/// # Safety
/// cs_prt must point to a valid constraints system structure of type standard_format
pub unsafe fn get_exact_circuit_size(cs_prt: *const u8) -> u32 {
    turbo_get_exact_circuit_size(cs_prt)
}

/// # Safety
/// cs_prt must point to a valid constraints system structure of type standard_format
pub unsafe fn init_proving_key(cs_ptr: &[u8], pk_data_ptr: *mut *mut u8) -> usize {
    let cs_ptr = cs_ptr.as_ptr();
    turbo_init_proving_key(cs_ptr, pk_data_ptr as *const *mut u8 as *mut *const u8)
}

/// # Safety
/// pippenger must point to a valid Pippenger object
pub unsafe fn init_verification_key(
    pippenger: *mut ::std::os::raw::c_void,
    g2_ptr: &[u8],
    pk_ptr: &[u8],
    vk_data_ptr: *mut *mut u8,
) -> usize {
    turbo_init_verification_key(
        pippenger,
        g2_ptr.as_ptr() as *const u8,
        pk_ptr.as_ptr() as *const u8,
        vk_data_ptr as *const *mut u8 as *mut *const u8,
    )
}

/// # Safety
/// pippenger must point to a valid Pippenger object
pub unsafe fn create_proof_with_pk(
    pippenger: *mut ::std::os::raw::c_void,
    g2_ptr: &[u8],
    pk_ptr: &[u8],
    cs_ptr: &[u8],
    witness_ptr: &[u8],
    proof_data_ptr: *mut *mut u8,
) -> usize {
    let cs_ptr = cs_ptr.as_ptr() as *const u8;
    let pk_ptr = pk_ptr.as_ptr() as *const u8;
    turbo_new_proof(
        pippenger,
        g2_ptr.as_ptr(),
        pk_ptr,
        cs_ptr,
        witness_ptr.as_ptr(),
        proof_data_ptr as *const *mut u8 as *mut *mut u8,
    )
}

/// # Safety
/// cs_prt must point to a valid constraints system structure of type standard_format
pub unsafe fn verify_with_vk(g2_ptr: &[u8], vk_ptr: &[u8], cs_ptr: &[u8], proof: &[u8]) -> bool {
    let proof_ptr = proof.as_ptr() as *const u8;

    turbo_verify_proof(
        g2_ptr.as_ptr() as *const u8,
        vk_ptr.as_ptr() as *const u8,
        cs_ptr.as_ptr() as *const u8,
        proof_ptr as *mut u8,
        proof.len() as u32,
    )
}
