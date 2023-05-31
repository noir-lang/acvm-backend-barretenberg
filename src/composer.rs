use acvm::async_trait;

use crate::barretenberg_structures::{Assignments, ConstraintSystem};
use crate::crs::download_crs;
use crate::{crs::CRS, Barretenberg, Error, FIELD_BYTES};
use std::slice;

const NUM_RESERVED_GATES: u32 = 4; // this must be >= num_roots_cut_out_of_vanishing_polynomial (found under prover settings in barretenberg)

#[async_trait(?Send)]
pub(crate) trait Composer {
    fn get_circuit_size(&self, constraint_system: &ConstraintSystem) -> Result<u32, Error>;

    fn get_exact_circuit_size(&self, constraint_system: &ConstraintSystem) -> Result<u32, Error>;

    async fn get_crs(&self, constraint_system: &ConstraintSystem) -> Result<CRS, Error> {
        let num_points = self.get_circuit_size(constraint_system)?;

        download_crs(num_points as usize).await
    }

    async fn update_crs<'a>(
        &self,
        crs: &'a mut CRS,
        constraint_system: &ConstraintSystem,
    ) -> Result<&'a CRS, Error> {
        let num_points = self.get_circuit_size(constraint_system)?;

        if crs.num_points < num_points as usize {
            crs.update(num_points as usize).await?;
        }

        Ok(crs)
    }

    fn compute_proving_key(&self, constraint_system: &ConstraintSystem) -> Result<Vec<u8>, Error>;
    fn compute_verification_key(&self, crs: &CRS, proving_key: &[u8]) -> Result<Vec<u8>, Error>;

    fn create_proof_with_pk(
        &self,
        crs: &CRS,
        constraint_system: &ConstraintSystem,
        witness: Assignments,
        proving_key: &[u8],
        is_recursive: bool,
    ) -> Result<Vec<u8>, Error>;

    fn verify_with_vk(
        &self,
        crs: &CRS,
        constraint_system: &ConstraintSystem,
        // XXX: Important: This assumes that the proof does not have the public inputs pre-pended to it
        // This is not the case, if you take the proof directly from Barretenberg
        proof: &[u8],
        public_inputs: Assignments,
        verification_key: &[u8],
        is_recursive: bool,
    ) -> Result<bool, Error>;

    fn proof_as_fields(&self, proof: &[u8], public_inputs: Assignments) -> Result<Vec<u8>, Error>;
    fn verification_key_as_fields(&self, crs: &CRS, verification_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>;
}

#[cfg(feature = "native")]
impl Composer for Barretenberg {
    // XXX: There seems to be a bug in the C++ code
    // where it causes a `HeapAccessOutOfBound` error
    // for certain circuit sizes.
    //
    // This method calls the WASM for the circuit size
    // if an error is returned, then the circuit size is defaulted to 2^19.
    //
    // This method is primarily used to determine how many group
    // elements we need from the CRS. So using 2^19 on an error
    // should be an overestimation.
    fn get_circuit_size(&self, constraint_system: &ConstraintSystem) -> Result<u32, Error> {
        let cs_buf = constraint_system.to_bytes();

        let circuit_size;
        unsafe {
            circuit_size =
                barretenberg_sys::composer::get_total_circuit_size(cs_buf.as_slice().as_ptr());
        }

        pow2ceil(circuit_size + NUM_RESERVED_GATES)
    }

    fn get_exact_circuit_size(&self, constraint_system: &ConstraintSystem) -> Result<u32, Error> {
        let cs_buf = constraint_system.to_bytes();

        let circuit_size;
        unsafe {
            circuit_size =
                barretenberg_sys::composer::get_exact_circuit_size(cs_buf.as_slice().as_ptr())
        }

        Ok(circuit_size)
    }

    fn compute_proving_key(&self, constraint_system: &ConstraintSystem) -> Result<Vec<u8>, Error> {
        let cs_buf = constraint_system.to_bytes();

        let mut pk_addr: *mut u8 = std::ptr::null_mut();
        let pk_ptr = &mut pk_addr as *mut *mut u8;

        let pk_size;
        unsafe {
            pk_size = barretenberg_sys::composer::init_proving_key(&cs_buf, pk_ptr);
        }

        let result;
        unsafe {
            result = Vec::from_raw_parts(pk_addr, pk_size, pk_size);
        }
        Ok(result)
    }

    fn compute_verification_key(&self, crs: &CRS, proving_key: &[u8]) -> Result<Vec<u8>, Error> {
        let CRS {
            g1_data, g2_data, ..
        } = crs;
        let pippenger_ptr = self.get_pippenger(g1_data)?.pointer();

        let mut vk_addr: *mut u8 = std::ptr::null_mut();
        let vk_ptr = &mut vk_addr as *mut *mut u8;

        let vk_size;
        unsafe {
            vk_size = barretenberg_sys::composer::init_verification_key(
                pippenger_ptr,
                g2_data,
                proving_key,
                vk_ptr,
            )
        }

        let result;
        unsafe {
            result = Vec::from_raw_parts(vk_addr, vk_size, vk_size);
        }
        Ok(result.to_vec())
    }

    fn create_proof_with_pk(
        &self,
        crs: &CRS,
        constraint_system: &ConstraintSystem,
        witness: Assignments,
        proving_key: &[u8],
        is_recursive: bool,
    ) -> Result<Vec<u8>, Error> {
        let CRS {
            g1_data, g2_data, ..
        } = crs;
        let pippenger_ptr = self.get_pippenger(g1_data)?.pointer();
        let cs_buf: Vec<u8> = constraint_system.to_bytes();
        let witness_buf = witness.to_bytes();

        let mut proof_addr: *mut u8 = std::ptr::null_mut();
        let p_proof = &mut proof_addr as *mut *mut u8;

        let proof_size;
        unsafe {
            proof_size = barretenberg_sys::composer::create_proof_with_pk(
                pippenger_ptr,
                g2_data,
                proving_key,
                &cs_buf,
                &witness_buf,
                p_proof,
            );
        }

        let result;
        unsafe {
            result = Vec::from_raw_parts(proof_addr, proof_size, proof_size);
        }

        // Barretenberg returns proofs which are prepended with the public inputs.
        // This behavior is nonstandard so we strip the public inputs from the proof.
        Ok(remove_public_inputs(
            constraint_system.public_inputs_size(),
            &result,
        ))
    }

    fn verify_with_vk(
        &self,
        crs: &CRS,
        constraint_system: &ConstraintSystem,
        // XXX: Important: This assumes that the proof does not have the public inputs pre-pended to it
        // This is not the case, if you take the proof directly from Barretenberg
        proof: &[u8],
        public_inputs: Assignments,
        verification_key: &[u8],
        is_recursive: bool,
    ) -> Result<bool, Error> {
        let CRS { g2_data, .. } = crs;

        // Barretenberg expects public inputs to be prepended onto the proof
        let proof = prepend_public_inputs(proof.to_vec(), public_inputs);
        let cs_buf = constraint_system.to_bytes();

        let verified;
        unsafe {
            verified = barretenberg_sys::composer::verify_with_vk(
                g2_data,
                verification_key,
                &cs_buf,
                &proof,
            );
        }
        Ok(verified)
    }

    fn proof_as_fields(&self, proof: &[u8], public_inputs: Assignments) -> Result<Vec<u8>, Error> {
        let num_public_inputs = public_inputs.len();
        let mut proof_fields_addr: *mut u8 = std::ptr::null_mut();
        let p_proof_fields = &mut proof_fields_addr as *mut *mut u8;
        let proof = prepend_public_inputs(proof.to_vec(), public_inputs);

        let proof_fields_size;
        unsafe {
            proof_fields_size = barretenberg_sys::composer::serialize_proof_into_field_elements(
                &proof,
                p_proof_fields,
                proof.len(),
                num_public_inputs,
            )
        }

        let result;
        unsafe {
            result = Vec::from_raw_parts(proof_fields_addr, proof_fields_size, proof_fields_size);
        }

        Ok(result)
    }

    fn verification_key_as_fields(&self, crs: &CRS, verification_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let CRS { g2_data, .. } = crs;

        let mut vk_fields_addr: *mut u8 = std::ptr::null_mut();
        let p_vk_fields = &mut vk_fields_addr as *mut *mut u8;

        let mut vk_hash_fields_addr: *mut u8 = std::ptr::null_mut();
        let p_vk_hash_fields = &mut vk_hash_fields_addr as *mut *mut u8;

        let vk_fields_size;
        unsafe {
            vk_fields_size =
                barretenberg_sys::composer::serialize_verification_key_into_field_elements(
                    g2_data,
                    verification_key,
                    p_vk_fields,
                    p_vk_hash_fields,
                )
        }

        let vk_result;
        let vk_hash_result;
        unsafe {
            vk_result = Vec::from_raw_parts(vk_fields_addr, vk_fields_size, vk_fields_size);
            vk_hash_result = slice::from_raw_parts(vk_hash_fields_addr, 32);
        }

        Ok((vk_result.to_vec(), vk_hash_result.to_vec()))
    }
}

#[cfg(not(feature = "native"))]
impl Composer for Barretenberg {
    // XXX: There seems to be a bug in the C++ code
    // where it causes a `HeapAccessOutOfBound` error
    // for certain circuit sizes.
    //
    // This method calls the WASM for the circuit size
    // if an error is returned, then the circuit size is defaulted to 2^19.
    //
    // This method is primarily used to determine how many group
    // elements we need from the CRS. So using 2^19 on an error
    // should be an overestimation.
    fn get_circuit_size(&self, constraint_system: &ConstraintSystem) -> Result<u32, Error> {
        let cs_buf = constraint_system.to_bytes();
        let cs_ptr = self.allocate(&cs_buf)?;

        // This doesn't unwrap the result because we need to free even if there is a failure
        let circuit_size = self.call("acir_proofs_get_total_circuit_size", &cs_ptr);

        self.free(cs_ptr)?;

        let size: u32 = circuit_size?.try_into()?;

        pow2ceil(size + NUM_RESERVED_GATES)
    }

    fn get_exact_circuit_size(&self, constraint_system: &ConstraintSystem) -> Result<u32, Error> {
        let cs_buf = constraint_system.to_bytes();
        let cs_ptr = self.allocate(&cs_buf)?;

        // This doesn't unwrap the result because we need to free even if there is a failure
        let circuit_size = self.call("acir_proofs_get_exact_circuit_size", &cs_ptr);

        self.free(cs_ptr)?;

        Ok(circuit_size?.try_into()?)
    }

    fn compute_proving_key(&self, constraint_system: &ConstraintSystem) -> Result<Vec<u8>, Error> {
        let cs_buf = constraint_system.to_bytes();
        let cs_ptr = self.allocate(&cs_buf)?;

        // The proving key is not actually written to this pointer.
        // `pk_ptr_ptr` is a pointer to a pointer which holds the proving key.
        let pk_ptr_ptr: usize = 0;

        let pk_size = self.call_multiple(
            "acir_proofs_init_proving_key",
            vec![&cs_ptr, &pk_ptr_ptr.into()],
        )?;

        // We then need to read the pointer at `pk_ptr_ptr` to get the key's location
        // and then slice memory again at `pk_ptr` to get the proving key.
        let pk_ptr = self.get_pointer(pk_ptr_ptr);

        Ok(self.read_memory_variable_length(pk_ptr, pk_size.try_into()?))
    }

    fn compute_verification_key(&self, crs: &CRS, proving_key: &[u8]) -> Result<Vec<u8>, Error> {
        let CRS {
            g1_data, g2_data, ..
        } = crs;
        let pippenger_ptr = self.get_pippenger(g1_data)?.pointer();

        let g2_ptr = self.allocate(g2_data)?;
        let pk_ptr = self.allocate(proving_key)?;

        // The verification key is not actually written to this pointer.
        // `vk_ptr_ptr` is a pointer to a pointer which holds the verification key.
        let vk_ptr_ptr: usize = 0;

        let vk_size = self.call_multiple(
            "acir_proofs_init_verification_key",
            vec![&pippenger_ptr, &g2_ptr, &pk_ptr, &vk_ptr_ptr.into()],
        )?;

        // We then need to read the pointer at `vk_ptr_ptr` to get the key's location
        // and then slice memory again at `vk_ptr` to get the verification key.
        let vk_ptr = self.get_pointer(vk_ptr_ptr);

        Ok(self.read_memory_variable_length(vk_ptr, vk_size.try_into()?))
    }

    fn create_proof_with_pk(
        &self,
        crs: &CRS,
        constraint_system: &ConstraintSystem,
        witness: Assignments,
        proving_key: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let CRS {
            g1_data, g2_data, ..
        } = crs;
        let pippenger_ptr = self.get_pippenger(g1_data)?.pointer();
        let cs_buf: Vec<u8> = constraint_system.to_bytes();
        let witness_buf = witness.to_bytes();

        let cs_ptr = self.allocate(&cs_buf)?;
        let witness_ptr = self.allocate(&witness_buf)?;
        let g2_ptr = self.allocate(g2_data)?;
        let pk_ptr = self.allocate(proving_key)?;

        // The proof data is not actually written to this pointer.
        // `proof_ptr_ptr` is a pointer to a pointer which holds the proof data.
        let proof_ptr_ptr: usize = 0;

        let proof_size = self.call_multiple(
            "acir_proofs_new_proof",
            vec![
                &pippenger_ptr,
                &g2_ptr,
                &pk_ptr,
                &cs_ptr,
                &witness_ptr,
                &proof_ptr_ptr.into(),
            ],
        )?;

        // We then need to read the pointer at `proof_ptr_ptr` to get the proof's location
        // and then slice memory again at `proof_ptr` to get the proof data.
        let proof_ptr = self.get_pointer(proof_ptr_ptr);

        let result = self.read_memory_variable_length(proof_ptr, proof_size.try_into()?);

        // Barretenberg returns proofs which are prepended with the public inputs.
        // This behavior is nonstandard so we strip the public inputs from the proof.
        Ok(remove_public_inputs(
            constraint_system.public_inputs_size(),
            &result,
        ))
    }

    fn verify_with_vk(
        &self,
        crs: &CRS,
        constraint_system: &ConstraintSystem,
        // XXX: Important: This assumes that the proof does not have the public inputs pre-pended to it
        // This is not the case, if you take the proof directly from Barretenberg
        proof: &[u8],
        public_inputs: Assignments,
        verification_key: &[u8],
    ) -> Result<bool, Error> {
        let CRS { g2_data, .. } = crs;

        // Barretenberg expects public inputs to be prepended onto the proof
        let proof = prepend_public_inputs(proof.to_vec(), public_inputs);
        let cs_buf = constraint_system.to_bytes();

        let cs_ptr = self.allocate(&cs_buf)?;
        let proof_ptr = self.allocate(&proof)?;
        let g2_ptr = self.allocate(g2_data)?;
        let vk_ptr = self.allocate(verification_key)?;

        // This doesn't unwrap the result because we need to free even if there is a failure
        let verified = self.call_multiple(
            "acir_proofs_verify_proof",
            vec![&g2_ptr, &vk_ptr, &cs_ptr, &proof_ptr, &proof.len().into()],
        );

        self.free(proof_ptr)?;

        Ok(verified?.try_into()?)
    }
}

fn pow2ceil(v: u32) -> Result<u32, Error> {
    if v > (u32::MAX >> 1) {
        Err(Error::Pow2CeilOverflow(v))
    } else {
        let mut p = 1;
        while p < v {
            p <<= 1;
        }
        Ok(p)
    }
}

/// Removes the public inputs which are prepended to a proof by Barretenberg.
fn remove_public_inputs(num_pub_inputs: usize, proof: &[u8]) -> Vec<u8> {
    // Barretenberg prepends the public inputs onto the proof so we need to remove
    // the first `num_pub_inputs` field elements.
    let num_bytes_to_remove = num_pub_inputs * FIELD_BYTES;
    proof[num_bytes_to_remove..].to_vec()
}

/// Prepends a set of public inputs to a proof.
fn prepend_public_inputs(proof: Vec<u8>, public_inputs: Assignments) -> Vec<u8> {
    if public_inputs.is_empty() {
        return proof;
    }

    let public_inputs_bytes = public_inputs
        .into_iter()
        .flat_map(|assignment| assignment.to_be_bytes());

    public_inputs_bytes.chain(proof.into_iter()).collect()
}

#[cfg(test)]
mod test {
    use acvm::FieldElement;
    use tokio::test;

    use super::*;
    use crate::{barretenberg_structures::{
        BlockConstraint, Constraint, Keccak256Constraint, LogicConstraint, MemOpBarretenberg,
        PedersenConstraint, RangeConstraint, SchnorrConstraint, RecursionConstraint,
    }, recursion::Recursion};

    #[test]
    async fn test_no_constraints_no_pub_inputs() -> Result<(), Error> {
        let constraint_system = ConstraintSystem::new();

        let case_1 = WitnessResult {
            witness: vec![].into(),
            public_inputs: Assignments::default(),
            result: true,
        };
        let test_cases = vec![case_1];

        test_composer_with_pk_vk(constraint_system, test_cases).await
    }

    #[test]
    async fn test_a_single_constraint_no_pub_inputs() -> Result<(), Error> {
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
            .constraints(vec![constraint]);

        let case_1 = WitnessResult {
            witness: vec![(-1_i128).into(), 2_i128.into(), 1_i128.into()].into(),
            public_inputs: Assignments::default(),
            result: true,
        };
        let case_2 = WitnessResult {
            witness: vec![
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
            ]
            .into(),
            public_inputs: Assignments::default(),
            result: true,
        };
        let case_3 = WitnessResult {
            witness: vec![10_i128.into(), (-3_i128).into(), 7_i128.into()].into(),
            public_inputs: Assignments::default(),
            result: true,
        };
        let case_4 = WitnessResult {
            witness: vec![
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::one(),
            ]
            .into(),
            public_inputs: Assignments::default(),
            result: false,
        };
        let case_5 = WitnessResult {
            witness: vec![FieldElement::one(), 2_i128.into(), 6_i128.into()].into(),
            public_inputs: Assignments::default(),
            result: false,
        };
        let test_cases = vec![case_1, case_2, case_3, case_4, case_5];

        test_composer_with_pk_vk(constraint_system, test_cases).await
    }

    #[test]
    async fn test_a_single_constraint_with_pub_inputs() -> Result<(), Error> {
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

        // This fails because the constraint system requires public inputs,
        // but none are supplied in public_inputs. So the verifier will not
        // supply anything.
        let _case_1 = WitnessResult {
            witness: vec![(-1_i128).into(), 2_i128.into(), 1_i128.into()].into(),
            public_inputs: Assignments::default(),
            result: false,
        };
        let case_2 = WitnessResult {
            witness: vec![
                FieldElement::zero(),
                FieldElement::zero(),
                FieldElement::zero(),
            ]
            .into(),
            public_inputs: vec![FieldElement::zero(), FieldElement::zero()].into(),
            result: true,
        };

        let case_3 = WitnessResult {
            witness: vec![FieldElement::one(), 2_i128.into(), 6_i128.into()].into(),
            public_inputs: vec![FieldElement::one(), 3_i128.into()].into(),
            result: false,
        };

        // Not enough public inputs
        let _case_4 = WitnessResult {
            witness: vec![
                FieldElement::one(),
                FieldElement::from(2_i128),
                FieldElement::from(6_i128),
            ]
            .into(),
            public_inputs: vec![FieldElement::one()].into(),
            result: false,
        };

        let case_5 = WitnessResult {
            witness: vec![FieldElement::one(), 2_i128.into(), 3_i128.into()].into(),
            public_inputs: vec![FieldElement::one(), 2_i128.into()].into(),
            result: true,
        };

        let case_6 = WitnessResult {
            witness: vec![FieldElement::one(), 2_i128.into(), 3_i128.into()].into(),
            public_inputs: vec![FieldElement::one(), 3_i128.into()].into(),
            result: false,
        };
        let test_cases = vec![
            /*case_1,*/ case_2, case_3, /*case_4,*/ case_5, case_6,
        ];

        test_composer_with_pk_vk(constraint_system, test_cases).await
    }

    #[test]
    async fn test_multiple_constraints() -> Result<(), Error> {
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
        let constraint2 = Constraint {
            a: 2,
            b: 3,
            c: 4,
            qm: FieldElement::one(),
            ql: FieldElement::zero(),
            qr: FieldElement::zero(),
            qo: -FieldElement::one(),
            qc: FieldElement::one(),
        };

        let constraint_system = ConstraintSystem::new()
            .var_num(5)
            .public_inputs(vec![1])
            .constraints(vec![constraint, constraint2]);

        let case_1 = WitnessResult {
            witness: vec![1_i128.into(), 1_i128.into(), 2_i128.into(), 3_i128.into()].into(),
            public_inputs: vec![FieldElement::one()].into(),
            result: true,
        };
        let case_2 = WitnessResult {
            witness: vec![1_i128.into(), 1_i128.into(), 2_i128.into(), 13_i128.into()].into(),
            public_inputs: vec![FieldElement::one()].into(),
            result: false,
        };

        test_composer_with_pk_vk(constraint_system, vec![case_1, case_2]).await
    }

    #[test]
    async fn test_schnorr_constraints() -> Result<(), Error> {
        let mut signature_indices = [0i32; 64];
        for i in 13..(13 + 64) {
            signature_indices[i - 13] = i as i32;
        }
        let result_index = signature_indices.last().unwrap() + 1;

        let constraint = SchnorrConstraint {
            message: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            public_key_x: 11,
            public_key_y: 12,
            signature: signature_indices,
            result: result_index,
        };

        let arith_constraint = Constraint {
            a: result_index,
            b: result_index,
            c: result_index,
            qm: FieldElement::zero(),
            ql: FieldElement::zero(),
            qr: FieldElement::zero(),
            qo: FieldElement::one(),
            qc: -FieldElement::one(),
        };

        let constraint_system = ConstraintSystem::new()
            .var_num(80)
            .schnorr_constraints(vec![constraint])
            .constraints(vec![arith_constraint]);

        let pub_x = FieldElement::from_hex(
            "0x17cbd3ed3151ccfd170efe1d54280a6a4822640bf5c369908ad74ea21518a9c5",
        )
        .unwrap();
        let pub_y = FieldElement::from_hex(
            "0x0e0456e3795c1a31f20035b741cd6158929eeccd320d299cfcac962865a6bc74",
        )
        .unwrap();

        let sig: [i128; 64] = [
            5, 202, 31, 146, 81, 242, 246, 69, 43, 107, 249, 153, 198, 44, 14, 111, 191, 121, 137,
            166, 160, 103, 18, 181, 243, 233, 226, 95, 67, 16, 37, 128, 85, 76, 19, 253, 30, 77,
            192, 53, 138, 205, 69, 33, 236, 163, 83, 194, 84, 137, 184, 221, 176, 121, 179, 27, 63,
            70, 54, 16, 176, 250, 39, 239,
        ];
        let sig_as_scalars: Vec<FieldElement> = sig.into_iter().map(FieldElement::from).collect();

        let message: Vec<FieldElement> = vec![
            0_i128.into(),
            1_i128.into(),
            2_i128.into(),
            3_i128.into(),
            4_i128.into(),
            5_i128.into(),
            6_i128.into(),
            7_i128.into(),
            8_i128.into(),
            9_i128.into(),
        ];
        let mut witness_values = Vec::new();
        witness_values.extend(message);
        witness_values.push(pub_x);
        witness_values.push(pub_y);
        witness_values.extend(sig_as_scalars);
        witness_values.push(FieldElement::zero());

        let case_1 = WitnessResult {
            witness: witness_values.into(),
            public_inputs: Assignments::default(),
            result: true,
        };

        test_composer_with_pk_vk(constraint_system, vec![case_1]).await
    }

    #[test]
    async fn test_keccak256_constraint() -> Result<(), Error> {
        let input_value: u128 = 0xbd;
        let input_index = 1;

        // 0x5a502f9fca467b266d5b7833651937e805270ca3f3af1c0dd2462dca4b3b1abf
        let result_values: [u128; 32] = [
            0x5a, 0x50, 0x2f, 0x9f, 0xca, 0x46, 0x7b, 0x26, 0x6d, 0x5b, 0x78, 0x33, 0x65, 0x19,
            0x37, 0xe8, 0x05, 0x27, 0x0c, 0xa3, 0xf3, 0xaf, 0x1c, 0x0d, 0xd2, 0x46, 0x2d, 0xca,
            0x4b, 0x3b, 0x1a, 0xbf,
        ];
        let result_indices: Vec<i32> = (2i32..2 + result_values.len() as i32).collect();

        let keccak_constraint = Keccak256Constraint {
            inputs: vec![(input_index, 8)],
            result: result_indices.clone().try_into().unwrap(),
        };

        let mut constraints = Vec::new();
        for (value, index) in result_values.iter().zip(&result_indices) {
            let byte_constraint = Constraint {
                a: *index,
                b: *index,
                c: *index,
                qm: FieldElement::zero(),
                ql: FieldElement::one(),
                qr: FieldElement::zero(),
                qo: FieldElement::zero(),
                qc: -FieldElement::from(*value),
            };
            constraints.push(byte_constraint)
        }

        let constraint_system = ConstraintSystem::new()
            .var_num(100)
            .keccak256_constraints(vec![keccak_constraint])
            .constraints(constraints);

        let witness_values: Vec<_> = std::iter::once(input_value)
            .chain(result_values)
            .map(FieldElement::from)
            .collect();
        let case_1 = WitnessResult {
            witness: witness_values.into(),
            public_inputs: Assignments::default(),
            result: true,
        };

        test_composer_with_pk_vk(constraint_system, vec![case_1]).await
    }

    #[test]
    async fn test_ped_constraints() -> Result<(), Error> {
        let constraint = PedersenConstraint {
            inputs: vec![1, 2],
            result_x: 3,
            result_y: 4,
        };

        let x_constraint = Constraint {
            a: 3,
            b: 3,
            c: 3,
            qm: FieldElement::zero(),
            ql: FieldElement::one(),
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: -FieldElement::from_hex(
                "0x11831f49876c313f2a9ec6d8d521c7ce0b6311c852117e340bfe27fd1ac096ef",
            )
            .unwrap(),
        };
        let y_constraint = Constraint {
            a: 4,
            b: 4,
            c: 4,
            qm: FieldElement::zero(),
            ql: FieldElement::one(),
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: -FieldElement::from_hex(
                "0x0ecf9d98be4597a88c46a7e0fa8836b57a7dcb41ee30f8d8787b11cc259c83fa",
            )
            .unwrap(),
        };

        let constraint_system = ConstraintSystem::new()
            .var_num(100)
            .pedersen_constraints(vec![constraint])
            .constraints(vec![x_constraint, y_constraint]);

        let scalar_0 = FieldElement::from_hex("0x00").unwrap();
        let scalar_1 = FieldElement::from_hex("0x01").unwrap();
        let witness_values = vec![scalar_0, scalar_1];

        let case_1 = WitnessResult {
            witness: witness_values.into(),
            public_inputs: Assignments::default(),
            result: true,
        };

        test_composer_with_pk_vk(constraint_system, vec![case_1]).await
    }

    #[test]
    async fn test_memory_constraints() -> Result<(), Error> {
        let two_field = FieldElement::one() + FieldElement::one();
        let one = Constraint {
            a: 0,
            b: 0,
            c: 0,
            qm: FieldElement::zero(),
            ql: FieldElement::zero(),
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: FieldElement::one(),
        };

        let two_x_constraint = Constraint {
            a: 1,
            b: 0,
            c: 0,
            qm: FieldElement::zero(),
            ql: two_field,
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: FieldElement::zero(),
        };
        let x_1_constraint = Constraint {
            a: 1,
            b: 0,
            c: 0,
            qm: FieldElement::zero(),
            ql: FieldElement::one(),
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: FieldElement::one(),
        };

        let y_constraint = Constraint {
            a: 2,
            b: 0,
            c: 0,
            qm: FieldElement::zero(),
            ql: FieldElement::one(),
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: FieldElement::zero(),
        };
        let z_constraint = Constraint {
            a: 3,
            b: 0,
            c: 0,
            qm: FieldElement::zero(),
            ql: FieldElement::one(),
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: FieldElement::zero(),
        };
        let op1 = MemOpBarretenberg {
            index: two_x_constraint,
            value: y_constraint,
            is_store: 0,
        };
        let op2 = MemOpBarretenberg {
            index: x_1_constraint.clone(),
            value: z_constraint,
            is_store: 0,
        };
        let block_constraint = BlockConstraint {
            init: vec![one, x_1_constraint],
            trace: vec![op1, op2],
            is_ram: 0,
        };

        let result_constraint = Constraint {
            a: 2,
            b: 3,
            c: 0,
            qm: FieldElement::zero(),
            ql: FieldElement::one(),
            qr: FieldElement::one(),
            qo: FieldElement::zero(),
            qc: -(two_field),
        };
        let constraint_system = ConstraintSystem::new()
            .var_num(4)
            .block_constraints(vec![block_constraint])
            .constraints(vec![result_constraint]);

        let scalar_0 = FieldElement::zero();
        let scalar_1 = FieldElement::one();
        let witness_values = vec![scalar_0, scalar_1, scalar_1];

        let case_1 = WitnessResult {
            witness: witness_values.into(),
            public_inputs: Assignments::default(),
            result: true,
        };

        let bad_values = vec![scalar_0, scalar_1, scalar_1 + scalar_1];
        let case_2 = WitnessResult {
            witness: bad_values.into(),
            public_inputs: Assignments::default(),
            result: false,
        };

        test_composer_with_pk_vk(constraint_system, vec![case_1, case_2]).await
    }

    #[test]
    async fn test_logic_constraints() -> Result<(), Error> {
        let (constraint_system, case_1) = create_logic_constraint_circuit();

        test_composer_with_pk_vk(constraint_system, vec![case_1]).await
    }

    fn create_logic_constraint_circuit() -> (ConstraintSystem, WitnessResult) {
        /*
         * constraints produced by Noir program:
         * fn main(x : u32, y : pub u32) {
         * let z = x ^ y;
         *
         * constrain z != 10;
         * }
         */
        let range_a = RangeConstraint { a: 1, num_bits: 32 };
        let range_b = RangeConstraint { a: 2, num_bits: 32 };

        let logic_constraint = LogicConstraint {
            a: 1,
            b: 2,
            result: 3,
            num_bits: 32,
            is_xor_gate: true,
        };

        let expr_a = Constraint {
            a: 3,
            b: 4,
            c: 0,
            qm: FieldElement::zero(),
            ql: FieldElement::one(),
            qr: -FieldElement::one(),
            qo: FieldElement::zero(),
            qc: -FieldElement::from_hex("0x0a").unwrap(),
        };
        let expr_b = Constraint {
            a: 4,
            b: 5,
            c: 6,
            qm: FieldElement::one(),
            ql: FieldElement::zero(),
            qr: FieldElement::zero(),
            qo: -FieldElement::one(),
            qc: FieldElement::zero(),
        };
        let expr_c = Constraint {
            a: 4,
            b: 6,
            c: 4,
            qm: FieldElement::one(),
            ql: FieldElement::zero(),
            qr: FieldElement::zero(),
            qo: -FieldElement::one(),
            qc: FieldElement::zero(),
        };
        let expr_d = Constraint {
            a: 6,
            b: 0,
            c: 0,
            qm: FieldElement::zero(),
            ql: -FieldElement::one(),
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: FieldElement::one(),
        };

        let constraint_system = ConstraintSystem::new()
            .var_num(7)
            .public_inputs(vec![2])
            .range_constraints(vec![range_a, range_b])
            .logic_constraints(vec![logic_constraint])
            .constraints(vec![expr_a, expr_b, expr_c, expr_d]);

        let scalar_5 = FieldElement::from_hex("0x05").unwrap();
        let scalar_10 = FieldElement::from_hex("0x0a").unwrap();
        let scalar_15 = FieldElement::from_hex("0x0f").unwrap();
        let scalar_5_inverse = scalar_5.inverse();
        let witness_values = vec![
            scalar_5,
            scalar_10,
            scalar_15,
            scalar_5,
            scalar_5_inverse,
            FieldElement::one(),
        ];
        let case_1 = WitnessResult {
            witness: witness_values.into(),
            public_inputs: vec![scalar_10].into(),
            result: true,
        };

        (constraint_system, case_1)
    }


    #[derive(Debug, Clone)]
    struct RecursiveCircuitData {
        key_witnesses: Vec<FieldElement>,
        vk_hash_value: FieldElement,
        proof_witnesses: Vec<FieldElement>,
        num_public_inputs: i32,
    }

    async fn fetch_recursive_circuit_data(
        constraint_system: ConstraintSystem,
        witness_res: WitnessResult,
    ) -> Result<RecursiveCircuitData, Error> {
        let bb = Barretenberg::new();
        let crs = bb.get_crs(&constraint_system).await?;

        let proving_key = bb.compute_proving_key(&constraint_system)?;
        let verification_key = bb.compute_verification_key(&crs, &proving_key)?;

        let proof = bb.create_proof_with_pk(
            &crs,
            &constraint_system,
            witness_res.witness,
            &proving_key,
            true,
        )?;

        let verified = bb.verify_with_vk(
            &crs,
            &constraint_system,
            &proof,
            witness_res.public_inputs.clone(),
            &verification_key,
            true,
        )?;
        assert_eq!(verified, witness_res.result);

        // NOTE: We need to get the field bytes in non-montgomery form to read them in correctly using the acir_field API
        let proof_fields_as_bytes = bb.proof_as_fields(&proof, witness_res.public_inputs)?;
        let proof_fields_bytes_slices = proof_fields_as_bytes.chunks(32).collect::<Vec<_>>();
        let mut proof_witness_values: Vec<FieldElement> = Vec::new();
        for proof_field_bytes in proof_fields_bytes_slices {
            proof_witness_values.push(FieldElement::from_be_bytes_reduce(proof_field_bytes));
        }

        let (vk_fields_as_bytes, vk_hash_as_bytes) =
            bb.verification_key_as_fields(&crs, &verification_key)?;

        let vk_fields_as_bytes_slices = vk_fields_as_bytes.chunks(32).collect::<Vec<_>>();
        let mut vk_witness_values: Vec<FieldElement> = Vec::new();
        for vk_field_bytes in vk_fields_as_bytes_slices {
            vk_witness_values.push(FieldElement::from_be_bytes_reduce(vk_field_bytes));
        }

        let vk_hash_value = FieldElement::from_be_bytes_reduce(&vk_hash_as_bytes);
        vk_witness_values.push(vk_hash_value);
        Ok(RecursiveCircuitData {
            key_witnesses: vk_witness_values,
            vk_hash_value,
            proof_witnesses: proof_witness_values,
            num_public_inputs: constraint_system.public_inputs_size() as i32,
        })
    }

    async fn fetch_inner_circuit_data() -> Result<RecursiveCircuitData, Error> {
        let (inner_constraint_system, inner_witness_res) = create_logic_constraint_circuit();

        fetch_recursive_circuit_data(inner_constraint_system, inner_witness_res).await
    }

    #[test]
    async fn test_recursion_constraint() -> Result<(), Error> {
        let RecursiveCircuitData {
            key_witnesses,
            proof_witnesses,
            vk_hash_value,
            ..
        } = fetch_inner_circuit_data().await?;

        let proof_size = proof_witnesses.len() as i32;
        let mut proof_indices = Vec::new();
        for i in 0..proof_size {
            proof_indices.push(i + 19);
        }

        let mut key_indices = Vec::new();
        for i in 0..key_witnesses.len() as i32 {
            key_indices.push(i + 19 + proof_size);
        }

        let mut output_vars = [0_i32; 16];
        for i in 0..16 {
            output_vars[i] = i as i32 + 3;
        }

        // let nested_vars = key_indices[6..22].try_into().unwrap();

        let recurison_constraint = RecursionConstraint {
            key: key_indices,
            proof: proof_indices,
            public_inputs: vec![1],
            key_hash: 2,
            input_aggregation_object: [0; 16], // Set all indices to `0` when there is no `input_aggregation_object`
            output_aggregation_object: output_vars,
            nested_aggregation_object: [0; 16],
        };

        // Add a constraint that fixes the vk hash to be the expected value
        let vk_equality_constraint = Constraint {
            a: recurison_constraint.key_hash,
            b: 0,
            c: 0,
            qm: FieldElement::zero(),
            ql: FieldElement::one(),
            qr: FieldElement::zero(),
            qo: FieldElement::zero(),
            qc: -vk_hash_value,
        };
        let mut witness: Vec<FieldElement> = Vec::new();
        witness.extend(vec![FieldElement::zero(); 18]);

        for witness_val in proof_witnesses.clone() {
            witness.push(witness_val);
        }

        for witness_val in key_witnesses.clone() {
            witness.push(witness_val);
        }

        let public_inputs = output_vars.to_vec().into_iter().map(|v| v as u32).collect();

        let outer_constraint_system = ConstraintSystem::new()
            .var_num(witness.len() as u32 + 1)
            .public_inputs(public_inputs)
            .recursion_constraints(vec![recurison_constraint])
            .constraints(vec![vk_equality_constraint]);

        let bb = Barretenberg::new();
        let output_agg_to_insert_into_witness = bb.verify_proof_(
            key_witnesses[..(key_witnesses.len()-1)].to_vec(),
            proof_witnesses.clone(),
            1,
            [FieldElement::zero(); 16],
        );

        let outer_witness_res = WitnessResult {
            witness: witness.into(),
            public_inputs: output_agg_to_insert_into_witness.to_vec().into(),
            result: true,
        };

        test_composer_with_pk_vk(outer_constraint_system, vec![outer_witness_res]).await
    }

    fn create_outer_circuit(
        inner_circuits: Vec<RecursiveCircuitData>,
    ) -> (ConstraintSystem, WitnessResult) {
        let mut recursion_constraints = Vec::new();

        let mut witness_offset: i32 = 1;
        let mut output_aggregation_object = [0 as i32; 16];
        let mut witness: Vec<FieldElement> = Vec::new();

        let bb = Barretenberg::new();

        let mut output_agg_to_insert_into_witness = [FieldElement::zero(); 16];

        for i in 0..inner_circuits.len() {
            let has_input_aggregation_object = i > 0;

            let inner_circuit = inner_circuits[i].clone();
            let proof_witnesses = inner_circuit.proof_witnesses;
            let key_witnesses = inner_circuit.key_witnesses;

            let has_nested_proof: bool = key_witnesses[5] == FieldElement::one();

            let num_inner_public_inputs = inner_circuit.num_public_inputs as i32;

            let key_hash_start_idx = witness_offset;
            let public_input_start_idx = key_hash_start_idx + 1;
            let output_aggregation_object_start_idx = public_input_start_idx
                + num_inner_public_inputs
                + if has_nested_proof { 16 } else { 0 };
            let proof_indices_start_idx = output_aggregation_object_start_idx + 16;
            let key_indices_start_idx = proof_indices_start_idx + proof_witnesses.len() as i32;

            let mut proof_indices = Vec::new();
            let mut key_indices = Vec::new();
            let mut inner_public_inputs = Vec::new();
            let mut input_aggregation_object = [0; 16];
            let mut nested_aggregation_object = [0; 16];

            if has_input_aggregation_object {
                input_aggregation_object = output_aggregation_object;
            }
            for i in 0..16 {
                output_aggregation_object[i] = i as i32 + output_aggregation_object_start_idx;
            }
            if has_nested_proof {
                for i in 6..22 {
                    let key_witness_as_int = key_witnesses[i].to_u128() as i32;
                    nested_aggregation_object[i - 6] = key_witness_as_int;
                }
            }

            let proof_size = proof_witnesses.len() as i32;
            for i in 0..proof_size {
                proof_indices.push(i + proof_indices_start_idx);
            }
            for i in 0..key_witnesses.len() as i32 {
                key_indices.push(i + key_indices_start_idx);
            }

            for i in 0..num_inner_public_inputs as i32 {
                inner_public_inputs.push(i + public_input_start_idx);
            }

            let recursion_constraint = RecursionConstraint {
                key: key_indices,
                proof: proof_indices,
                public_inputs: inner_public_inputs,
                key_hash: key_hash_start_idx,
                input_aggregation_object,
                output_aggregation_object,
                nested_aggregation_object,
            };
            recursion_constraints.push(recursion_constraint);

            for _ in 0..(proof_indices_start_idx - witness_offset) {
                witness.push(FieldElement::zero());
            }

            output_agg_to_insert_into_witness = bb.verify_proof_(
                key_witnesses.clone(),
                proof_witnesses.clone(),
                num_inner_public_inputs as u32,
                output_agg_to_insert_into_witness,
            );

            for witness_val in proof_witnesses {
                witness.push(witness_val);
            }
            witness_offset = key_indices_start_idx + key_witnesses.len() as i32;

            for witness_val in key_witnesses {
                witness.push(witness_val);
            }
        }

        let public_inputs = output_aggregation_object
            .to_vec()
            .into_iter()
            .map(|v| v as u32)
            .collect();
        let constraint_system = ConstraintSystem::new()
            .var_num((witness.len() + 1) as u32)
            .public_inputs(public_inputs)
            .recursion_constraints(recursion_constraints);

        let witness_res = WitnessResult {
            witness: witness.into(),
            public_inputs: output_agg_to_insert_into_witness.to_vec().into(),
            result: true,
        };
        (constraint_system, witness_res)
    }

    #[test]
    async fn test_double_recursion() -> Result<(), Error> {
        let mut inner_circuits = Vec::new();
        let a = fetch_inner_circuit_data().await?;
        inner_circuits.push(a);

        let b = fetch_inner_circuit_data().await?;
        inner_circuits.push(b);

        let c = create_outer_circuit(inner_circuits);
        test_composer_with_pk_vk(c.0, vec![c.1]).await
    }

    #[test]
    async fn test_full_recursive_composition() -> Result<(), Error> {
        let mut layer_1_circuits = Vec::new();
        let a_circuit = fetch_inner_circuit_data().await?;
        layer_1_circuits.push(a_circuit);

        let mut layer_2_circuits = Vec::new();
        let a2_circuit = fetch_inner_circuit_data().await?;
        layer_2_circuits.push(a2_circuit);

        let b_cs_and_witness = create_outer_circuit(layer_1_circuits);
        let b_circuit =
            fetch_recursive_circuit_data(b_cs_and_witness.0, b_cs_and_witness.1).await?;
        layer_2_circuits.push(b_circuit);

        let c_cs_and_witness = create_outer_circuit(layer_2_circuits);
        test_composer_with_pk_vk(c_cs_and_witness.0, vec![c_cs_and_witness.1]).await
    }

    #[derive(Clone, Debug)]
    struct WitnessResult {
        witness: Assignments,
        public_inputs: Assignments,
        result: bool,
    }

    async fn test_composer_with_pk_vk(
        constraint_system: ConstraintSystem,
        test_cases: Vec<WitnessResult>,
    ) -> Result<(), Error> {
        let bb = Barretenberg::new();
        let crs = bb.get_crs(&constraint_system).await?;

        let proving_key = bb.compute_proving_key(&constraint_system)?;
        let verification_key = bb.compute_verification_key(&crs, &proving_key)?;

        for test_case in test_cases.into_iter() {
            let proof =
                bb.create_proof_with_pk(&crs, &constraint_system, test_case.witness, &proving_key, false)?;
            let verified = bb.verify_with_vk(
                &crs,
                &constraint_system,
                &proof,
                test_case.public_inputs,
                &verification_key,
                false,
            )?;
            assert_eq!(verified, test_case.result);
        }
        Ok(())
    }
}
