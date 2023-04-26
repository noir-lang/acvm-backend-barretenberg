use crate::barretenberg_structures::{Assignments, ConstraintSystem};
use crate::crs::{CRS, G2};
use crate::{Barretenberg, FIELD_BYTES};

const NUM_RESERVED_GATES: u32 = 4; // this must be >= num_roots_cut_out_of_vanishing_polynomial (found under prover settings in barretenberg)

pub(crate) trait Composer {
    fn get_circuit_size(&self, constraint_system: &ConstraintSystem) -> u32;
    fn get_exact_circuit_size(&self, constraint_system: &ConstraintSystem) -> u32;

    fn compute_proving_key(&self, constraint_system: &ConstraintSystem) -> Vec<u8>;
    fn compute_verification_key(
        &self,
        constraint_system: &ConstraintSystem,
        proving_key: &[u8],
    ) -> Vec<u8>;

    fn create_proof_with_pk(
        &self,
        constraint_system: &ConstraintSystem,
        witness: Assignments,
        proving_key: &[u8],
    ) -> Vec<u8>;

    fn verify_with_vk(
        &self,
        constraint_system: &ConstraintSystem,
        // XXX: Important: This assumes that the proof does not have the public inputs pre-pended to it
        // This is not the case, if you take the proof directly from Barretenberg
        proof: &[u8],
        public_inputs: Assignments,
        verification_key: &[u8],
    ) -> bool;
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
    fn get_circuit_size(&self, constraint_system: &ConstraintSystem) -> u32 {
        let cs_buf = constraint_system.to_bytes();

        let circuit_size;
        unsafe {
            circuit_size =
                barretenberg_sys::composer::get_total_circuit_size(cs_buf.as_slice().as_ptr());
        }

        pow2ceil(circuit_size + NUM_RESERVED_GATES)
    }

    fn get_exact_circuit_size(&self, constraint_system: &ConstraintSystem) -> u32 {
        let cs_buf = constraint_system.to_bytes();

        unsafe { barretenberg_sys::composer::get_exact_circuit_size(cs_buf.as_slice().as_ptr()) }
    }

    fn compute_proving_key(&self, constraint_system: &ConstraintSystem) -> Vec<u8> {
        let cs_buf = constraint_system.to_bytes();

        let mut pk_addr: *mut u8 = std::ptr::null_mut();
        let pk_ptr = &mut pk_addr as *mut *mut u8;

        let pk_size;
        unsafe {
            pk_size = barretenberg_sys::composer::init_proving_key(&cs_buf, pk_ptr);
        }

        std::mem::forget(cs_buf);

        let result;
        unsafe {
            result = Vec::from_raw_parts(pk_addr, pk_size, pk_size);
        }
        result
    }

    fn compute_verification_key(
        &self,
        constraint_system: &ConstraintSystem,
        proving_key: &[u8],
    ) -> Vec<u8> {
        let circuit_size = self.get_circuit_size(constraint_system);
        let CRS {
            g1_data, g2_data, ..
        } = CRS::new(circuit_size as usize);
        let pippenger_ptr = self.get_pippenger(&g1_data).pointer();

        let mut vk_addr: *mut u8 = std::ptr::null_mut();
        let vk_ptr = &mut vk_addr as *mut *mut u8;
        let proving_key = proving_key.to_vec();

        let vk_size;
        unsafe {
            vk_size = barretenberg_sys::composer::init_verification_key(
                pippenger_ptr,
                &g2_data,
                &proving_key,
                vk_ptr,
            )
        }

        std::mem::forget(g2_data);
        std::mem::forget(proving_key);

        let result;
        unsafe {
            result = Vec::from_raw_parts(vk_addr, vk_size, vk_size);
        }
        result.to_vec()
    }

    fn create_proof_with_pk(
        &self,
        constraint_system: &ConstraintSystem,
        witness: Assignments,
        proving_key: &[u8],
    ) -> Vec<u8> {
        let circuit_size = self.get_circuit_size(constraint_system);
        let CRS {
            g1_data, g2_data, ..
        } = CRS::new(circuit_size as usize);
        let pippenger_ptr = self.get_pippenger(&g1_data).pointer();
        let cs_buf: Vec<u8> = constraint_system.to_bytes();
        let witness_buf = witness.to_bytes();

        let mut proof_addr: *mut u8 = std::ptr::null_mut();
        let p_proof = &mut proof_addr as *mut *mut u8;
        let proving_key = proving_key.to_vec();

        let proof_size;
        unsafe {
            proof_size = barretenberg_sys::composer::create_proof_with_pk(
                pippenger_ptr,
                &g2_data,
                &proving_key,
                &cs_buf,
                &witness_buf,
                p_proof,
            );
        }

        std::mem::forget(g2_data);
        std::mem::forget(proving_key);
        std::mem::forget(cs_buf);
        std::mem::forget(witness_buf);

        let result;
        unsafe {
            result = Vec::from_raw_parts(proof_addr, proof_size, proof_size);
        }

        // Barretenberg returns proofs which are prepended with the public inputs.
        // This behavior is nonstandard so we strip the public inputs from the proof.
        remove_public_inputs(constraint_system.public_inputs_size(), &result)
    }

    fn verify_with_vk(
        &self,
        constraint_system: &ConstraintSystem,
        // XXX: Important: This assumes that the proof does not have the public inputs pre-pended to it
        // This is not the case, if you take the proof directly from Barretenberg
        proof: &[u8],
        public_inputs: Assignments,
        verification_key: &[u8],
    ) -> bool {
        let g2_data = G2::new().data;

        // Barretenberg expects public inputs to be prepended onto the proof
        let proof = prepend_public_inputs(proof.to_vec(), public_inputs);
        let cs_buf = constraint_system.to_bytes();

        let verification_key = verification_key.to_vec();

        let verified;
        unsafe {
            verified = barretenberg_sys::composer::verify_with_vk(
                &g2_data,
                &verification_key,
                &cs_buf,
                &proof,
            );
        }
        verified
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
    fn get_circuit_size(&self, constraint_system: &ConstraintSystem) -> u32 {
        let cs_buf = constraint_system.to_bytes();
        let cs_ptr = self.allocate(&cs_buf);

        let circuit_size = self
            .call("acir_proofs_get_total_circuit_size", &cs_ptr)
            .into_i32();
        let circuit_size =
            u32::try_from(circuit_size).expect("circuit cannot have negative number of gates");

        self.free(cs_ptr);

        pow2ceil(circuit_size + NUM_RESERVED_GATES)
    }

    fn get_exact_circuit_size(&self, constraint_system: &ConstraintSystem) -> u32 {
        let cs_buf = constraint_system.to_bytes();
        let cs_ptr = self.allocate(&cs_buf);

        let circuit_size = self
            .call("acir_proofs_get_exact_circuit_size", &cs_ptr)
            .into_i32();
        let circuit_size =
            u32::try_from(circuit_size).expect("circuit cannot have negative number of gates");

        self.free(cs_ptr);

        circuit_size
    }

    fn compute_proving_key(&self, constraint_system: &ConstraintSystem) -> Vec<u8> {
        use super::wasm::POINTER_BYTES;
        use wasmer::Value;

        let cs_buf = constraint_system.to_bytes();
        let cs_ptr = self.allocate(&cs_buf);

        // The proving key is not actually written to this pointer.
        // `pk_ptr_ptr` is a pointer to a pointer which holds the proving key.
        let pk_ptr_ptr: usize = 0;

        let pk_size = self
            .call_multiple(
                "acir_proofs_init_proving_key",
                vec![&cs_ptr, &Value::I32(pk_ptr_ptr as i32)],
            )
            .value();
        let pk_size: usize = pk_size.unwrap_i32() as usize;

        // We then need to read the pointer at `pk_ptr_ptr` to get the key's location
        // and then slice memory again at `pk_ptr` to get the proving key.
        let pk_ptr = self.slice_memory(pk_ptr_ptr, POINTER_BYTES);
        let pk_ptr: usize =
            u32::from_le_bytes(pk_ptr[0..POINTER_BYTES].try_into().unwrap()) as usize;

        self.slice_memory(pk_ptr, pk_size)
    }

    fn compute_verification_key(
        &self,
        constraint_system: &ConstraintSystem,
        proving_key: &[u8],
    ) -> Vec<u8> {
        use super::wasm::POINTER_BYTES;
        use wasmer::Value;

        let circuit_size = self.get_circuit_size(constraint_system);
        let CRS {
            g1_data, g2_data, ..
        } = CRS::new(circuit_size as usize);
        let pippenger_ptr = self.get_pippenger(&g1_data).pointer();

        let g2_ptr = self.allocate(&g2_data);
        let pk_ptr = self.allocate(proving_key);

        // The verification key is not actually written to this pointer.
        // `vk_ptr_ptr` is a pointer to a pointer which holds the verification key.
        let vk_ptr_ptr: usize = 0;

        let vk_size = self
            .call_multiple(
                "acir_proofs_init_verification_key",
                vec![
                    &pippenger_ptr,
                    &g2_ptr,
                    &pk_ptr,
                    &Value::I32(vk_ptr_ptr as i32),
                ],
            )
            .value();
        let vk_size: usize = vk_size.unwrap_i32() as usize;

        // We then need to read the pointer at `vk_ptr_ptr` to get the key's location
        // and then slice memory again at `vk_ptr` to get the verification key.
        let vk_ptr = self.slice_memory(vk_ptr_ptr, POINTER_BYTES);
        let vk_ptr: usize =
            u32::from_le_bytes(vk_ptr[0..POINTER_BYTES].try_into().unwrap()) as usize;

        self.slice_memory(vk_ptr, vk_size)
    }

    fn create_proof_with_pk(
        &self,
        constraint_system: &ConstraintSystem,
        witness: Assignments,
        proving_key: &[u8],
    ) -> Vec<u8> {
        use super::wasm::POINTER_BYTES;
        use wasmer::Value;

        let circuit_size = self.get_circuit_size(constraint_system);
        let CRS {
            g1_data, g2_data, ..
        } = CRS::new(circuit_size as usize);
        let pippenger_ptr = self.get_pippenger(&g1_data).pointer();
        let cs_buf: Vec<u8> = constraint_system.to_bytes();
        let witness_buf = witness.to_bytes();

        let cs_ptr = self.allocate(&cs_buf);
        let witness_ptr = self.allocate(&witness_buf);
        let g2_ptr = self.allocate(&g2_data);
        let pk_ptr = self.allocate(proving_key);

        // The proof data is not actually written to this pointer.
        // `proof_ptr_ptr` is a pointer to a pointer which holds the proof data.
        let proof_ptr_ptr: usize = 0;

        let proof_size = self
            .call_multiple(
                "acir_proofs_new_proof",
                vec![
                    &pippenger_ptr,
                    &g2_ptr,
                    &pk_ptr,
                    &cs_ptr,
                    &witness_ptr,
                    &Value::I32(0),
                ],
            )
            .value();
        let proof_size: usize = proof_size.unwrap_i32() as usize;

        // We then need to read the pointer at `proof_ptr_ptr` to get the proof's location
        // and then slice memory again at `proof_ptr` to get the proof data.
        let proof_ptr = self.slice_memory(proof_ptr_ptr, POINTER_BYTES);
        let proof_ptr: usize =
            u32::from_le_bytes(proof_ptr[0..POINTER_BYTES].try_into().unwrap()) as usize;

        let result = self.slice_memory(proof_ptr, proof_size);

        // Barretenberg returns proofs which are prepended with the public inputs.
        // This behavior is nonstandard so we strip the public inputs from the proof.
        remove_public_inputs(constraint_system.public_inputs_size(), &result)
    }

    fn verify_with_vk(
        &self,
        constraint_system: &ConstraintSystem,
        // XXX: Important: This assumes that the proof does not have the public inputs pre-pended to it
        // This is not the case, if you take the proof directly from Barretenberg
        proof: &[u8],
        public_inputs: Assignments,
        verification_key: &[u8],
    ) -> bool {
        use wasmer::Value;
        let g2_data = G2::new().data;

        // Barretenberg expects public inputs to be prepended onto the proof
        let proof = prepend_public_inputs(proof.to_vec(), public_inputs);
        let cs_buf = constraint_system.to_bytes();

        let cs_ptr = self.allocate(&cs_buf);
        let proof_ptr = self.allocate(&proof);
        let g2_ptr = self.allocate(&g2_data);
        let vk_ptr = self.allocate(verification_key);

        let verified = self
            .call_multiple(
                "acir_proofs_verify_proof",
                vec![
                    &g2_ptr,
                    &vk_ptr,
                    &cs_ptr,
                    &proof_ptr,
                    &Value::I32(proof.len() as i32),
                ],
            )
            .value();

        self.free(proof_ptr);

        match verified.unwrap_i32() {
            0 => false,
            1 => true,
            _ => panic!("Expected a 1 or a zero for the verification result"),
        }
    }
}

fn pow2ceil(v: u32) -> u32 {
    if v > (u32::MAX >> 1) {
        panic!("pow2ceil overflow");
    }

    let mut p = 1;
    while p < v {
        p <<= 1;
    }
    p
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

    use super::*;
    use crate::barretenberg_structures::{
        Constraint, LogicConstraint, PedersenConstraint, RangeConstraint, SchnorrConstraint,
    };

    #[test]
    fn test_no_constraints_no_pub_inputs() {
        let constraint_system = ConstraintSystem::new();

        let case_1 = WitnessResult {
            witness: vec![].into(),
            public_inputs: Assignments::default(),
            result: true,
        };
        let test_cases = vec![case_1];

        test_composer_with_pk_vk(constraint_system, test_cases);
    }

    #[test]
    fn test_a_single_constraint_no_pub_inputs() {
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

        test_composer_with_pk_vk(constraint_system, test_cases);
    }
    #[test]
    fn test_a_single_constraint_with_pub_inputs() {
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

        test_composer_with_pk_vk(constraint_system, test_cases);
    }

    #[test]
    fn test_multiple_constraints() {
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

        test_composer_with_pk_vk(constraint_system, vec![case_1, case_2]);
    }

    #[test]
    fn test_schnorr_constraints() {
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

        test_composer_with_pk_vk(constraint_system, vec![case_1]);
    }

    #[test]
    fn test_ped_constraints() {
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

        test_composer_with_pk_vk(constraint_system, vec![case_1]);
    }

    #[test]
    fn test_logic_constraints() {
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

        test_composer_with_pk_vk(constraint_system, vec![case_1]);
    }

    #[derive(Clone, Debug)]
    struct WitnessResult {
        witness: Assignments,
        public_inputs: Assignments,
        result: bool,
    }

    fn test_composer_with_pk_vk(
        constraint_system: ConstraintSystem,
        test_cases: Vec<WitnessResult>,
    ) {
        let bb = Barretenberg::new();

        let proving_key = bb.compute_proving_key(&constraint_system);
        let verification_key = bb.compute_verification_key(&constraint_system, &proving_key);

        for test_case in test_cases.into_iter() {
            let proof =
                bb.create_proof_with_pk(&constraint_system, test_case.witness, &proving_key);
            let verified = bb.verify_with_vk(
                &constraint_system,
                &proof,
                test_case.public_inputs,
                &verification_key,
            );
            assert_eq!(verified, test_case.result);
        }
    }
}
