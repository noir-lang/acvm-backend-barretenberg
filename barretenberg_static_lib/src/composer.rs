use super::crs::CRS;
use super::pippenger::Pippenger;
use common::{barretenberg_structures::*, proof};

pub struct StandardComposer {
    pippenger: Pippenger,
    crs: CRS,
    constraint_system: ConstraintSystem,
}

impl StandardComposer {
    pub fn new(constraint_system: ConstraintSystem) -> StandardComposer {
        let circuit_size = StandardComposer::get_circuit_size(&constraint_system);

        let crs = CRS::new(circuit_size as usize + 1);

        let pippenger = Pippenger::new(&crs.g1_data);

        StandardComposer {
            pippenger,
            crs,
            constraint_system,
        }
    }
}

impl StandardComposer {
    const NUM_RESERVED_GATES: u32 = 4; // this must be >= num_roots_cut_out_of_vanishing_polynomial (found under prover settings in barretenberg)

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
    pub fn get_circuit_size(constraint_system: &ConstraintSystem) -> u32 {
        let num_gates;
        unsafe {
            num_gates = barretenberg_sys::composer::get_total_circuit_size(
                constraint_system.to_bytes().as_slice().as_ptr(),
            );
        }
        pow2ceil(num_gates + StandardComposer::NUM_RESERVED_GATES)
    }

    pub fn get_exact_circuit_size(constraint_system: &ConstraintSystem) -> u32 {
        unsafe {
            barretenberg_sys::composer::get_exact_circuit_size(
                constraint_system.to_bytes().as_slice().as_ptr(),
            )
        }
    }

    pub fn compute_proving_key(&self) -> Vec<u8> {
        let cs_buf = self.constraint_system.to_bytes();
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

    pub fn compute_verification_key(&self, proving_key: &[u8]) -> Vec<u8> {
        let mut vk_addr: *mut u8 = std::ptr::null_mut();
        let vk_ptr = &mut vk_addr as *mut *mut u8;
        let g2_clone = self.crs.g2_data.clone();
        let pippenger_ptr = self.pippenger.pointer();
        let proving_key = proving_key.to_vec();

        let vk_size;
        unsafe {
            vk_size = barretenberg_sys::composer::init_verification_key(
                pippenger_ptr,
                &g2_clone,
                &proving_key,
                vk_ptr,
            )
        }

        std::mem::forget(g2_clone);
        std::mem::forget(proving_key);

        let result;
        unsafe {
            result = Vec::from_raw_parts(vk_addr, vk_size, vk_size);
        }
        result.to_vec()
    }

    pub fn create_proof_with_pk(
        &mut self,
        witness: WitnessAssignments,
        proving_key: &[u8],
    ) -> Vec<u8> {
        let cs_buf = self.constraint_system.to_bytes();
        let mut proof_addr: *mut u8 = std::ptr::null_mut();
        let p_proof = &mut proof_addr as *mut *mut u8;
        let g2_clone = self.crs.g2_data.clone();
        let witness_buf = witness.to_bytes();
        let proof_size;
        let proving_key = proving_key.to_vec();
        unsafe {
            proof_size = barretenberg_sys::composer::create_proof_with_pk(
                self.pippenger.pointer(),
                &g2_clone,
                &proving_key,
                &cs_buf,
                &witness_buf,
                p_proof,
            );
        }

        std::mem::forget(g2_clone);
        std::mem::forget(proving_key);
        std::mem::forget(cs_buf);
        std::mem::forget(witness_buf);

        let result;
        unsafe {
            result = Vec::from_raw_parts(proof_addr, proof_size, proof_size);
        }
        proof::remove_public_inputs(self.constraint_system.public_inputs_size(), &result)
    }

    pub fn verify_with_vk(
        &mut self,
        // XXX: Important: This assumes that the proof does not have the public inputs pre-pended to it
        // This is not the case, if you take the proof directly from Barretenberg
        proof: &[u8],
        public_inputs: Assignments,
        verification_key: &[u8],
    ) -> bool {
        // Prepend the public inputs to the proof.
        // This is how Barretenberg expects it to be.
        // This is non-standard however, so this Rust wrapper will strip the public inputs
        // from proofs created by Barretenberg. Then in Verify we prepend them again.

        let proof = proof::prepend_public_inputs(proof.to_vec(), public_inputs);

        let cs_buf = self.constraint_system.to_bytes();
        let verification_key = verification_key.to_vec();

        let verified;
        unsafe {
            verified = barretenberg_sys::composer::verify_with_vk(
                &self.crs.g2_data,
                &verification_key,
                &cs_buf,
                &proof,
            );
        }
        verified
    }
}

fn pow2ceil(v: u32) -> u32 {
    v.next_power_of_two()
}

#[cfg(test)]
mod test {

    use super::*;
    use common::barretenberg_structures::{Constraint, PedersenConstraint, Scalar};
    use rusty_fork::rusty_fork_test;

    rusty_fork_test! {
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
    }
    rusty_fork_test! {
        #[test]
        fn test_a_single_constraint_no_pub_inputs() {
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
                .constraints(vec![constraint]);

            let case_1 = WitnessResult {
                witness: vec![(-1_i128).into(), 2_i128.into(), 1_i128.into()].into(),
                public_inputs: Assignments::default(),
                result: true,
            };
            let case_2 = WitnessResult {
                witness: vec![Scalar::zero(), Scalar::zero(), Scalar::zero()].into(),
                public_inputs: Assignments::default(),
                result: true,
            };
            let case_3 = WitnessResult {
                witness: vec![10_i128.into(), (-3_i128).into(), 7_i128.into()].into(),
                public_inputs: Assignments::default(),
                result: true,
            };
            let case_4 = WitnessResult {
                witness: vec![Scalar::zero(), Scalar::zero(), Scalar::one()].into(),
                public_inputs: Assignments::default(),
                result: false,
            };
            let case_5 = WitnessResult {
                witness: vec![Scalar::one(), 2_i128.into(), 6_i128.into()].into(),
                public_inputs: Assignments::default(),
                result: false,
            };
            let test_cases = vec![case_1, case_2, case_3, case_4, case_5];

            test_composer_with_pk_vk(constraint_system, test_cases);
        }
    }
    rusty_fork_test! {
        #[test]
        fn test_a_single_constraint_with_pub_inputs() {
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

            // This fails because the constraint system requires public inputs,
            // but none are supplied in public_inputs. So the verifier will not
            // supply anything.
            let _case_1 = WitnessResult {
                witness: vec![(-1_i128).into(), 2_i128.into(), 1_i128.into()].into(),
                public_inputs: Assignments::default(),
                result: false,
            };
            let case_2 = WitnessResult {
                witness: vec![Scalar::zero(), Scalar::zero(), Scalar::zero()].into(),
                public_inputs: vec![Scalar::zero(), Scalar::zero()].into(),
                result: true,
            };

            let case_3 = WitnessResult {
                witness: vec![Scalar::one(), 2_i128.into(), 6_i128.into()].into(),
                public_inputs: vec![Scalar::one(), 3_i128.into()].into(),
                result: false,
            };

            // Not enough public inputs
            let _case_4 = WitnessResult {
                witness: vec![Scalar::one(), Scalar::from(2_i128), Scalar::from(6_i128)].into(),
                public_inputs: vec![Scalar::one()].into(),
                result: false,
            };

            let case_5 = WitnessResult {
                witness: vec![Scalar::one(), 2_i128.into(), 3_i128.into()].into(),
                public_inputs: vec![Scalar::one(), 2_i128.into()].into(),
                result: true,
            };

            let case_6 = WitnessResult {
                witness: vec![Scalar::one(), 2_i128.into(), 3_i128.into()].into(),
                public_inputs: vec![Scalar::one(), 3_i128.into()].into(),
                result: false,
            };
            let test_cases = vec![
                /*case_1,*/ case_2, case_3, /*case_4,*/ case_5, case_6,
            ];

            test_composer_with_pk_vk(constraint_system, test_cases);
        }
    }
    rusty_fork_test! {
        #[test]
        fn test_multiple_constraints() {
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
            let constraint2 = Constraint {
                a: 2,
                b: 3,
                c: 4,
                qm: Scalar::one(),
                ql: Scalar::zero(),
                qr: Scalar::zero(),
                qo: -Scalar::one(),
                qc: Scalar::one(),
            };

            let constraint_system = ConstraintSystem::new()
                .var_num(5)
                .public_inputs(vec![1])
                .constraints(vec![constraint, constraint2]);

            let case_1 = WitnessResult {
                witness: vec![1_i128.into(), 1_i128.into(), 2_i128.into(), 3_i128.into()].into(),
                public_inputs: vec![Scalar::one()].into(),
                result: true,
            };
            let case_2 = WitnessResult {
                witness: vec![1_i128.into(), 1_i128.into(), 2_i128.into(), 13_i128.into()].into(),
                public_inputs: vec![Scalar::one()].into(),
                result: false,
            };

            test_composer_with_pk_vk(constraint_system, vec![case_1, case_2]);
        }
    }
    rusty_fork_test! {
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
            qm: Scalar::zero(),
            ql: Scalar::zero(),
            qr: Scalar::zero(),
            qo: Scalar::one(),
            qc: -Scalar::one(),
        };

        let constraint_system = ConstraintSystem::new()
            .var_num(80)
            .schnorr_constraints(vec![constraint])
            .constraints(vec![arith_constraint]);

        let pub_x =
            Scalar::from_hex("0x17cbd3ed3151ccfd170efe1d54280a6a4822640bf5c369908ad74ea21518a9c5")
                .unwrap();
        let pub_y =
            Scalar::from_hex("0x0e0456e3795c1a31f20035b741cd6158929eeccd320d299cfcac962865a6bc74")
                .unwrap();

        let sig: [i128; 64] = [
            5, 202, 31, 146, 81, 242, 246, 69, 43, 107, 249, 153, 198, 44, 14, 111, 191, 121, 137,
            166, 160, 103, 18, 181, 243, 233, 226, 95, 67, 16, 37, 128, 85, 76, 19, 253, 30, 77,
            192, 53, 138, 205, 69, 33, 236, 163, 83, 194, 84, 137, 184, 221, 176, 121, 179, 27, 63,
            70, 54, 16, 176, 250, 39, 239,
        ];
        let mut sig_as_scalars = [Scalar::zero(); 64];
        for i in 0..64 {
            sig_as_scalars[i] = sig[i].into()
        }
        let message: Vec<Scalar> = vec![
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
        witness_values.push(Scalar::zero());

        let case_1 = WitnessResult {
            witness: witness_values.into(),
            public_inputs: Assignments::default(),
            result: true,
        };

        test_composer_with_pk_vk(constraint_system, vec![case_1]);
    }
    }
    rusty_fork_test! {
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
            qm: Scalar::zero(),
            ql: Scalar::one(),
            qr: Scalar::zero(),
            qo: Scalar::zero(),
            qc: -Scalar::from_hex(
                "0x11831f49876c313f2a9ec6d8d521c7ce0b6311c852117e340bfe27fd1ac096ef",
            )
            .unwrap(),
        };
        let y_constraint = Constraint {
            a: 4,
            b: 4,
            c: 4,
            qm: Scalar::zero(),
            ql: Scalar::one(),
            qr: Scalar::zero(),
            qo: Scalar::zero(),
            qc: -Scalar::from_hex(
                "0x0ecf9d98be4597a88c46a7e0fa8836b57a7dcb41ee30f8d8787b11cc259c83fa",
            )
            .unwrap(),
        };

        let constraint_system = ConstraintSystem::new()
            .var_num(100)
            .pedersen_constraints(vec![constraint])
            .constraints(vec![x_constraint, y_constraint]);

        let scalar_0 = Scalar::from_hex("0x00").unwrap();
        let scalar_1 = Scalar::from_hex("0x01").unwrap();
        let witness_values = vec![scalar_0, scalar_1];

        let case_1 = WitnessResult {
            witness: witness_values.into(),
            public_inputs: Assignments::default(),
            result: true,
        };

        test_composer_with_pk_vk(constraint_system, vec![case_1]);
    }
    }
    rusty_fork_test! {
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
            qm: Scalar::zero(),
            ql: Scalar::one(),
            qr: -Scalar::one(),
            qo: Scalar::zero(),
            qc: -Scalar::from_hex("0x0a").unwrap(),
        };
        let expr_b = Constraint {
            a: 4,
            b: 5,
            c: 6,
            qm: Scalar::one(),
            ql: Scalar::zero(),
            qr: Scalar::zero(),
            qo: -Scalar::one(),
            qc: Scalar::zero(),
        };
        let expr_c = Constraint {
            a: 4,
            b: 6,
            c: 4,
            qm: Scalar::one(),
            ql: Scalar::zero(),
            qr: Scalar::zero(),
            qo: -Scalar::one(),
            qc: Scalar::zero(),
        };
        let expr_d = Constraint {
            a: 6,
            b: 0,
            c: 0,
            qm: Scalar::zero(),
            ql: -Scalar::one(),
            qr: Scalar::zero(),
            qo: Scalar::zero(),
            qc: Scalar::one(),
        };

        let constraint_system = ConstraintSystem::new()
            .var_num(7)
            .public_inputs(vec![2])
            .range_constraints(vec![range_a, range_b])
            .logic_constraints(vec![logic_constraint])
            .constraints(vec![expr_a, expr_b, expr_c, expr_d]);

        let scalar_5 = Scalar::from_hex("0x05").unwrap();
        let scalar_10 = Scalar::from_hex("0x0a").unwrap();
        let scalar_15 = Scalar::from_hex("0x0f").unwrap();
        let scalar_5_inverse = scalar_5.inverse();
        let witness_values = vec![
            scalar_5,
            scalar_10,
            scalar_15,
            scalar_5,
            scalar_5_inverse,
            Scalar::one(),
        ];
        let case_1 = WitnessResult {
            witness: witness_values.into(),
            public_inputs: vec![scalar_10].into(),
            result: true,
        };

        test_composer_with_pk_vk(constraint_system, vec![case_1]);
    }
    }
    #[derive(Clone, Debug)]
    struct WitnessResult {
        witness: WitnessAssignments,
        public_inputs: Assignments,
        result: bool,
    }

    fn test_composer_with_pk_vk(
        constraint_system: ConstraintSystem,
        test_cases: Vec<WitnessResult>,
    ) {
        let mut sc = StandardComposer::new(constraint_system);

        let proving_key = sc.compute_proving_key();
        let verification_key = sc.compute_verification_key(&proving_key);

        for test_case in test_cases.into_iter() {
            let proof = sc.create_proof_with_pk(test_case.witness, &proving_key);
            let verified = sc.verify_with_vk(&proof, test_case.public_inputs, &verification_key);
            assert_eq!(verified, test_case.result);
        }
    }
}
