use super::crs::CRS;
use super::pippenger::Pippenger;
use common::barretenberg_structures::*;
use std::slice;
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
    // XXX: This does not belong here. Ideally, the Rust code should generate the SC code
    // Since it's already done in C++, we are just re-exporting for now
    pub fn smart_contract(&mut self) -> String {
        let mut contract_ptr: *mut u8 = std::ptr::null_mut();
        let p_contract_ptr = &mut contract_ptr as *mut *mut u8;
        let cs_buf = self.constraint_system.to_bytes();
        let sc_as_bytes;
        let contract_size;
        unsafe {
            contract_size = barretenberg_wrapper::composer::smart_contract(
                self.pippenger.pointer(),
                &self.crs.g2_data,
                &cs_buf,
                p_contract_ptr,
            );
            assert!(contract_size > 0);
            sc_as_bytes = slice::from_raw_parts(contract_ptr, contract_size as usize)
        }
        // TODO to check
        // XXX: We truncate the first 40 bytes, due to it being mangled
        // For some reason, the first line is partially mangled
        // So in C+ the first line is duplicated and then truncated
        let verification_method: String = sc_as_bytes[40..].iter().map(|b| *b as char).collect();
        common::contract::turbo_verifier::create(&verification_method)
    }

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
        unsafe {
            barretenberg_wrapper::composer::get_circuit_size(
                constraint_system.to_bytes().as_slice().as_ptr(),
            )
        }
    }

    pub fn get_exact_circuit_size(constraint_system: &ConstraintSystem) -> u32 {
        unsafe {
            barretenberg_wrapper::composer::get_exact_circuit_size(
                constraint_system.to_bytes().as_slice().as_ptr(),
            )
        }
    }

    pub fn create_proof(&mut self, witness: WitnessAssignments) -> Vec<u8> {
        let now = std::time::Instant::now();

        let cs_buf = self.constraint_system.to_bytes();
        let mut proof_addr: *mut u8 = std::ptr::null_mut();
        let p_proof = &mut proof_addr as *mut *mut u8;
        let g2_clone = self.crs.g2_data.clone();
        let witness_buf = witness.to_bytes();
        let proof_size;
        unsafe {
            proof_size = barretenberg_wrapper::composer::create_proof(
                self.pippenger.pointer(),
                &cs_buf,
                &g2_clone,
                &witness_buf,
                p_proof,
            );
        }

        //  TODO - to check why barretenberg  is freeing them, cf:
        //   aligned_free((void*)witness_buf);
        //   aligned_free((void*)g2x);
        //   aligned_free((void*)constraint_system_buf);
        std::mem::forget(cs_buf);
        std::mem::forget(g2_clone);
        std::mem::forget(witness_buf);
        //

        let result;
        unsafe {
            result = Vec::from_raw_parts(proof_addr, proof_size as usize, proof_size as usize)
        }
        println!(
            "Total Proving time (Rust + Static Lib) : {}ns ~ {}seconds",
            now.elapsed().as_nanos(),
            now.elapsed().as_secs(),
        );
        result
    }

    pub fn verify(
        &mut self,
        // XXX: Important: This assumes that the proof does not have the public inputs pre-pended to it
        // This is not the case, if you take the proof directly from Barretenberg
        proof: &[u8],
        public_inputs: Option<Assignments>,
    ) -> bool {
        // Prepend the public inputs to the proof.
        // This is how Barretenberg expects it to be.
        // This is non-standard however, so this Rust wrapper will strip the public inputs
        // from proofs created by Barretenberg. Then in Verify we prepend them again.

        let mut proof = proof.to_vec();
        if let Some(pi) = &public_inputs {
            let mut proof_with_pi = Vec::new();
            for assignment in pi.0.iter() {
                proof_with_pi.extend(&assignment.to_bytes());
            }
            proof_with_pi.extend(proof);
            proof = proof_with_pi;
        }
        let now = std::time::Instant::now();

        let no_pub_input: Vec<u8> = Vec::new();
        let verified;
        unsafe {
            verified = barretenberg_wrapper::composer::verify(
                self.pippenger.pointer(),
                &proof,
                &self.constraint_system.to_bytes(),
                &self.crs.g2_data,
            );
        }
        println!(
            "Total Verifier time (Rust + Static Lib) : {}ns ~ {}seconds",
            now.elapsed().as_nanos(),
            now.elapsed().as_secs(),
        );
        verified
    }
}

// TODO: move this to common
pub(crate) fn remove_public_inputs(num_pub_inputs: usize, proof: Vec<u8>) -> Vec<u8> {
    // This is only for public inputs and for Barretenberg.
    // Barretenberg only used bn254, so each element is 32 bytes.
    // To remove the public inputs, we need to remove (num_pub_inputs * 32) bytes
    let num_bytes_to_remove = 32 * num_pub_inputs;
    proof[num_bytes_to_remove..].to_vec()
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::barretenberg_structures::Scalar;

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

        let constraint_system = ConstraintSystem {
            var_num: 4,
            public_inputs: vec![],
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

        let case_1 = WitnessResult {
            witness: Assignments(vec![(-1_i128).into(), 2_i128.into(), 1_i128.into()]),
            public_inputs: None,
            result: true,
        };
        let case_2 = WitnessResult {
            witness: Assignments(vec![Scalar::zero(), Scalar::zero(), Scalar::zero()]),
            public_inputs: None,
            result: true,
        };
        let case_3 = WitnessResult {
            witness: Assignments(vec![10_i128.into(), (-3_i128).into(), 7_i128.into()]),
            public_inputs: None,
            result: true,
        };
        let case_4 = WitnessResult {
            witness: Assignments(vec![Scalar::zero(), Scalar::zero(), Scalar::one()]),
            public_inputs: None,
            result: false,
        };
        let case_5 = WitnessResult {
            witness: Assignments(vec![Scalar::one(), 2_i128.into(), 6_i128.into()]),
            public_inputs: None,
            result: false,
        };
        // This should fail as we specified that we do not have any public inputs
        let case_6a = WitnessResult {
            witness: Assignments(vec![Scalar::one(), 2_i128.into(), 6_i128.into()]),
            public_inputs: Some(Assignments(vec![Scalar::one()])),
            result: false,
        };
        // Even if the public input is zero
        let case_6b = WitnessResult {
            witness: Assignments(vec![
                Scalar::one(),
                Scalar::from(2_i128),
                Scalar::from(6_i128),
            ]),
            public_inputs: Some(Assignments(vec![Scalar::zero()])),
            result: false,
        };

        test_circuit(
            constraint_system,
            vec![case_1, case_2, case_3, case_4, case_5, case_6a, case_6b],
        );
    }
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

        // This fails because the constraint system requires public inputs,
        // but none are supplied in public_inputs. So the verifier will not
        // supply anything.
        let case_1 = WitnessResult {
            witness: Assignments(vec![(-1_i128).into(), 2_i128.into(), 1_i128.into()]),
            public_inputs: None,
            result: false,
        };
        let case_2 = WitnessResult {
            witness: Assignments(vec![Scalar::zero(), Scalar::zero(), Scalar::zero()]),
            public_inputs: Some(Assignments(vec![Scalar::zero(), Scalar::zero()])),
            result: true,
        };

        let case_3 = WitnessResult {
            witness: Assignments(vec![Scalar::one(), 2_i128.into(), 6_i128.into()]),
            public_inputs: Some(Assignments(vec![Scalar::one(), 3_i128.into()])),
            result: false,
        };

        // Not enough public inputs
        let case_4 = WitnessResult {
            witness: Assignments(vec![
                Scalar::one(),
                Scalar::from(2_i128),
                Scalar::from(6_i128),
            ]),
            public_inputs: Some(Assignments(vec![Scalar::one()])),
            result: false,
        };

        let case_5 = WitnessResult {
            witness: Assignments(vec![Scalar::one(), 2_i128.into(), 3_i128.into()]),
            public_inputs: Some(Assignments(vec![Scalar::one(), 2_i128.into()])),
            result: true,
        };

        let case_6 = WitnessResult {
            witness: Assignments(vec![Scalar::one(), 2_i128.into(), 3_i128.into()]),
            public_inputs: Some(Assignments(vec![Scalar::one(), 3_i128.into()])),
            result: false,
        };

        test_circuit(
            constraint_system,
            vec![case_1, case_2, case_3, case_4, case_5, case_6],
        );
    }

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

        let constraint_system = ConstraintSystem {
            var_num: 5,
            public_inputs: vec![1],
            logic_constraints: vec![],
            range_constraints: vec![],
            sha256_constraints: vec![],
            merkle_membership_constraints: vec![],
            schnorr_constraints: vec![],
            blake2s_constraints: vec![],
            pedersen_constraints: vec![],
            hash_to_field_constraints: vec![],
            constraints: vec![constraint, constraint2],
            ecdsa_secp256k1_constraints: vec![],
            fixed_base_scalar_mul_constraints: vec![],
        };

        let case_1 = WitnessResult {
            witness: Assignments(vec![
                1_i128.into(),
                1_i128.into(),
                2_i128.into(),
                3_i128.into(),
            ]),
            public_inputs: Some(Assignments(vec![Scalar::one()])),
            result: true,
        };
        let case_2 = WitnessResult {
            witness: Assignments(vec![
                1_i128.into(),
                1_i128.into(),
                2_i128.into(),
                13_i128.into(),
            ]),
            public_inputs: Some(Assignments(vec![Scalar::one()])),
            result: false,
        };

        test_circuit(constraint_system, vec![case_1, case_2]);
    }
    // TODO: an added asset statement was added, making this test fail
    // TODO: we can regenerate a signature using the new code
    // #[test]
    // fn test_schnorr_constraints() {
    //     let mut signature_indices = [0i32; 64];
    //     for i in 13..(13 + 64) {
    //         signature_indices[i - 13] = i as i32;
    //     }
    //     let result_indice = signature_indices.last().unwrap() + 1;

    //     let constraint = SchnorrConstraint {
    //         message: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    //         public_key_x: 11,
    //         public_key_y: 12,
    //         signature: signature_indices,
    //         result: result_indice,
    //     };

    //     let arith_constraint = Constraint {
    //         a: result_indice,
    //         b: result_indice,
    //         c: result_indice,
    //         qm: Scalar::zero(),
    //         ql: Scalar::zero(),
    //         qr: Scalar::zero(),
    //         qo: Scalar::one(),
    //         qc: -Scalar::one(),
    //     };

    //     let constraint_system = ConstraintSystem {
    //         var_num: 80,
    //         public_inputs: vec![],
    //         logic_constraints: vec![],
    //         range_constraints: vec![],
    //         sha256_constraints: vec![],
    //         merkle_membership_constraints: vec![],
    //         schnorr_constraints: vec![constraint],
    //         blake2s_constraints: vec![],
    //         pedersen_constraints: vec![],
    //         hash_to_field_constraints: vec![],
    //         constraints: vec![arith_constraint],
    //         ecdsa_secp256k1_constraints: vec![],
    //         fixed_base_scalar_mul_constraints: vec![],
    //     };

    //     let pub_x =
    //         Scalar::from_hex("0x17cbd3ed3151ccfd170efe1d54280a6a4822640bf5c369908ad74ea21518a9c5")
    //             .unwrap();
    //     let pub_y =
    //         Scalar::from_hex("0x0e0456e3795c1a31f20035b741cd6158929eeccd320d299cfcac962865a6bc74")
    //             .unwrap();

    //     let sig: [i128; 64] = [
    //         7, 131, 147, 205, 145, 77, 60, 169, 159, 86, 91, 209, 140, 210, 4, 21, 186, 39, 221,
    //         195, 62, 35, 220, 144, 135, 28, 201, 97, 145, 125, 146, 211, 92, 16, 67, 59, 162, 133,
    //         144, 52, 184, 137, 241, 102, 176, 152, 138, 220, 21, 40, 211, 178, 191, 67, 71, 11,
    //         209, 191, 86, 91, 196, 68, 98, 214,
    //     ];
    //     let mut sig_as_scalars = [Scalar::zero(); 64];
    //     for i in 0..64 {
    //         sig_as_scalars[i] = sig[i].into()
    //     }
    //     let message: Vec<Scalar> = vec![
    //         0_i128.into(),
    //         1_i128.into(),
    //         2_i128.into(),
    //         3_i128.into(),
    //         4_i128.into(),
    //         5_i128.into(),
    //         6_i128.into(),
    //         7_i128.into(),
    //         8_i128.into(),
    //         9_i128.into(),
    //     ];
    //     let mut witness_values = Vec::new();
    //     witness_values.extend(message);
    //     witness_values.push(pub_x);
    //     witness_values.push(pub_y);
    //     witness_values.extend(&sig_as_scalars);
    //     witness_values.push(Scalar::zero());

    //     let case_1 = WitnessResult {
    //         witness: Assignments(witness_values),
    //         public_inputs: None,
    //         result: true,
    //     };

    //     test_circuit(constraint_system, vec![case_1]);
    // }
    // TODO: Pedersen generators have changed, so these fixed numbers
    // TODO will not work
    // #[test]
    // fn test_ped_constraints() {
    //     let constraint = PedersenConstraint {
    //         inputs: vec![1, 2],
    //         result_x: 3,
    //         result_y: 4,
    //     };

    //     let x_constraint = Constraint {
    //         a: 3,
    //         b: 3,
    //         c: 3,
    //         qm: Scalar::zero(),
    //         ql: Scalar::one(),
    //         qr: Scalar::zero(),
    //         qo: Scalar::zero(),
    //         qc: -Scalar::from_hex(
    //             "0x108800e84e0f1dafb9fdf2e4b5b311fd59b8b08eaf899634c59cc985b490234b",
    //         )
    //         .unwrap(),
    //     };
    //     let y_constraint = Constraint {
    //         a: 4,
    //         b: 4,
    //         c: 4,
    //         qm: Scalar::zero(),
    //         ql: Scalar::one(),
    //         qr: Scalar::zero(),
    //         qo: Scalar::zero(),
    //         qc: -Scalar::from_hex(
    //             "0x2d43ef68df82e0adf74fed92b1bc950670b9806afcfbcda08bb5baa6497bdf14",
    //         )
    //         .unwrap(),
    //     };

    //     let constraint_system = ConstraintSystem {
    //         var_num: 100,
    //         public_inputs: vec![],
    //         logic_constraints: vec![],
    //         range_constraints: vec![],
    //         sha256_constraints: vec![],
    //         merkle_membership_constraints: vec![],
    //         schnorr_constraints: vec![],
    //         blake2s_constraints: vec![],
    //         pedersen_constraints: vec![constraint],
    //         hash_to_field_constraints: vec![],
    //         constraints: vec![x_constraint, y_constraint],
    //         ecdsa_secp256k1_constraints: vec![],
    //         fixed_base_scalar_mul_constraints: vec![],
    //     };

    //     let scalar_0 = Scalar::from_hex("0x00").unwrap();
    //     let scalar_1 = Scalar::from_hex("0x01").unwrap();

    //     let mut witness_values = Vec::new();
    //     witness_values.push(scalar_0);
    //     witness_values.push(scalar_1);
    //     // witness_values.push(Scalar::zero());

    //     let case_1 = WitnessResult {
    //         witness: Assignments(witness_values),
    //         public_inputs: None,
    //         result: true,
    //     };

    //     test_circuit(constraint_system, vec![case_1]);
    // }

    #[derive(Clone, Debug)]
    struct WitnessResult {
        witness: WitnessAssignments,
        public_inputs: Option<Assignments>,
        result: bool,
    }

    fn test_circuit(constraint_system: ConstraintSystem, test_cases: Vec<WitnessResult>) {
        let mut sc = StandardComposer::new(constraint_system);
        for test_case in test_cases.into_iter() {
            let proof = sc.create_proof(test_case.witness);
            let verified = sc.verify(&proof, test_case.public_inputs);
            assert_eq!(verified, test_case.result);
        }
    }
}
