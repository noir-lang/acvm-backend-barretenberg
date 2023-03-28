use super::pippenger::Pippenger;
use super::Barretenberg;
use common::barretenberg_structures::*;
use common::crs::CRS;
use common::proof;
use wasmer::Value;

pub struct StandardComposer {
    barretenberg: Barretenberg,
    pippenger: Pippenger,
    crs: CRS,
    constraint_system: ConstraintSystem,
}

impl StandardComposer {
    pub fn new(constraint_system: ConstraintSystem) -> StandardComposer {
        let mut barretenberg = Barretenberg::new();

        let circuit_size =
            StandardComposer::get_circuit_size(&mut barretenberg, &constraint_system);

        let crs = CRS::new(circuit_size as usize);

        let pippenger = Pippenger::new(&crs.g1_data, &mut barretenberg);

        StandardComposer {
            barretenberg,
            pippenger,
            crs,
            constraint_system,
        }
    }
}

impl StandardComposer {
    const NUM_RESERVED_GATES: u32 = 4; // this must be >= num_roots_cut_out_of_vanishing_polynomial (found under prover settings in barretenberg)

    // XXX: This does not belong here. Ideally, the Rust code should generate the SC code
    // Since it's already done in C++, we are just re-exporting for now
    pub fn smart_contract(&mut self) -> String {
        let cs_buf = self.constraint_system.to_bytes();
        let cs_ptr = self.barretenberg.allocate(&cs_buf);

        let g2_ptr = self.barretenberg.allocate(&self.crs.g2_data);

        let contract_size = self
            .barretenberg
            .call_multiple(
                "composer__smart_contract",
                vec![&self.pippenger.pointer(), &g2_ptr, &cs_ptr, &Value::I32(0)],
            )
            .value();
        let contract_ptr = self.barretenberg.slice_memory(0, 4);
        let contract_ptr = u32::from_le_bytes(contract_ptr[0..4].try_into().unwrap());

        let sc_as_bytes = self.barretenberg.slice_memory(
            contract_ptr as usize,
            contract_ptr as usize + contract_size.unwrap_i32() as usize,
        );

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
    pub fn get_circuit_size(
        barretenberg: &mut Barretenberg,
        constraint_system: &ConstraintSystem,
    ) -> u32 {
        let num_gates = StandardComposer::get_exact_circuit_size(barretenberg, constraint_system);
        pow2ceil(
            num_gates
                + constraint_system.public_inputs.len() as u32
                + StandardComposer::NUM_RESERVED_GATES,
        )
    }

    pub fn get_exact_circuit_size(
        barretenberg: &mut Barretenberg,
        constraint_system: &ConstraintSystem,
    ) -> u32 {
        let cs_buf = constraint_system.to_bytes();
        let cs_ptr = barretenberg.allocate(&cs_buf);

        let func = barretenberg
            .instance
            .exports
            .get_function("acir_proofs_get_exact_circuit_size")
            .unwrap();

        let params: Vec<_> = vec![cs_ptr.clone()];
        match func.call(&params) {
            Ok(vals) => {
                let i32_bytes = vals.first().cloned().unwrap().unwrap_i32().to_be_bytes();
                let u32_val = u32::from_be_bytes(i32_bytes);
                barretenberg.free(cs_ptr);
                u32_val
            }
            Err(_) => {
                unreachable!("failed on acir_proofs_get_exact_circuit_size call");
            }
        }
    }

    pub fn compute_proving_key(&mut self) -> Vec<u8> {
        let cs_buf = self.constraint_system.to_bytes();
        let cs_ptr = self.barretenberg.allocate(&cs_buf);

        let pk_size = self
            .barretenberg
            .call_multiple(
                "acir_proofs_init_proving_key",
                vec![&cs_ptr, &Value::I32(0)],
            )
            .value();

        let pk_ptr = self.barretenberg.slice_memory(0, 4);
        let pk_ptr = u32::from_le_bytes(pk_ptr[0..4].try_into().unwrap());

        self.barretenberg.slice_memory(
            pk_ptr as usize,
            pk_ptr as usize + pk_size.unwrap_i32() as usize,
        )
    }

    pub fn compute_verification_key(&mut self, proving_key: &[u8]) -> Vec<u8> {
        let g2_ptr = self.barretenberg.allocate(&self.crs.g2_data);

        let pk_ptr = self.barretenberg.allocate(proving_key);

        let vk_size = self
            .barretenberg
            .call_multiple(
                "acir_proofs_init_verification_key",
                vec![&self.pippenger.pointer(), &g2_ptr, &pk_ptr, &Value::I32(0)],
            )
            .value();

        let vk_ptr = self.barretenberg.slice_memory(0, 4);
        let vk_ptr = u32::from_le_bytes(vk_ptr[0..4].try_into().unwrap());

        self.barretenberg.slice_memory(
            vk_ptr as usize,
            vk_ptr as usize + vk_size.unwrap_i32() as usize,
        )
    }

    pub fn create_proof_with_pk(
        &mut self,
        witness: WitnessAssignments,
        proving_key: &[u8],
    ) -> Vec<u8> {
        let cs_buf = self.constraint_system.to_bytes();
        let cs_ptr = self.barretenberg.allocate(&cs_buf);

        let witness_buf = witness.to_bytes();
        let witness_ptr = self.barretenberg.allocate(&witness_buf);

        let g2_ptr = self.barretenberg.allocate(&self.crs.g2_data);

        let pk_ptr = self.barretenberg.allocate(proving_key);

        let proof_size = self
            .barretenberg
            .call_multiple(
                "acir_proofs_new_proof",
                vec![
                    &self.pippenger.pointer(),
                    &g2_ptr,
                    &pk_ptr,
                    &cs_ptr,
                    &witness_ptr,
                    &Value::I32(0),
                ],
            )
            .value();

        let proof_ptr = self.barretenberg.slice_memory(0, 4);
        let proof_ptr = u32::from_le_bytes(proof_ptr[0..4].try_into().unwrap());

        let proof = self.barretenberg.slice_memory(
            proof_ptr as usize,
            proof_ptr as usize + proof_size.unwrap_i32() as usize,
        );
        proof::remove_public_inputs(self.constraint_system.public_inputs.len(), &proof)
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
        //
        let proof = proof::prepend_public_inputs(proof.to_vec(), public_inputs);

        let cs_buf = self.constraint_system.to_bytes();
        let cs_ptr = self.barretenberg.allocate(&cs_buf);

        let proof_ptr = self.barretenberg.allocate(&proof);

        let g2_ptr = self.barretenberg.allocate(&self.crs.g2_data);

        let vk_ptr = self.barretenberg.allocate(verification_key);

        let verified = self
            .barretenberg
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

        self.barretenberg.free(proof_ptr);

        match verified.unwrap_i32() {
            0 => false,
            1 => true,
            _ => panic!("Expected a 1 or a zero for the verification result"),
        }
    }
}

fn pow2ceil(v: u32) -> u32 {
    let mut p = 1;
    while p < v {
        p <<= 1;
    }
    p
}

#[cfg(test)]
mod test {

    use super::*;
    use common::barretenberg_structures::{Constraint, PedersenConstraint, Scalar};

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
            public_inputs: Assignments::default(),
            result: true,
        };
        let case_2 = WitnessResult {
            witness: Assignments(vec![Scalar::zero(), Scalar::zero(), Scalar::zero()]),
            public_inputs: Assignments::default(),
            result: true,
        };
        let case_3 = WitnessResult {
            witness: Assignments(vec![10_i128.into(), (-3_i128).into(), 7_i128.into()]),
            public_inputs: Assignments::default(),
            result: true,
        };
        let case_4 = WitnessResult {
            witness: Assignments(vec![Scalar::zero(), Scalar::zero(), Scalar::one()]),
            public_inputs: Assignments::default(),
            result: false,
        };
        let case_5 = WitnessResult {
            witness: Assignments(vec![Scalar::one(), 2_i128.into(), 6_i128.into()]),
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
        let _case_1 = WitnessResult {
            witness: Assignments(vec![(-1_i128).into(), 2_i128.into(), 1_i128.into()]),
            public_inputs: Assignments::default(),
            result: false,
        };
        let case_2 = WitnessResult {
            witness: Assignments(vec![Scalar::zero(), Scalar::zero(), Scalar::zero()]),
            public_inputs: Assignments(vec![Scalar::zero(), Scalar::zero()]),
            result: true,
        };

        let case_3 = WitnessResult {
            witness: Assignments(vec![Scalar::one(), 2_i128.into(), 6_i128.into()]),
            public_inputs: Assignments(vec![Scalar::one(), 3_i128.into()]),
            result: false,
        };

        // Not enough public inputs
        let _case_4 = WitnessResult {
            witness: Assignments(vec![
                Scalar::one(),
                Scalar::from(2_i128),
                Scalar::from(6_i128),
            ]),
            public_inputs: Assignments(vec![Scalar::one()]),
            result: false,
        };

        let case_5 = WitnessResult {
            witness: Assignments(vec![Scalar::one(), 2_i128.into(), 3_i128.into()]),
            public_inputs: Assignments(vec![Scalar::one(), 2_i128.into()]),
            result: true,
        };

        let case_6 = WitnessResult {
            witness: Assignments(vec![Scalar::one(), 2_i128.into(), 3_i128.into()]),
            public_inputs: Assignments(vec![Scalar::one(), 3_i128.into()]),
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
            public_inputs: Assignments(vec![Scalar::one()]),
            result: true,
        };
        let case_2 = WitnessResult {
            witness: Assignments(vec![
                1_i128.into(),
                1_i128.into(),
                2_i128.into(),
                13_i128.into(),
            ]),
            public_inputs: Assignments(vec![Scalar::one()]),
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
            qm: Scalar::zero(),
            ql: Scalar::zero(),
            qr: Scalar::zero(),
            qo: Scalar::one(),
            qc: -Scalar::one(),
        };

        let constraint_system = ConstraintSystem {
            var_num: 80,
            public_inputs: vec![],
            logic_constraints: vec![],
            range_constraints: vec![],
            sha256_constraints: vec![],
            merkle_membership_constraints: vec![],
            schnorr_constraints: vec![constraint],
            blake2s_constraints: vec![],
            pedersen_constraints: vec![],
            hash_to_field_constraints: vec![],
            constraints: vec![arith_constraint],
            ecdsa_secp256k1_constraints: vec![],
            fixed_base_scalar_mul_constraints: vec![],
        };

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
            witness: Assignments(witness_values),
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
            qm: Scalar::zero(),
            ql: Scalar::one(),
            qr: Scalar::zero(),
            qo: Scalar::zero(),
            qc: -Scalar::from_hex(
                "0x229fb88be21cec523e9223a21324f2e305aea8bff9cdbcb3d0c6bba384666ea1",
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
                "0x296b4b4605e586a91caa3202baad557628a8c56d0a1d6dff1a7ca35aed3029d5",
            )
            .unwrap(),
        };

        let constraint_system = ConstraintSystem {
            var_num: 100,
            public_inputs: vec![],
            logic_constraints: vec![],
            range_constraints: vec![],
            sha256_constraints: vec![],
            merkle_membership_constraints: vec![],
            schnorr_constraints: vec![],
            blake2s_constraints: vec![],
            pedersen_constraints: vec![constraint],
            hash_to_field_constraints: vec![],
            constraints: vec![x_constraint, y_constraint],
            ecdsa_secp256k1_constraints: vec![],
            fixed_base_scalar_mul_constraints: vec![],
        };

        let scalar_0 = Scalar::from_hex("0x00").unwrap();
        let scalar_1 = Scalar::from_hex("0x01").unwrap();
        let witness_values = vec![scalar_0, scalar_1];

        let case_1 = WitnessResult {
            witness: Assignments(witness_values),
            public_inputs: Assignments::default(),
            result: true,
        };

        test_composer_with_pk_vk(constraint_system, vec![case_1]);
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
