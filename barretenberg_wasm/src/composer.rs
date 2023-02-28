use super::pippenger::Pippenger;
use super::Barretenberg;
use common::barretenberg_structures::Assignments;
use common::barretenberg_structures::ConstraintSystem;
use common::barretenberg_structures::WitnessAssignments;
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
            .get_function("standard_example__get_exact_circuit_size")
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
                unreachable!("failed on standard_example__get_exact_circuit_size call");
            }
        }
    }

    pub fn create_proof(&mut self, witness: WitnessAssignments) -> Vec<u8> {
        let cs_buf = self.constraint_system.to_bytes();
        let cs_ptr = self.barretenberg.allocate(&cs_buf);

        let witness_buf = witness.to_bytes();
        let witness_ptr = self.barretenberg.allocate(&witness_buf);

        let g2_ptr = self.barretenberg.allocate(&self.crs.g2_data);

        let proof_size = self
            .barretenberg
            .call_multiple(
                "composer__new_proof",
                vec![
                    &self.pippenger.pointer(),
                    &g2_ptr,
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

    pub fn verify(
        &mut self,
        // XXX: Important: This assumes that the proof does not have the public inputs pre-pended to it
        // This is not the case, if you take the proof directly from Barretenberg
        proof: &[u8],
        public_inputs: Assignments,
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

        let verified = self
            .barretenberg
            .call_multiple(
                "composer__verify_proof",
                vec![
                    &self.pippenger.pointer(),
                    &g2_ptr,
                    &cs_ptr,
                    &proof_ptr,
                    &Value::I32(proof.len() as i32),
                ],
            )
            .value();

        // self.barretenberg.free(cs_ptr);
        self.barretenberg.free(proof_ptr);
        // self.barretenberg.free(g2_ptr);

        match verified.unwrap_i32() {
            0 => false,
            1 => true,
            _ => panic!("Expected a 1 or a zero for the verification result"),
        }
    }

    pub fn compute_proving_key(&mut self) -> Vec<u8> {
        let cs_buf = self.constraint_system.to_bytes();
        let cs_ptr = self.barretenberg.allocate(&cs_buf);

        let pk_size = self
            .barretenberg
            .call_multiple("c_init_proving_key", vec![&cs_ptr, &Value::I32(0)])
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
                "c_init_verification_key",
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
                "c_new_proof",
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
                "c_verify_proof",
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
