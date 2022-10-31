
use super::crs::CRS;
use super::pippenger::Pippenger;
use super::Barretenberg;
use acvm::FieldElement as Scalar;
use wasmer::Value;
use crate::barretenberg_structures::Assignments;
use crate::barretenberg_structures::WitnessAssignments;
use crate::barretenberg_structures::ConstraintSystem;
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
        crate::contract::turbo_verifier::create(&verification_method)
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
        let cs_buf = constraint_system.to_bytes();
        let cs_ptr = barretenberg.allocate(&cs_buf);

        let func = barretenberg
            .instance
            .exports
            .get_function("composer__get_circuit_size")
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
                // Default to 2^19
                2u32.pow(19)
            }
        }
    }

    pub fn create_proof(&mut self, witness: WitnessAssignments) -> Vec<u8> {
        use core::convert::TryInto;
        let now = std::time::Instant::now();

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
        println!(
            "Total Proving time (Rust + WASM) : {}ns ~ {}seconds",
            now.elapsed().as_nanos(),
            now.elapsed().as_secs(),
        );
        remove_public_inputs(self.constraint_system.public_inputs.len(), proof)
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
        //

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

        let cs_buf = self.constraint_system.to_bytes();
        let cs_ptr = self.barretenberg.allocate(&cs_buf);

        let proof_ptr = self.barretenberg.allocate(&proof);

        let g2_ptr = self.barretenberg.allocate(&self.crs.g2_data);

        let verified = match public_inputs {
            None => self
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
                .value(),
            Some(pub_inputs) => {
                let pub_inputs_buf = pub_inputs.to_bytes();
                let pub_inputs_ptr = self.barretenberg.allocate(&pub_inputs_buf);

                let verified = self
                    .barretenberg
                    .call_multiple(
                        "composer__verify_proof_with_public_inputs",
                        vec![
                            &self.pippenger.pointer(),
                            &g2_ptr,
                            &cs_ptr,
                            &pub_inputs_ptr,
                            &proof_ptr,
                            &Value::I32(proof.len() as i32),
                        ],
                    )
                    .value();

                self.barretenberg.free(pub_inputs_ptr);

                verified
            }
        };
        // self.barretenberg.free(cs_ptr);
        self.barretenberg.free(proof_ptr);
        // self.barretenberg.free(g2_ptr);

        println!(
            "Total Verifier time (Rust + WASM) : {}ns ~ {}seconds",
            now.elapsed().as_nanos(),
            now.elapsed().as_secs(),
        );

        match verified.unwrap_i32() {
            0 => false,
            1 => true,
            _ => panic!("Expected a 1 or a zero for the verification result"),
        }
    }
}

fn remove_public_inputs(num_pub_inputs: usize, proof: Vec<u8>) -> Vec<u8> {
    // This is only for public inputs and for Barretenberg.
    // Barretenberg only used bn254, so each element is 32 bytes.
    // To remove the public inputs, we need to remove (num_pub_inputs * 32) bytes
    let num_bytes_to_remove = 32 * num_pub_inputs;
    proof[num_bytes_to_remove..].to_vec()
}