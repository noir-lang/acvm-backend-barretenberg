use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use acvm::acir::circuit::Opcode;
use acvm::acir::{circuit::Circuit, native_types::WitnessMap, BlackBoxFunc};
use acvm::FieldElement;
use acvm::{Language, ProofSystemCompiler};
use tempfile::tempdir;

use crate::barretenberg_shim::WriteVkCommand;
use crate::FIELD_BYTES;
use crate::{barretenberg_structures::Assignments, composer::Composer, BackendError, Barretenberg};

impl ProofSystemCompiler for Barretenberg {
    type Error = BackendError;

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }

    fn get_exact_circuit_size(&self, circuit: &Circuit) -> Result<u32, Self::Error> {
        Ok(Composer::get_exact_circuit_size(
            self,
            &circuit.try_into()?,
        )?)
    }

    fn supports_opcode(&self, opcode: &Opcode) -> bool {
        match opcode {
            Opcode::Arithmetic(_) => true,
            Opcode::Directive(_) => true,
            Opcode::Brillig(_) => true,
            Opcode::MemoryInit { .. } => true,
            Opcode::MemoryOp { .. } => true,
            Opcode::BlackBoxFuncCall(func) => match func.get_black_box_func() {
                BlackBoxFunc::AND
                | BlackBoxFunc::XOR
                | BlackBoxFunc::RANGE
                | BlackBoxFunc::SHA256
                | BlackBoxFunc::Blake2s
                | BlackBoxFunc::Keccak256
                | BlackBoxFunc::SchnorrVerify
                | BlackBoxFunc::Pedersen
                | BlackBoxFunc::HashToField128Security
                | BlackBoxFunc::EcdsaSecp256k1
                | BlackBoxFunc::EcdsaSecp256r1
                | BlackBoxFunc::FixedBaseScalarMul
                | BlackBoxFunc::RecursiveAggregation => true,
            },
        }
    }
    // TODO: This is being deprecated
    fn preprocess(
        &self,
        common_reference_string: &[u8],
        circuit: &Circuit,
    ) -> Result<(Vec<u8>, Vec<u8>), Self::Error> {
        let crs = common_reference_string.try_into()?;
        let constraint_system = &circuit.try_into()?;

        let proving_key = self.compute_proving_key(constraint_system)?;
        let verification_key = self.compute_verification_key(&crs, &proving_key)?;

        Ok((proving_key, verification_key))
    }

    fn prove_with_pk(
        &self,
        common_reference_string: &[u8],
        circuit: &Circuit,
        witness_values: WitnessMap,
        proving_key: &[u8], // This is PreProcessedProgram.
        _is_recursive: bool,
    ) -> Result<Vec<u8>, Self::Error> {
        let temp_directory = tempdir().expect("could not create a temporary directory");
        let temp_directory = temp_directory.path();
        let temp_dir_path_str = temp_directory.to_str().unwrap();

        // Create a temporary file for the witness
        let serialized_witnesses: Vec<u8> = witness_values
            .try_into()
            .expect("could not serialize witness map");
        let witness_path = temp_directory.join("witness").with_extension("tr");
        write_to_file(&serialized_witnesses, &witness_path);

        // Create a temporary file for the circuit
        //
        // TODO: We are using the proving key here while the PR to change barretenberg
        // TODO to accepting Circuits has not been merged.
        //
        // TODO: Callers of this method should pass the serialized preprocessProgram to
        // TODO as the proving key for now.
        // TODO: This is the same for the verification procedure.
        let circuit_path = temp_directory.join("circuit").with_extension("json");
        write_to_file(proving_key, &circuit_path);

        // Create proof and store it in the specified path
        let proof_path = temp_directory.join("proof").with_extension("proof");
        crate::barretenberg_shim::ProveCommand {
            verbose: true,
            path_to_crs: temp_dir_path_str.to_string(),
            is_recursive: _is_recursive,
            path_to_json_abi: circuit_path.as_os_str().to_str().unwrap().to_string(),
            path_to_proof_output: proof_path.as_os_str().to_str().unwrap().to_string(),
            path_to_witness: witness_path.as_os_str().to_str().unwrap().to_string(),
        }
        .run()
        .expect("prove command failed");

        // Barretenberg return the proof prepended with the public inputs.
        //
        // This is not how the API expects the proof to be formatted,
        // so we remove the public inputs from the proof.
        //
        // TODO: As noted in the verification procedure, this is an abstraction leak
        // TODO: and will need modifications to barretenberg
        let proof_with_public_inputs =
            read_bytes_from_file(&proof_path.as_os_str().to_str().unwrap()).unwrap();
        let proof =
            remove_public_inputs(circuit.public_inputs().0.len(), &proof_with_public_inputs);
        Ok(proof)
    }

    fn verify_with_vk(
        &self,
        common_reference_string: &[u8],
        proof: &[u8],
        public_inputs: WitnessMap,
        circuit: &Circuit,
        verification_key: &[u8], // This is PreProcessedProgram
        _is_recursive: bool,
    ) -> Result<bool, Self::Error> {
        let temp_directory = tempdir().expect("could not create a temporary directory");
        let temp_directory = temp_directory.path();
        let temp_dir_path = temp_directory.to_str().unwrap();

        // Unlike when proving, we omit any unassigned witnesses.
        // Witness values should be ordered by their index but we skip over any indices without an assignment.
        let flattened_public_inputs: Vec<FieldElement> =
            public_inputs.into_iter().map(|(_, el)| el).collect();

        // Barretenberg expects the proof to be prepended with the public inputs.
        //
        // TODO: This is an abstraction leak and barretenberg's API should accept the public inputs
        // TODO: separately and then prepend them internally
        let proof_with_public_inputs =
            prepend_public_inputs(proof.to_vec(), flattened_public_inputs.to_vec());

        // Create a temporary file for the proof
        let proof_path = temp_directory.join("proof").with_extension("proof");
        write_to_file(&proof_with_public_inputs, &proof_path);

        // Create a temporary file for the circuit
        //
        // TODO: We are using the verification key here while the PR to change barretenberg
        // TODO to accepting Circuits has not been merged.
        //
        // TODO: Callers of this method should pass the serialized preprocessProgram to
        // TODO as the verification key for now
        let circuit_path = temp_directory.join("circuit").with_extension("json");
        write_to_file(verification_key, &circuit_path);

        // Create the verification key and write it to the specified path
        let vk_path = temp_directory.join("vk");
        WriteVkCommand {
            verbose: false,
            path_to_crs: temp_dir_path.to_string(),
            is_recursive: false,
            path_to_json_abi: circuit_path.as_os_str().to_str().unwrap().to_string(),
            path_to_vk_output: vk_path.as_os_str().to_str().unwrap().to_string(),
        }
        .run()
        .expect("write vk command failed");

        // Verify the proof
        Ok(crate::barretenberg_shim::VerifyCommand {
            verbose: false,
            path_to_crs: temp_dir_path.to_string(),
            is_recursive: _is_recursive,
            path_to_proof: proof_path.as_os_str().to_str().unwrap().to_string(),
            path_to_vk: vk_path.as_os_str().to_str().unwrap().to_string(),
        }
        .run())
    }

    fn proof_as_fields(
        &self,
        _proof: &[u8],
        _public_inputs: WitnessMap,
    ) -> Result<Vec<FieldElement>, Self::Error> {
        panic!("vk_as_fields not supported in this backend");
    }

    fn vk_as_fields(
        &self,
        _common_reference_string: &[u8],
        _verification_key: &[u8],
    ) -> Result<(Vec<FieldElement>, FieldElement), Self::Error> {
        panic!("vk_as_fields not supported in this backend");
    }
}

/// Flatten a witness map into a vector of witness assignments.
fn flatten_witness_map(circuit: &Circuit, witness_values: WitnessMap) -> Assignments {
    let num_witnesses = circuit.num_vars();

    // Note: The witnesses are sorted via their witness index
    // witness_values may not have all the witness indexes, e.g for unused witness which are not solved by the solver
    let witness_assignments: Vec<FieldElement> = (1..num_witnesses)
        .map(|witness_index| {
            // Get the value if it exists. If i does not, then we fill it with the zero value
            witness_values
                .get_index(witness_index)
                .map_or(FieldElement::zero(), |field| *field)
        })
        .collect();

    witness_assignments.into()
}

pub(super) fn write_to_file(bytes: &[u8], path: &Path) -> String {
    let display = path.display();

    let mut file = match File::create(path) {
        Err(why) => panic!("couldn't create {display}: {why}"),
        Ok(file) => file,
    };

    match file.write_all(bytes) {
        Err(why) => panic!("couldn't write to {display}: {why}"),
        Ok(_) => display.to_string(),
    }
}

fn read_bytes_from_file(path: &str) -> std::io::Result<Vec<u8>> {
    // Open the file for reading.
    let mut file = File::open(path)?;

    // Create a buffer to store the bytes.
    let mut buffer = Vec::new();

    // Read bytes from the file.
    file.read_to_end(&mut buffer)?;

    Ok(buffer)
}

/// Removes the public inputs which are prepended to a proof by Barretenberg.
fn remove_public_inputs(num_pub_inputs: usize, proof: &[u8]) -> Vec<u8> {
    // Barretenberg prepends the public inputs onto the proof so we need to remove
    // the first `num_pub_inputs` field elements.
    let num_bytes_to_remove = num_pub_inputs * FIELD_BYTES;
    proof[num_bytes_to_remove..].to_vec()
}

/// Prepends a set of public inputs to a proof.
fn prepend_public_inputs(proof: Vec<u8>, public_inputs: Vec<FieldElement>) -> Vec<u8> {
    if public_inputs.is_empty() {
        return proof;
    }

    let public_inputs_bytes = public_inputs
        .into_iter()
        .flat_map(|assignment| assignment.to_be_bytes());

    public_inputs_bytes.chain(proof.into_iter()).collect()
}
