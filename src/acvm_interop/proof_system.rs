use super::Plonk;
#[cfg(feature = "sys")]
use crate::barretenberg_rs::composer::StandardComposer;
use crate::barretenberg_structures::Assignments;
use acvm::acir::{circuit::Circuit, native_types::Witness};
use acvm::FieldElement;
use acvm::{Language, ProofSystemCompiler};
use std::collections::BTreeMap;
#[cfg(feature = "wasm-base")]
use std::io::Write;
#[cfg(feature = "wasm-base")]
use tempfile::NamedTempFile;

impl ProofSystemCompiler for Plonk {
    #[cfg(feature = "sys")]
    fn prove_with_meta(
        &self,
        circuit: Circuit,
        witness_values: BTreeMap<Witness, FieldElement>,
    ) -> Vec<u8> {
        let constraint_system = crate::serialise_circuit(&circuit);

        let mut composer = StandardComposer::new(constraint_system);

        // Add witnesses in the correct order
        // Note: The witnesses are sorted via their witness index
        // witness_values may not have all the witness indexes, e.g for unused witness which are not solved by the solver
        let mut sorted_witness = Assignments::new();
        let num_witnesses = circuit.num_vars();
        for i in 1..num_witnesses {
            // Get the value if it exists. If i does not, then we fill it with the zero value
            let value = match witness_values.get(&Witness(i)) {
                Some(value) => *value,
                None => FieldElement::zero(),
            };

            sorted_witness.push(value);
        }

        composer.create_proof(sorted_witness)
    }

    #[cfg(feature = "wasm-base")]
    fn prove_with_meta(
        &self,
        circuit: Circuit,
        witness_values: BTreeMap<Witness, FieldElement>,
    ) -> Vec<u8> {
        //Serialise to disk
        let serialized = circuit.to_bytes();
        let mut circuit_file = NamedTempFile::new().unwrap();
        circuit_file.write_all(serialized.as_slice());

        let serialized = Witness::to_bytes(&witness_values);
        let mut witness_file = NamedTempFile::new().unwrap();
        witness_file.write_all(serialized.as_slice());

        let circuit_file_path = tempfile_to_path(&circuit_file);
        let witness_file_path = tempfile_to_path(&witness_file);

        create_proof_using_cli(circuit_file_path, witness_file_path)
    }

    #[cfg(feature = "sys")]
    fn verify_from_cs(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: Circuit,
    ) -> bool {
        let constraint_system = crate::serialise_circuit(&circuit);

        let mut composer = StandardComposer::new(constraint_system);

        composer.verify(proof, Some(Assignments::from_vec(public_inputs)))
    }

    #[cfg(feature = "wasm-base")]
    fn verify_from_cs(
        &self,
        proof: &[u8],
        public_inputs: Vec<FieldElement>,
        circuit: Circuit,
    ) -> bool {
        let serialized = circuit.to_bytes();
        let mut circuit_file = NamedTempFile::new().unwrap();
        circuit_file.write_all(serialized.as_slice());

        // Prepend the public inputs to the proof
        let mut proof_with_pub_inputs = Vec::new();
        for pi in public_inputs {
            proof_with_pub_inputs.extend(pi.to_bytes())
        }
        proof_with_pub_inputs.extend(proof);

        let mut proof_with_pub_inputs_file = NamedTempFile::new().unwrap();
        proof_with_pub_inputs_file.write_all(&proof_with_pub_inputs);

        let circuit_file_path = tempfile_to_path(&circuit_file);
        let proof_file_path = tempfile_to_path(&proof_with_pub_inputs_file);

        verify_proof_using_cli(circuit_file_path, proof_file_path)
    }

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }
}

#[cfg(feature = "wasm-base")]
fn get_path_to_cli() -> String {
    let output = std::process::Command::new("npm")
        .arg("root")
        .arg("-g")
        .stdout(std::process::Stdio::piped())
        .output()
        .expect("Failed to execute command to fetch root directory");

    let path_to_root_dir = String::from_utf8(output.stdout).unwrap();
    let path_to_root_dir = path_to_root_dir.trim().to_owned();
    let mut path_to_indexjs = path_to_root_dir;
    path_to_indexjs.push_str("/@noir-lang/noir-cli/dest/index.js");
    path_to_indexjs
}

#[cfg(feature = "wasm-base")]
fn create_proof_using_cli(path_to_acir: String, path_to_witness: String) -> Vec<u8> {
    use std::io::Read;

    let proof_file = NamedTempFile::new().unwrap();
    let path_to_save_proof = tempfile_to_path(&proof_file);

    let path_to_cli = get_path_to_cli();
    let output = std::process::Command::new("node")
        .arg(path_to_cli)
        .arg("createProofWithSerialised")
        .arg(path_to_acir)
        .arg(&path_to_save_proof)
        .arg(path_to_witness)
        .status()
        .expect("Failed to execute command to run noir-cli");

    let f = std::fs::File::open(path_to_save_proof).unwrap();
    let mut reader = std::io::BufReader::new(f);
    let mut buffer = Vec::new();

    reader.read_to_end(&mut buffer).unwrap();

    buffer
}

#[cfg(feature = "wasm-base")]
fn verify_proof_using_cli(path_to_acir: String, path_to_proof: String) -> bool {
    use std::io::Read;

    let output_file = NamedTempFile::new().unwrap();
    let path_to_output = tempfile_to_path(&output_file);

    let path_to_cli = get_path_to_cli();
    let output = std::process::Command::new("node")
        .arg(path_to_cli)
        .arg("verifyProof")
        .arg(path_to_acir)
        .arg(&path_to_proof)
        .arg(&path_to_output)
        .status()
        .expect("Failed to execute command to run noir-cli");

    let f = std::fs::File::open(path_to_output).unwrap();
    let mut reader = std::io::BufReader::new(f);
    let mut buffer = Vec::new();

    reader.read_to_end(&mut buffer).unwrap();

    assert_eq!(buffer.len(), 1);

    buffer[0] == 1
}

#[cfg(feature = "wasm-base")]
fn tempfile_to_path(file: &NamedTempFile) -> String {
    file.path().as_os_str().to_str().unwrap().to_owned()
}
