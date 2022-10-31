use super::Plonk;
use acvm::acir::{circuit::Circuit, native_types::Witness};
use acvm::FieldElement;
use acvm::{Language, ProofSystemCompiler};
use common::barretenberg_structures::Assignments;
use std::collections::BTreeMap;
use std::io::Write;
use tempfile::NamedTempFile;

#[cfg(windows)]
pub const NODE: &'static str = "node.exe";
#[cfg(windows)]
pub const NPM: &'static str = "npm.cmd";

#[cfg(not(windows))]
pub const NODE: &'static str = "node";
#[cfg(not(windows))]
pub const NPM: &'static str = "npm";

impl ProofSystemCompiler for Plonk {
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

        let proof_bytes = create_proof_using_cli(circuit_file_path, witness_file_path);
        witness_file.close().unwrap(); //ensure the witness file is deleted, or error else.
        remove_public_inputs(circuit.public_inputs.0.len(), proof_bytes)
    }

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

fn get_path_to_cli() -> String {
    let output = std::process::Command::new(NPM)
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

fn create_proof_using_cli(path_to_acir: String, path_to_witness: String) -> Vec<u8> {
    use std::io::Read;

    let proof_file = NamedTempFile::new().unwrap();
    let path_to_save_proof = tempfile_to_path(&proof_file);

    let path_to_cli = get_path_to_cli();
    let output = std::process::Command::new(NODE)
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

fn verify_proof_using_cli(path_to_acir: String, path_to_proof: String) -> bool {
    use std::io::Read;

    let output_file = NamedTempFile::new().unwrap();
    let path_to_output = tempfile_to_path(&output_file);

    let path_to_cli = get_path_to_cli();
    let output = std::process::Command::new(NODE)
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

fn tempfile_to_path(file: &NamedTempFile) -> String {
    file.path().as_os_str().to_str().unwrap().to_owned()
}

fn remove_public_inputs(num_pub_inputs: usize, proof: Vec<u8>) -> Vec<u8> {
    // This is only for public inputs and for Barretenberg.
    // Barretenberg only uses bn254, so each element is 32 bytes.
    // To remove the public inputs, we need to remove (num_pub_inputs * 32) bytes
    let num_bytes_to_remove = 32 * num_pub_inputs;
    proof[num_bytes_to_remove..].to_vec()
}
