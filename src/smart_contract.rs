use super::proof_system::{read_bytes_from_file, serialize_circuit, write_to_file};
use crate::{
    bb::{ContractCommand, WriteVkCommand},
    BackendError, Barretenberg,
};
use acvm::{acir::circuit::Circuit, SmartContract};
use tempfile::tempdir;

/// Embed the Solidity verifier file
const ULTRA_VERIFIER_CONTRACT: &str = include_str!("contract.sol");

impl SmartContract for Barretenberg {
    type Error = BackendError;

    fn eth_contract_from_vk(
        &self,
        _common_reference_string: &[u8],
        circuit: &Circuit,
        _verification_key: &[u8],
    ) -> Result<String, Self::Error> {
        let temp_directory = tempdir().expect("could not create a temporary directory");
        let temp_directory = temp_directory.path();
        let temp_dir_path = temp_directory.to_str().unwrap();

        // Create a temporary file for the circuit
        let circuit_path = temp_directory.join("circuit").with_extension("bytecode");
        let serialized_circuit = serialize_circuit(circuit);
        write_to_file(serialized_circuit.as_bytes(), &circuit_path);

        // Create the verification key and write it to the specified path
        let vk_path = temp_directory.join("vk");
        WriteVkCommand {
            verbose: false,
            path_to_crs: temp_dir_path.to_string(),
            is_recursive: false,
            path_to_bytecode: circuit_path.as_os_str().to_str().unwrap().to_string(),
            path_to_vk_output: vk_path.as_os_str().to_str().unwrap().to_string(),
        }
        .run()
        .expect("write vk command failed");

        let contract_path = temp_directory.join("contract.sol");
        ContractCommand {
            verbose: false,
            path_to_crs: temp_dir_path.to_string(),
            path_to_vk: vk_path.as_os_str().to_str().unwrap().to_string(),
            path_to_contract_output: contract_path.as_os_str().to_str().unwrap().to_string(),
        }
        .run()
        .expect("contract command failed");

        let smart_contract =
            read_bytes_from_file(contract_path.as_os_str().to_str().unwrap()).unwrap();
        let verification_key_library = String::from_utf8(smart_contract).unwrap();
        Ok(format!(
            "{verification_key_library}{ULTRA_VERIFIER_CONTRACT}"
        ))
    }
}
