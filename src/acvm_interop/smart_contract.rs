use super::proof_system::{read_bytes_from_file, serialize_circuit, write_to_file};
use crate::{
    barretenberg_shim::{ContractCommand, WriteVkCommand},
    BackendError, Barretenberg,
};
use acvm::{acir::circuit::Circuit, SmartContract};
use tempfile::tempdir;

/// Embed the Solidity verifier file
const ULTRA_VERIFIER_CONTRACT: &str = include_str!("contract.sol");

#[cfg(feature = "native")]
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

#[cfg(not(feature = "native"))]
impl SmartContract for Barretenberg {
    type Error = BackendError;

    fn eth_contract_from_vk(
        &self,
        common_reference_string: &[u8],
        _circuit: &Circuit,
        verification_key: &[u8],
    ) -> Result<String, Self::Error> {
        let CRS { g2_data, .. } = common_reference_string.try_into()?;

        let g2_ptr = self.allocate(&g2_data)?;
        let vk_ptr = self.allocate(verification_key)?;

        // The smart contract string is not actually written to this pointer.
        // `contract_ptr_ptr` is a pointer to a pointer which holds the smart contract string.
        let contract_ptr_ptr: usize = 0;

        let contract_size = self.call_multiple(
            "acir_proofs_get_solidity_verifier",
            vec![&g2_ptr, &vk_ptr, &contract_ptr_ptr.into()],
        )?;

        // We then need to read the pointer at `contract_ptr_ptr` to get the smart contract's location
        // and then slice memory again at `contract_ptr_ptr` to get the smart contract string.
        let contract_ptr = self.get_pointer(contract_ptr_ptr);

        let sc_as_bytes = self.read_memory_variable_length(contract_ptr, contract_size.try_into()?);

        let verification_key_library: String = sc_as_bytes.iter().map(|b| *b as char).collect();
        Ok(format!(
            "{verification_key_library}{ULTRA_VERIFIER_CONTRACT}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use acvm::{acir::circuit::Circuit, SmartContract};
    use tokio::test;

    use crate::BackendError;

    #[test]
    async fn test_smart_contract() -> Result<(), BackendError> {
        use crate::barretenberg_structures::{Constraint, ConstraintSystem};
        use crate::composer::Composer;
        use crate::Barretenberg;
        use acvm::FieldElement;

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

        let bb = Barretenberg::new();
        let crs = bb.get_crs(&constraint_system).await?;

        let proving_key = bb.compute_proving_key(&constraint_system)?;
        let verification_key = bb.compute_verification_key(&crs, &proving_key)?;

        let common_reference_string: Vec<u8> = crs.try_into()?;

        let contract = bb.eth_contract_from_vk(
            &common_reference_string,
            &Circuit::default(),
            &verification_key,
        )?;

        assert!(contract.contains("contract BaseUltraVerifier"));
        assert!(contract.contains("contract UltraVerifier"));
        assert!(contract.contains("library UltraVerificationKey"));

        Ok(())
    }
}
