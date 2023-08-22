use super::{assert_binary_exists, get_binary_path, CliShimError};

/// VerifyCommand will call the barretenberg binary
/// to return a solidity library with the verification key
/// that can be used to verify proofs on-chain.
///
/// This does not return a Solidity file that is able
/// to verify a proof. See acvm_interop/contract.sol for the
/// remaining logic that is missing.
pub(crate) struct ContractCommand {
    pub(crate) verbose: bool,
    pub(crate) path_to_crs: String,
    pub(crate) path_to_vk: String,
}

impl ContractCommand {
    pub(crate) fn run(self) -> Result<String, CliShimError> {
        assert_binary_exists();
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("contract")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-k")
            .arg(self.path_to_vk)
            .arg("-o")
            .arg("/dev/null");

        if self.verbose {
            command.arg("-v");
        }

        let output = command.output().expect("Failed to execute command");
        if output.status.success() {
            let contract_string = String::from_utf8_lossy(&output.stdout).into();
            Ok(contract_string)
        } else {
            Err(CliShimError)
        }
    }
}

#[test]
fn contract_command() {
    let path_to_1_mul = "./src/1_mul.bytecode";
    let path_to_vk_output = "./src/vk1";
    let path_to_crs = "./src/crs";

    let write_vk_command = super::WriteVkCommand {
        verbose: true,
        path_to_bytecode: path_to_1_mul.to_string(),
        path_to_vk_output: path_to_vk_output.to_string(),
        is_recursive: false,
        path_to_crs: path_to_crs.to_string(),
    };

    assert!(write_vk_command.run().is_ok());

    let contract_command = ContractCommand {
        verbose: true,
        path_to_vk: path_to_vk_output.to_string(),
        path_to_crs: path_to_crs.to_string(),
    };

    assert!(contract_command.run().is_ok());
}
