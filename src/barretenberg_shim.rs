// Reference: https://github.com/AztecProtocol/aztec-packages/blob/master/circuits/cpp/barretenberg/cpp/src/barretenberg/bb/main.cpp

use std::env;

/// Returns the path to the binary that was set by the `NARGO_BINARIES_PATH` environment variable
fn get_binary_path() -> String {
    // Get the NARGO_BINARIES_PATH environment variable
    if let Ok(bin_path) = env::var("NARGO_BINARIES_PATH") {
        bin_path
    } else {
        // TODO: This will be done once and for all in Nargo in the future; when Nargo gets installed
        unreachable!("`NARGO_BINARIES_PATH` environment variable not set. Please run the bash script to download the binaries and set the path variable");
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Error communicating with barretenberg binary")]
pub struct CliShimError;

/// VerifyCommand will call the barretenberg binary
/// to verify a proof
pub struct VerifyCommand {
    pub verbose: bool,
    pub path_to_crs: String,
    pub is_recursive: bool,
    pub path_to_proof: String,
    pub path_to_vk: String,
}

impl VerifyCommand {
    pub fn run(self) -> bool {
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("verify")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-p")
            .arg(self.path_to_proof)
            .arg("-k")
            .arg(self.path_to_vk);

        if self.verbose {
            command.arg("-v");
        }
        if self.is_recursive {
            command.arg("-r");
        }

        let output = command.output().expect("Failed to execute command");
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        output.status.success()
    }
}

/// VerifyCommand will call the barretenberg binary
/// to return a solidity library with the verification key
/// that can be used to verify proofs on-chain.
///
/// This does not return a Solidity file that is able
/// to verify a proof. See acvm_interop/contract.sol for the
/// remaining logic that is missing.
pub struct ContractCommand {
    pub verbose: bool,
    pub path_to_crs: String,
    pub path_to_vk: String,
    pub path_to_contract_output: String,
}

impl ContractCommand {
    pub fn run(self) -> Result<(), CliShimError> {
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("contract")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-k")
            .arg(self.path_to_vk)
            .arg("-o")
            .arg(self.path_to_contract_output);

        println!("{:?}", command);

        if self.verbose {
            command.arg("-v");
        }

        let output = command.output().expect("Failed to execute command");
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        if output.status.success() {
            Ok(())
        } else {
            Err(CliShimError)
        }
    }
}

/// WriteCommand will call the barretenberg binary
/// to write a verification key to a file
pub struct WriteVkCommand {
    pub verbose: bool,
    pub path_to_crs: String,
    pub is_recursive: bool,
    pub path_to_bytecode: String,
    pub path_to_vk_output: String,
}

impl WriteVkCommand {
    pub fn run(self) -> Result<(), CliShimError> {
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("write_vk")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-b")
            .arg(self.path_to_bytecode)
            .arg("-o")
            .arg(self.path_to_vk_output);

        if self.verbose {
            command.arg("-v");
        }
        if self.is_recursive {
            command.arg("-r");
        }

        let output = command.output().expect("Failed to execute command");

        if output.status.success() {
            Ok(())
        } else {
            Err(CliShimError)
        }
    }
}

/// ProveCommand will call the barretenberg binary
/// to create a proof, given the witness and the bytecode.
///
/// Note:Internally barretenberg will create and discard the
/// proving key, so this is not returned.
///
/// The proof will be written to the specified output file.
pub struct ProveCommand {
    pub verbose: bool,
    pub path_to_crs: String,
    pub is_recursive: bool,
    pub path_to_bytecode: String,
    pub path_to_proof_output: String,
    pub path_to_witness: String,
}

impl ProveCommand {
    pub fn run(self) -> Result<(), CliShimError> {
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("prove")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-b")
            .arg(self.path_to_bytecode)
            .arg("-w")
            .arg(self.path_to_witness)
            .arg("-o")
            .arg(self.path_to_proof_output);

        if self.verbose {
            command.arg("-v");
        }
        if self.is_recursive {
            command.arg("-r");
        }

        println!("{:?}", command.output());

        let output = command.output().expect("Failed to execute command");

        if output.status.success() {
            Ok(())
        } else {
            Err(CliShimError)
        }
    }
}

/// ProveAndVerifyCommand will call the barretenberg binary
/// to create a proof and then verify the proof once created.
///
/// Note: Functions like this are useful for testing. In a real workflow,
/// ProveCommand and VerifyCommand will be used separately.
struct ProveAndVerifyCommand {
    verbose: bool,
    path_to_crs: String,
    is_recursive: bool,
    path_to_bytecode: String,
    path_to_witness: String,
}

impl ProveAndVerifyCommand {
    fn run(self) -> bool {
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("prove_and_verify")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-b")
            .arg(self.path_to_bytecode)
            .arg("-w")
            .arg(self.path_to_witness);
        if self.verbose {
            command.arg("-v");
        }
        if self.is_recursive {
            command.arg("-r");
        }

        command
            .output()
            .expect("Failed to execute command")
            .status
            .success()
    }
}

/// GatesCommand will call the barretenberg binary
/// to return the number of gates needed to create a proof
/// for the given bytecode.
pub struct GatesCommand {
    pub path_to_bytecode: String,
}

impl GatesCommand {
    pub fn run(self) -> u32 {
        let output = std::process::Command::new(get_binary_path())
            .arg("gates")
            .arg("-b")
            .arg(self.path_to_bytecode)
            .output()
            .expect("Failed to execute command");

        // Note: barretenberg includes the newline, so that subsequent prints to stdout
        // are not on the same line as the gates output.
        let number_gates_with_new_line: String = String::from_utf8_lossy(&output.stdout).into();
        let number_of_gates = number_gates_with_new_line.trim().to_string();

        number_of_gates.parse::<u32>().unwrap()
    }
}

#[test]
fn gate_command() {
    let path_to_1_mul = "./src/1_mul.bytecode";
    let gate_command = GatesCommand {
        path_to_bytecode: path_to_1_mul.to_string(),
    };

    let output = gate_command.run();
    assert_eq!(output, 2775);
}

#[test]
fn prove_and_verify_command() {
    let path_to_1_mul = "./src/1_mul.bytecode";
    let path_to_1_mul_witness = "./src/witness.tr";
    let path_to_crs = "./src/crs";
    let prove_and_verify_command = ProveAndVerifyCommand {
        verbose: true,
        path_to_crs: path_to_crs.to_string(),
        is_recursive: false,
        path_to_bytecode: path_to_1_mul.to_string(),
        path_to_witness: path_to_1_mul_witness.to_string(),
    };

    let output = prove_and_verify_command.run();
    assert!(output);
}

#[test]
fn prove_command() {
    let path_to_1_mul = "./src/1_mul.bytecode";
    let path_to_1_mul_witness = "./src/witness.tr";
    let path_to_crs = "./src/crs";
    let path_to_proof_output = "./src/proof1";
    let prove_command = ProveCommand {
        verbose: true,
        path_to_crs: path_to_crs.to_string(),
        is_recursive: false,
        path_to_bytecode: path_to_1_mul.to_string(),
        path_to_witness: path_to_1_mul_witness.to_string(),
        path_to_proof_output: path_to_proof_output.to_string(),
    };

    let proof_created = prove_command.run();
    assert!(proof_created.is_ok());
}

#[test]
fn write_vk_command() {
    let path_to_1_mul = "./src/1_mul.bytecode";
    let path_to_vk_output = "./src/vk1";
    let path_to_crs = "./src/crs";

    let write_vk_command = WriteVkCommand {
        verbose: true,
        path_to_bytecode: path_to_1_mul.to_string(),
        path_to_vk_output: path_to_vk_output.to_string(),
        is_recursive: false,
        path_to_crs: path_to_crs.to_string(),
    };

    let vk_written = write_vk_command.run();
    assert!(vk_written.is_ok());
}

#[test]
fn contract_command() {
    let path_to_1_mul = "./src/1_mul.bytecode";
    let path_to_vk_output = "./src/vk1";
    let path_to_crs = "./src/crs";

    let write_vk_command = WriteVkCommand {
        verbose: true,
        path_to_bytecode: path_to_1_mul.to_string(),
        path_to_vk_output: path_to_vk_output.to_string(),
        is_recursive: false,
        path_to_crs: path_to_crs.to_string(),
    };

    assert!(write_vk_command.run().is_ok());

    let path_to_contract_output = "./src/contract.sol";
    let contract_command = ContractCommand {
        verbose: true,
        path_to_vk: path_to_vk_output.to_string(),
        path_to_contract_output: path_to_contract_output.to_string(),
        path_to_crs: path_to_crs.to_string(),
    };

    assert!(contract_command.run().is_ok());
}

#[test]
fn no_command_provided_works() {
    // This is a simple test to check that the binaries work

    let output = std::process::Command::new(get_binary_path())
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr, "No command provided.\n");
}
