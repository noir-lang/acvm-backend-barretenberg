// Reference: https://github.com/AztecProtocol/aztec-packages/blob/master/circuits/cpp/barretenberg/cpp/src/barretenberg/bb/main.cpp

use std::env;

//
// TODO: use an environment variable to set the path to the binary
// TODO: this will be set by nargo
//
fn get_binary_path() -> String {
    // Get the NARGO_BINARIES_PATH environment variable
    if let Ok(bin_path) = env::var("NARGO_BINARIES_PATH") {
        return format!("{}", bin_path);
    } else {
        // TODO: This will be done once and for all in Nargo in the future; when Nargo gets installed
        unreachable!("`NARGO_BINARIES_PATH` environment variable not set. Please run the bash script to download the binaries and set the path variable");
    }
}

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

struct ContractCommand {
    verbose: bool,
    path_to_crs: String,
    path_to_vk: String,
    path_to_contract_output: String,
}

impl ContractCommand {
    pub fn run(self) -> Result<(), ()> {
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("contract")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-k")
            .arg(self.path_to_vk)
            .arg("-o")
            .arg(self.path_to_contract_output);

        if self.verbose {
            command.arg("-v");
        }

        let output = command.output().expect("Failed to execute command");
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        if output.status.success() {
            Ok(())
        } else {
            Err(())
        }
    }
}

pub struct WriteVkCommand {
    pub verbose: bool,
    pub path_to_crs: String,
    pub is_recursive: bool,
    pub path_to_json_abi: String,
    pub path_to_vk_output: String,
}

impl WriteVkCommand {
    pub fn run(self) -> Result<(), ()> {
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("write_vk")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-j")
            .arg(self.path_to_json_abi)
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
            Err(())
        }
    }
}
pub struct ProveCommand {
    pub verbose: bool,
    pub path_to_crs: String,
    pub is_recursive: bool,
    pub path_to_json_abi: String,
    pub path_to_proof_output: String,
    pub path_to_witness: String,
}

impl ProveCommand {
    pub fn run(self) -> Result<(), ()> {
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("prove")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-j")
            .arg(self.path_to_json_abi)
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

        let output = command.output().expect("Failed to execute command");

        if output.status.success() {
            Ok(())
        } else {
            Err(())
        }
    }
}

struct ProveAndVerifyCommand {
    verbose: bool,
    path_to_crs: String,
    is_recursive: bool,
    path_to_json_abi: String,
    path_to_witness: String,
}

impl ProveAndVerifyCommand {
    pub fn run(self) -> bool {
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("prove_and_verify")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-j")
            .arg(self.path_to_json_abi)
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

struct GatesCommand {
    path_to_json_abi: String,
}

impl GatesCommand {
    pub fn run(self) -> String {
        let output = std::process::Command::new(get_binary_path())
            .arg("gates")
            .arg("-j")
            .arg(self.path_to_json_abi)
            .output()
            .expect("Failed to execute command");
        // TODO: Seems info method in C++ prints to stderr
        // println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8_lossy(&output.stderr).into()
    }
}

#[test]
fn gate_command() {
    let path_to_1_mul = "./src/1_mul.json";
    let gate_command = GatesCommand {
        path_to_json_abi: path_to_1_mul.to_string(),
    };

    let output = gate_command.run();
    assert_eq!(output, "gates: 2775\n");
}

// TODO: print contract to stdout
// TODO: print gate to stdout without prefix

#[test]
fn prove_and_verify_command() {
    let path_to_1_mul = "./src/1_mul.json";
    let path_to_1_mul_witness = "./src/witness.tr";
    let path_to_crs = "./src/crs";
    let prove_and_verify_command = ProveAndVerifyCommand {
        verbose: true,
        path_to_crs: path_to_crs.to_string(),
        is_recursive: false,
        path_to_json_abi: path_to_1_mul.to_string(),
        path_to_witness: path_to_1_mul_witness.to_string(),
    };

    let output = prove_and_verify_command.run();
    assert!(output);
}

#[test]
fn prove_command() {
    let path_to_1_mul = "./src/1_mul.json";
    let path_to_1_mul_witness = "./src/witness.tr";
    let path_to_crs = "./src/crs";
    let path_to_proof_output = "./src/proofs/proof1";
    let prove_command = ProveCommand {
        verbose: true,
        path_to_crs: path_to_crs.to_string(),
        is_recursive: false,
        path_to_json_abi: path_to_1_mul.to_string(),
        path_to_witness: path_to_1_mul_witness.to_string(),
        path_to_proof_output: path_to_proof_output.to_string(),
    };

    let proof_created = prove_command.run();
    assert!(proof_created.is_ok());
}

#[test]
fn write_vk_command() {
    let path_to_1_mul = "./src/1_mul.json";
    let path_to_vk_output = "./src/vk1";
    let path_to_crs = "./src/crs";

    let write_vk_command = WriteVkCommand {
        verbose: true,
        path_to_json_abi: path_to_1_mul.to_string(),
        path_to_vk_output: path_to_vk_output.to_string(),
        is_recursive: false,
        path_to_crs: path_to_crs.to_string(),
    };

    let vk_written = write_vk_command.run();
    assert!(vk_written.is_ok());
}

#[test]
fn contract_command() {
    let path_to_1_mul = "./src/1_mul.json";
    let path_to_vk_output = "./src/vk1";
    let path_to_crs = "./src/crs";

    let write_vk_command = WriteVkCommand {
        verbose: true,
        path_to_json_abi: path_to_1_mul.to_string(),
        path_to_vk_output: path_to_vk_output.to_string(),
        is_recursive: false,
        path_to_crs: path_to_crs.to_string(),
    };

    assert!(write_vk_command.run().is_ok());

    let path_to_contract_output = "./src/contracts/contract.sol";
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
