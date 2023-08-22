// Reference: https://github.com/AztecProtocol/aztec-packages/blob/master/circuits/cpp/barretenberg/cpp/src/barretenberg/bb/main.cpp

mod contract;
mod gates;
mod prove;
mod prove_and_verify;
mod verify;
mod write_vk;

use std::path::PathBuf;

pub(crate) use contract::ContractCommand;
pub(crate) use gates::GatesCommand;
pub(crate) use prove::ProveCommand;
pub(crate) use verify::VerifyCommand;
pub(crate) use write_vk::WriteVkCommand;

/// Returns the path to the binary that was set by the `NARGO_BINARIES_PATH` environment variable
fn get_binary_path() -> PathBuf {
    dirs::home_dir()
        .unwrap()
        .join(".nargo/backends/acvm-backend-barretenberg/backend_binary")
}

fn assert_binary_exists() {
    if !get_binary_path().exists() {
        panic!("Barretenberg binary isn't installed")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Error communicating with barretenberg binary")]
pub(crate) struct CliShimError;

#[test]
fn no_command_provided_works() {
    // This is a simple test to check that the binaries work

    let output = std::process::Command::new(get_binary_path())
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr, "No command provided.\n");
}
