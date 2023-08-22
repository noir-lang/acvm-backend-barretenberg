// Reference: https://github.com/AztecProtocol/aztec-packages/blob/master/circuits/cpp/barretenberg/cpp/src/barretenberg/bb/main.cpp

mod contract;
mod gates;
mod prove;
mod prove_and_verify;
mod verify;
mod write_vk;

use std::{io::Cursor, path::PathBuf};

use const_format::formatcp;
pub(crate) use contract::ContractCommand;
pub(crate) use gates::GatesCommand;
pub(crate) use prove::ProveCommand;
pub(crate) use verify::VerifyCommand;
pub(crate) use write_vk::WriteVkCommand;

const USERNAME: &str = "AztecProtocol";
const REPO: &str = "barretenberg";
const VERSION: &str = "0.4.2";
const TAG: &str = formatcp!("barretenberg-v{}", VERSION);
const DEST_FOLDER: &str = ".nargo/backends/acvm-backend-barretenberg";
const BINARY_NAME: &str = "backend_binary";

const API_URL: &str = formatcp!(
    "https://github.com/{}/{}/releases/download/{}",
    USERNAME,
    REPO,
    TAG
);

/// Returns the path to the binary that was set by the `NARGO_BINARIES_PATH` environment variable
fn get_binary_path() -> PathBuf {
    dirs::home_dir()
        .unwrap()
        .join(formatcp!("{}/{}", DEST_FOLDER, BINARY_NAME))
}

fn assert_binary_exists() {
    if !get_binary_path().exists() {
        get_bb()
    }
}

fn download_compressed_file() -> Cursor<Vec<u8>> {
    let archive_name = match env!("TARGET_OS") {
        "linux" => "bb-ubuntu.tar.gz",
        "macos" => "barretenberg-x86_64-apple-darwin.tar.gz",
        _ => panic!("Unsupported OS"),
    };

    try_download(&format!("{API_URL}/{archive_name}"))
        .unwrap_or_else(|error| panic!("\n\nDownload error: {}\n\n", error))
}

/// Try to download the specified URL into a buffer which is returned.
fn try_download(url: &str) -> Result<Cursor<Vec<u8>>, String> {
    let response = reqwest::blocking::get(url).map_err(|error| error.to_string())?;

    let bytes = response.bytes().unwrap();

    // TODO: Check SHA of downloaded binary

    Ok(Cursor::new(bytes.to_vec()))
}

fn get_bb() {
    use flate2::read::GzDecoder;
    use tar::Archive;
    use tempfile::tempdir;

    // Create directories
    std::fs::create_dir_all(DEST_FOLDER).unwrap();

    // Download sources
    let compressed_file = download_compressed_file();

    // Unpack the tarball
    let gz_decoder = GzDecoder::new(compressed_file);
    let mut archive = Archive::new(gz_decoder);

    let temp_directory = tempdir().expect("could not create a temporary directory");
    archive.unpack(&temp_directory).unwrap();

    let binary_path = match env!("TARGET_OS") {
        "linux" => temp_directory.path().join("cpp/build/bin/bb"),
        "macos" => temp_directory.path().join("bb"),
        _ => panic!("Unsupported OS"),
    };

    // Rename the binary to the desired name
    std::fs::copy(binary_path, get_binary_path()).unwrap();

    drop(temp_directory);
}

#[derive(Debug, thiserror::Error)]
#[error("Error communicating with barretenberg binary")]
pub(crate) struct CliShimError;

#[test]
fn no_command_provided_works() {
    // This is a simple test to check that the binaries work
    assert_binary_exists();

    let output = std::process::Command::new(get_binary_path())
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr, "No command provided.\n");
}
