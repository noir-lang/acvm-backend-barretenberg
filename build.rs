use build_target::Os;
use const_format::formatcp;
use dirs::home_dir;
use std::env::{self};
use std::io::Cursor;

// Useful for printing debugging messages during the build
// macro_rules! p {
//     ($($tokens: tt)*) => {
//         println!("cargo:warning={}", format!($($tokens)*))
//     }
// }

const USERNAME: &str = "AztecProtocol";
const REPO: &str = "barretenberg";
const VERSION: &str = "0.3.6";
const TAG: &str = formatcp!("barretenberg-v{}", VERSION);
const DEST_FOLDER: &str = ".nargo/backends/acvm-backend-barretenberg";
const BINARY_NAME: &str = "backend_binary";

const API_URL: &str = formatcp!(
    "https://github.com/{}/{}/releases/download/{}/",
    USERNAME,
    REPO,
    TAG
);

const DEST_PATH: &str = formatcp!("{}/{}", DEST_FOLDER, BINARY_NAME);

fn main() -> Result<(), String> {
    // TODO: check if binary exists at correct path and download if not
    get_bb();

    // We also embed a version of the backend for black box functions
    let native_backend = env::var("CARGO_FEATURE_NATIVE").is_ok();

    if native_backend {
        Ok(())
    } else {
        match env::var("BARRETENBERG_BIN_DIR") {
            Ok(bindir) => {
                println!("cargo:rustc-env=BARRETENBERG_BIN_DIR={bindir}");
                Ok(())
            }
            Err(_) => {
                if let Ok(bindir) = pkg_config::get_variable("barretenberg", "bindir") {
                    println!("cargo:rustc-env=BARRETENBERG_BIN_DIR={bindir}");
                    Ok(())
                } else {
                    Err("Unable to locate barretenberg.wasm - Please set the BARRETENBERG_BIN_DIR env var to the directory where it exists".into())
                }
            }
        }
    }
}

fn download_compressed_file() -> Cursor<Vec<u8>> {
    let os = build_target::target_os().unwrap();
    let archive_name = match os {
        Os::Linux => "bb-ubuntu.tar.gz",
        Os::MacOs => "barretenberg-x86_64-apple-darwin.tar.gz",
        Os::Windows => todo!("Windows is not currently supported"),
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
    use tempdir::TempDir;

    // Create directories
    std::fs::create_dir_all(DEST_FOLDER).unwrap();

    // Download sources
    let compressed_file = download_compressed_file();

    // Unpack the tarball
    let gz_decoder = GzDecoder::new(compressed_file);
    let mut archive = Archive::new(gz_decoder);

    let temp_dir = TempDir::new("temp_backend").unwrap();
    archive.unpack(&temp_dir).unwrap();

    let os = build_target::target_os().unwrap();
    let binary_path = match os {
        Os::Linux => temp_dir.path().join("cpp/build/bin/bb"),
        Os::MacOs => temp_dir.path().join("bb"),
        Os::Windows => todo!("Windows is not currently supported"),
        _ => panic!("Unsupported OS"),
    };

    // Rename the binary to the desired name
    let desired_path = home_dir().unwrap().join(DEST_PATH);
    std::fs::copy(binary_path, desired_path).unwrap();

    drop(temp_dir);
}
