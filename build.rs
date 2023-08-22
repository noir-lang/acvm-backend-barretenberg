use std::env;

use build_target::Os;

// Useful for printing debugging messages during the build
// macro_rules! p {
//     ($($tokens: tt)*) => {
//         println!("cargo:warning={}", format!($($tokens)*))
//     }
// }

fn main() -> Result<(), String> {
    // We need to inject which OS we're building for so that we can download the correct barretenberg binary.
    match build_target::target_os().unwrap() {
        os @ (Os::Linux | Os::MacOs) => println!("cargo:rustc-env=TARGET_OS={os}"),
        Os::Windows => todo!("Windows is not currently supported"),
        _ => panic!("Unsupported OS"),
    };

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
