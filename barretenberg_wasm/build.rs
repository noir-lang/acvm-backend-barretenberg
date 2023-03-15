use std::{env, fs};

// Useful for printing debugging messages during the build
// macro_rules! p {
//     ($($tokens: tt)*) => {
//         println!("cargo:warning={}", format!($($tokens)*))
//     }
// }

fn copy_wasm(wasm_path: &String) -> Result<(), String> {
    match fs::copy(wasm_path, "src/barretenberg.wasm") {
        Ok(_) => Ok(()),
        Err(err) => {
            println!("{err:?}");
            Err(format!(
                "Failed to copy {wasm_path} into project. Does it exist?"
            ))
        }
    }
}

fn main() -> Result<(), String> {
    match env::var("BARRETENBERG_WASM") {
        Ok(wasm_path) => copy_wasm(&wasm_path),
        Err(_) => {
            if let Ok(bindir) = pkg_config::get_variable("barretenberg", "bindir") {
                copy_wasm(&format!("{bindir}/barretenberg.wasm"))
            } else {
                Err("Unable to locate barretenberg.wasm - Please set the BARRETENBERG_WASM env var to the full path".into())
            }
        }
    }
}
