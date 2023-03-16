use bindgen::BindgenError;
use color_eyre::{config::HookBuilder, eyre::Result};
use pkg_config::Error;
use std::{env, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
enum BuildError {
    #[error("Barretenberg could not be found because {0} was set.")]
    PkgConfigDisabled(String),
    #[error("Failed to locate correct Barretenberg. {0}.")]
    PkgConfigProbe(String),
    #[error("{0}")]
    PkgConfigGeneric(String),

    #[error("Clang encountered an error during rust-bindgen: {0}.")]
    BindgenErrorClangDiagnostic(String),
    #[error("Encountered a rust-bindgen error: {0}.")]
    BindgenGeneric(String),
    #[error("Failed to write {0} with rust-bindgen.")]
    BindgenWrite(String),
}

// These are the operating systems that are supported
enum OS {
    Linux,
    Apple,
}

fn select_os() -> OS {
    match env::consts::OS {
        "linux" => OS::Linux,
        "macos" => OS::Apple,
        "windows" => unimplemented!("windows is not supported"),
        _ => {
            // For other OS's we default to linux
            OS::Linux
        }
    }
}

// Useful for printing debugging messages during the build
// macro_rules! p {
//     ($($tokens: tt)*) => {
//         println!("cargo:warning={}", format!($($tokens)*))
//     }
// }

fn main() -> Result<()> {
    // Register a eyre hook to display more readable failure messages to end-users
    let (_, eyre_hook) = HookBuilder::default()
        .display_env_section(false)
        .into_hooks();
    eyre_hook.install()?;

    pkg_config::Config::new()
        .range_version("0.1.0".."0.2.0")
        .probe("barretenberg")
        .map_err(|err| match err {
            Error::EnvNoPkgConfig(val) => BuildError::PkgConfigDisabled(val),
            Error::ProbeFailure {
                name: _,
                command: _,
                ref output,
            } => BuildError::PkgConfigProbe(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ),
            err => BuildError::PkgConfigGeneric(format!("{err}")),
        })?;

    let os = select_os();

    link_cpp_stdlib(&os);
    link_lib_omp(&os);

    // Generate bindings from a header file and place them in a bindings.rs file
    let bindings = bindgen::Builder::default()
        // Clang args so that we can compile C++ with C++20
        .clang_args(&["-std=gnu++20", "-xc++"])
        .header_contents(
            "wrapper.hpp",
            r#"
            #include <barretenberg/dsl/turbo_proofs/c_bind.hpp>
            #include <barretenberg/crypto/blake2s/c_bind.hpp>
            #include <barretenberg/crypto/pedersen/c_bind.hpp>
            #include <barretenberg/crypto/schnorr/c_bind.hpp>
            #include <barretenberg/ecc/curves/bn254/scalar_multiplication/c_bind.hpp>
            "#,
        )
        .allowlist_function("blake2s_to_field")
        .allowlist_function("turbo_get_exact_circuit_size")
        .allowlist_function("turbo_init_proving_key")
        .allowlist_function("turbo_init_verification_key")
        .allowlist_function("turbo_new_proof")
        .allowlist_function("turbo_verify_proof")
        .allowlist_function("pedersen__compress_fields")
        .allowlist_function("pedersen__compress")
        .allowlist_function("pedersen__commit")
        .allowlist_function("new_pippenger")
        .allowlist_function("compute_public_key")
        .allowlist_function("construct_signature")
        .allowlist_function("verify_signature")
        .generate()
        .map_err(|err| match err {
            BindgenError::ClangDiagnostic(msg) => {
                BuildError::BindgenErrorClangDiagnostic(msg.trim().to_string())
            }
            err => BuildError::BindgenGeneric(format!("{err}").trim().to_string()),
        })?;

    println!("cargo:rustc-link-lib=static=barretenberg");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindgen_file = out_path.join("bindings.rs");
    bindings
        .write_to_file(&bindgen_file)
        .map_err(|_| BuildError::BindgenWrite(bindgen_file.to_string_lossy().to_string()).into())
}

fn link_cpp_stdlib(os: &OS) {
    // The name of the c++ stdlib depends on the OS
    match os {
        OS::Linux => println!("cargo:rustc-link-lib=stdc++"),
        OS::Apple => println!("cargo:rustc-link-lib=c++"),
    }
}

fn link_lib_omp(os: &OS) {
    // We are using clang, so we need to tell the linker where to search for lomp
    match os {
        OS::Linux => {
            let mut search_paths = Vec::new();

            let comp = cc::Build::new()
                .flag("-v")
                .flag("-print-search-dirs")
                .get_compiler();
            let mut cmd = comp.to_command();
            let (out, _err) = match cmd.output() {
                Ok(out) => (
                    String::from_utf8(out.stdout).unwrap(),
                    String::from_utf8(out.stderr).unwrap(),
                ),
                Err(_err) => {
                    unimplemented!("Bad C compiler")
                }
            };

            for line in out
                .split('\n')
                .filter_map(|l| l.strip_prefix("libraries: ="))
            {
                search_paths.extend(env::split_paths(line));
            }
            for path in search_paths {
                if path.join("omp").exists() {
                    println!("cargo:rustc-link-search={}", path.display());
                }
            }
        }
        OS::Apple => {
            if let Some(brew_prefix) = find_brew_prefix() {
                println!("cargo:rustc-link-search={brew_prefix}/opt/libomp/lib");
            }
        }
    }
    println!("cargo:rustc-link-lib=omp");
}

fn find_brew_prefix() -> Option<String> {
    let output = std::process::Command::new("brew")
        .arg("--prefix")
        .stdout(std::process::Stdio::piped())
        .output();

    match output {
        Ok(output) => match String::from_utf8(output.stdout) {
            Ok(stdout) => Some(stdout.trim().to_string()),
            Err(_) => None,
        },
        Err(_) => None,
    }
}
