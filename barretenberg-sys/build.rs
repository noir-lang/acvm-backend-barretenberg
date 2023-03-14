use std::{env, path::PathBuf};

// These are the operating systems that are supported
pub enum OS {
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

fn main() {
    let os = select_os();

    link_cpp_stdlib(&os);
    link_lib_omp(&os);

    pkg_config::Config::new()
        .range_version("0.1.0".."0.2.0")
        .probe("barretenberg")
        .unwrap();

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
        .expect("Unable to generate bindings");

    println!("cargo:rustc-link-lib=barretenberg");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings");
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
            let llvm_dir = find_llvm_linux_path();
            println!("cargo:rustc-link-search={llvm_dir}/lib")
        }
        OS::Apple => {
            if let Some(brew_prefix) = find_brew_prefix() {
                println!("cargo:rustc-link-search={brew_prefix}/opt/libomp/lib")
            }
        }
    }
    println!("cargo:rustc-link-lib=omp");
}

fn find_llvm_linux_path() -> String {
    // Most linux systems will have the `find` application
    //
    // This assumes that there is a single llvm-X folder in /usr/lib
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("find /usr/lib -type d -name \"*llvm-*\" -print -quit")
        .stdout(std::process::Stdio::piped())
        .output()
        .expect("Failed to execute command to run `find`");
    // This should be the path to llvm
    let path_to_llvm = String::from_utf8(output.stdout).unwrap();
    path_to_llvm.trim().to_owned()
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
