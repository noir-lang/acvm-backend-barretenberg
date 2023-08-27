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

    Ok(())
}
