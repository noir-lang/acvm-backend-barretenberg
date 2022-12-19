use std::process::Command;

#[cfg(windows)]
pub const NPM: &str = "npm.cmd";

#[cfg(not(windows))]
pub const NPM: &str = "npm";

fn main() {
    Command::new(NPM)
        .arg("install")
        .arg("-g")
        .arg("@noir-lang/noir-cli")
        .status()
        .expect("Failed to execute command to install noir-cli");
}
