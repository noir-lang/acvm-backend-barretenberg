use std::process::Command;

fn main() {
    Command::new("npm")
        .arg("install")
        .arg("-g")
        .arg("@noir-lang/noir-cli")
        .status()
        .expect("Failed to execute command to install noir-cli");
}
