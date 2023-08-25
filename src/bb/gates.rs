use super::{assert_binary_exists, get_binary_path};

/// GatesCommand will call the barretenberg binary
/// to return the number of gates needed to create a proof
/// for the given bytecode.
pub(crate) struct GatesCommand {
    pub(crate) path_to_crs: String,
    pub(crate) path_to_bytecode: String,
}

impl GatesCommand {
    pub(crate) fn run(self) -> u32 {
        assert_binary_exists();
        let output = std::process::Command::new(get_binary_path())
            .arg("gates")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-b")
            .arg(self.path_to_bytecode)
            .output()
            .expect("Failed to execute command");

        // Note: barretenberg includes the newline, so that subsequent prints to stdout
        // are not on the same line as the gates output.
        let number_gates_with_new_line: String = String::from_utf8_lossy(&output.stdout).into();
        let number_of_gates = number_gates_with_new_line.trim().to_string();

        number_of_gates.parse::<u32>().unwrap()
    }
}

#[test]
fn gate_command() {
    use tempfile::tempdir;

    let path_to_1_mul = "./src/1_mul.bytecode";

    let temp_directory = tempdir().expect("could not create a temporary directory");
    let temp_directory_path = temp_directory.path();
    let path_to_crs = temp_directory_path.join("crs");

    let gate_command = GatesCommand {
        path_to_crs: path_to_crs.to_str().unwrap().to_string(),
        path_to_bytecode: path_to_1_mul.to_string(),
    };

    let output = gate_command.run();
    assert_eq!(output, 2775);
    drop(temp_directory);
}
