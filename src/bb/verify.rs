use super::{assert_binary_exists, get_binary_path};

/// VerifyCommand will call the barretenberg binary
/// to verify a proof
pub(crate) struct VerifyCommand {
    pub(crate) verbose: bool,
    pub(crate) path_to_crs: String,
    pub(crate) is_recursive: bool,
    pub(crate) path_to_proof: String,
    pub(crate) path_to_vk: String,
}

impl VerifyCommand {
    pub(crate) fn run(self) -> bool {
        assert_binary_exists();
        let mut command = std::process::Command::new(get_binary_path());

        command
            .arg("verify")
            .arg("-c")
            .arg(self.path_to_crs)
            .arg("-p")
            .arg(self.path_to_proof)
            .arg("-k")
            .arg(self.path_to_vk);

        if self.verbose {
            command.arg("-v");
        }
        if self.is_recursive {
            command.arg("-r");
        }

        let output = command.output().expect("Failed to execute command");
        output.status.success()
    }
}
