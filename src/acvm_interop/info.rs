use acvm::BackendInfo;

use crate::Barretenberg;

const BACKEND_IDENTIFIER: &str = "acvm-backend-barretenberg";

impl BackendInfo for Barretenberg {
    fn identifier(&self) -> String {
        BACKEND_IDENTIFIER.to_owned()
    }
}
