#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]

// `acvm-backend-barretenberg` can either interact with the Barretenberg backend through a static library
// or through an embedded wasm binary. It does not make sense to include both of these backends at the same time.
// We then throw a compilation error if both flags are set.
#[cfg(all(feature = "native", feature = "wasm"))]
compile_error!("feature \"native\" and feature \"wasm\" cannot be enabled at the same time");

#[cfg(all(feature = "native", target_arch = "wasm32"))]
compile_error!("feature \"native\" cannot be enabled for a \"wasm32\" target");

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
compile_error!("feature \"wasm\" cannot be enabled for a \"wasm32\" target");

mod barretenberg;
mod bb;
mod common_reference_string;
mod proof_system;
mod pwg;
mod smart_contract;

pub use barretenberg::Barretenberg;
use barretenberg::{Error, FeatureError};

impl acvm::Backend for Barretenberg {}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct BackendError(#[from] Error);

impl From<FeatureError> for BackendError {
    fn from(value: FeatureError) -> Self {
        value.into()
    }
}
