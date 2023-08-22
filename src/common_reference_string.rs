use acvm::{acir::circuit::Circuit, async_trait, CommonReferenceString};

use crate::{BackendError, Barretenberg};

// TODO(#185): Ensure CRS download works in JS
#[async_trait(?Send)]
impl CommonReferenceString for Barretenberg {
    type Error = BackendError;

    async fn generate_common_reference_string(
        &self,
        _circuit: &Circuit,
    ) -> Result<Vec<u8>, Self::Error> {
        unimplemented!("CRS handling is now left to the backend")
    }

    async fn update_common_reference_string(
        &self,
        _common_reference_string: Vec<u8>,
        _circuit: &Circuit,
    ) -> Result<Vec<u8>, Self::Error> {
        unimplemented!("CRS handling is now left to the backend")
    }
}
