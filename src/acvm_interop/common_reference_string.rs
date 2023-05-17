use acvm::{acir::circuit::Circuit, async_trait, CommonReferenceString};

use crate::{composer::Composer, BackendError, Barretenberg};

// TODO(#185): Ensure CRS download works in JS
#[async_trait]
impl CommonReferenceString for Barretenberg {
    type Error = BackendError;

    async fn generate_common_reference_string(
        &self,
        circuit: &Circuit,
    ) -> Result<Vec<u8>, Self::Error> {
        let constraint_system = &circuit.try_into()?;
        let common_reference_string = self.get_crs(constraint_system).await?.try_into()?;
        // Separated to have nicer coercion on error types
        Ok(common_reference_string)
    }

    async fn update_common_reference_string(
        &self,
        common_reference_string: Vec<u8>,
        circuit: &Circuit,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut crs = common_reference_string.try_into()?;
        let constraint_system = &circuit.try_into()?;
        let common_reference_string = self
            .update_crs(&mut crs, constraint_system)
            .await?
            .try_into()?;
        // Separated to have nicer coercion on error types
        Ok(common_reference_string)
    }
}
