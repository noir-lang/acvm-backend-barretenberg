use acvm::{acir::circuit::Circuit, async_trait, CommonReferenceString};

use crate::{composer::Composer, BackendError, Barretenberg};

// TODO: Separate impl for JS feature
#[async_trait]
impl CommonReferenceString for Barretenberg {
    type Error = BackendError;

    async fn generate_common_reference_string(
        &self,
        circuit: &Circuit,
    ) -> Result<Vec<u8>, Self::Error> {
        let constraint_system = &circuit.try_into()?;
        Ok(self.get_crs(constraint_system).await?.into())
    }

    async fn update_common_reference_string(
        &self,
        common_reference_string: &[u8],
        circuit: &Circuit,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut crs = common_reference_string.into();
        let constraint_system = &circuit.try_into()?;
        Ok(self.update_crs(&mut crs, constraint_system).await?.into())
    }
}
