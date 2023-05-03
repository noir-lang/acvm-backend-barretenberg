use acvm::{acir::circuit::Circuit, async_trait, CommonReferenceString};

use crate::{composer::Composer, Barretenberg, Error};

// TODO: Separate impl for JS feature
#[async_trait]
impl CommonReferenceString for Barretenberg {
    type Error = Error;

    async fn generate_common_reference_string(&self, circuit: &Circuit) -> Result<Vec<u8>, Error> {
        self.get_crs(&circuit.into()).await.map(|crs| crs.into())
    }

    fn is_common_reference_string_valid(
        &self,
        reference_string: &[u8],
        circuit: &Circuit,
    ) -> Result<bool, Error> {
        self.is_crs_valid(&reference_string.into(), &circuit.into())
    }
}
