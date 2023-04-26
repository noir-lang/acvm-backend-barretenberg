use acvm::{acir::circuit::Circuit, async_trait, ReferenceString};

use crate::{composer::Composer, crs::CRS, Barretenberg, Error};

// TODO: Separate impl for JS feature
#[async_trait]
impl ReferenceString for Barretenberg {
    type Error = Error;

    async fn get_reference_string(&self, circuit: &Circuit) -> Result<Vec<u8>, Error> {
        Composer::get_reference_string(self, &circuit.into()).map(|crs| crs.into())
    }

    fn is_reference_string_valid(
        &self,
        reference_string: &[u8],
        circuit: &Circuit,
    ) -> Result<bool, Error> {
        let crs: CRS = reference_string.into();

        let num_points = self.get_circuit_size(&circuit.into())?;

        // TODO: This probably needs more validation on g1_data and g2_data
        Ok(crs.num_points >= num_points as usize)
    }
}
