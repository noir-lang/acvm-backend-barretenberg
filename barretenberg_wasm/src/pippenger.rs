use super::{Barretenberg, FIELD_BYTES};
use wasmer::Value;

pub struct Pippenger {
    pippenger_ptr: Value,
}

impl Pippenger {
    pub fn new(crs_data: &[u8], barretenberg: &mut Barretenberg) -> Pippenger {
        let num_points = crs_data.len() / (2 * FIELD_BYTES);

        let crs_ptr = barretenberg.allocate(crs_data);

        let pippenger_ptr = barretenberg
            .call_multiple(
                "new_pippenger",
                vec![&crs_ptr, &Value::I32(num_points as i32)],
            )
            .value();

        barretenberg.free(crs_ptr);

        Pippenger { pippenger_ptr }
    }

    pub fn pointer(&self) -> Value {
        self.pippenger_ptr.clone()
    }
}
