use acvm::FieldElement;
use wasmer::Value;

use crate::barretenberg_structures::Assignments;

use super::Barretenberg;

impl Barretenberg {
    pub fn compress_native(&mut self, left: &FieldElement, right: &FieldElement) -> FieldElement {
        let lhs_ptr = self.allocate(&left.to_bytes()); // 0..32
        let rhs_ptr = self.allocate(&right.to_bytes()); // 32..64
        let result_ptr = Value::I32(64); // 64..96
        self.call_multiple(
            "pedersen_compress_fields",
            vec![&lhs_ptr, &rhs_ptr, &result_ptr],
        );

        let result_bytes = self.slice_memory(64, 96);
        FieldElement::from_be_bytes_reduce(&result_bytes)
    }
    pub fn compress_many(&mut self, inputs: Vec<FieldElement>) -> FieldElement {
        let input_buf = Assignments(inputs).to_bytes();
        let input_ptr = self.allocate(&input_buf);

        self.call_multiple("pedersen_compress", vec![&input_ptr, &Value::I32(0)]);

        let result_bytes = self.slice_memory(0, 32);
        FieldElement::from_be_bytes_reduce(&result_bytes)
    }

    pub fn encrypt(&mut self, inputs: Vec<FieldElement>) -> (FieldElement, FieldElement) {
        let input_buf = Assignments(inputs).to_bytes();
        let input_ptr = self.allocate(&input_buf);

        let result_ptr = Value::I32(32);
        self.call_multiple("pedersen_encrypt", vec![&input_ptr, &result_ptr]);

        let result_bytes = self.slice_memory(32, 96);
        let (point_x_bytes, point_y_bytes) = result_bytes.split_at(32);
        assert!(point_x_bytes.len() == 32);
        assert!(point_y_bytes.len() == 32);

        let point_x = FieldElement::from_be_bytes_reduce(point_x_bytes);
        let point_y = FieldElement::from_be_bytes_reduce(point_y_bytes);

        (point_x, point_y)
    }
}
