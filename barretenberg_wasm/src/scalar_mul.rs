use common::acvm::FieldElement;
use wasmer::Value;

use super::Barretenberg;

impl Barretenberg {
    pub fn fixed_base(&mut self, input: &FieldElement) -> (FieldElement, FieldElement) {
        let lhs_ptr = self.allocate(&input.to_be_bytes()); // 0..32
        let result_ptr = Value::I32(32);
        self.call_multiple("compute_public_key", vec![&lhs_ptr, &result_ptr]);

        let result_bytes = self.slice_memory(32, 96);
        let (pubkey_x_bytes, pubkey_y_bytes) = result_bytes.split_at(32);
        assert!(pubkey_x_bytes.len() == 32);
        assert!(pubkey_y_bytes.len() == 32);

        let pubkey_x = FieldElement::from_be_bytes_reduce(pubkey_x_bytes);
        let pubkey_y = FieldElement::from_be_bytes_reduce(pubkey_y_bytes);
        (pubkey_x, pubkey_y)
    }
}
