use common::acvm::FieldElement;
use wasmer::Value;

use super::{Barretenberg, FIELD_BYTES};

impl Barretenberg {
    pub fn fixed_base(&mut self, input: &FieldElement) -> (FieldElement, FieldElement) {
        let lhs_ptr: usize = 0;
        let result_ptr: usize = 32;

        self.transfer_to_heap(&input.to_be_bytes(), lhs_ptr);

        self.call_multiple(
            "compute_public_key",
            vec![&Value::I32(lhs_ptr as i32), &Value::I32(result_ptr as i32)],
        );

        let result_bytes = self.slice_memory(result_ptr, 2 * FIELD_BYTES);
        let (pubkey_x_bytes, pubkey_y_bytes) = result_bytes.split_at(32);
        assert!(pubkey_x_bytes.len() == FIELD_BYTES);
        assert!(pubkey_y_bytes.len() == FIELD_BYTES);

        let pubkey_x = FieldElement::from_be_bytes_reduce(pubkey_x_bytes);
        let pubkey_y = FieldElement::from_be_bytes_reduce(pubkey_y_bytes);
        (pubkey_x, pubkey_y)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn smoke_test() {
        let mut barretenberg = Barretenberg::new();
        let input = FieldElement::one();

        let res = barretenberg.fixed_base(&input);
        let x = "0000000000000000000000000000000000000000000000000000000000000001";
        let y = "0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c";

        assert_eq!(x, res.0.to_hex());
        assert_eq!(y, res.1.to_hex());
    }
}
