use acvm::FieldElement;
use std::convert::TryInto;
use wasmer::Value;

use super::Barretenberg;
impl Barretenberg {
    pub fn construct_signature(&mut self, message: &[u8], private_key: [u8; 32]) -> [u8; 64] {
        self.transfer_to_heap(&private_key, 64);
        self.transfer_to_heap(message, 96);
        let message_len = Value::I32(message.len() as i32);
        self.call_multiple(
            "construct_signature",
            vec![
                &Value::I32(96),
                &message_len,
                &Value::I32(64),
                &Value::I32(0),
                &Value::I32(32),
            ],
        );

        let sig_bytes = self.slice_memory(0, 64);
        sig_bytes.try_into().unwrap()
    }
    pub fn construct_public_key(&mut self, private_key: [u8; 32]) -> [u8; 64] {
        self.transfer_to_heap(&private_key, 0);

        self.call_multiple("compute_public_key", vec![&Value::I32(0), &Value::I32(32)]);

        self.slice_memory(32, 96).try_into().unwrap()
    }
    pub fn verify_signature(
        &mut self,
        pub_key: [u8; 64],
        sig: [u8; 64],
        message: &[u8],
    ) -> FieldElement {
        self.transfer_to_heap(&pub_key, 0);
        self.transfer_to_heap(&sig[0..32], 64);
        self.transfer_to_heap(&sig[32..64], 96);
        self.transfer_to_heap(message, 128);

        let wasm_value = self.call_multiple(
            "verify_signature",
            vec![
                &Value::I32(128),
                &Value::I32(message.len() as i32),
                &Value::I32(0),
                &Value::I32(64),
                &Value::I32(96),
            ],
        );
        match wasm_value.into_i32() {
            0 => FieldElement::zero(),
            1 => FieldElement::one(),
            _=> unreachable!("verify signature should return a boolean to indicate whether the signature + parameters were valid")
        }

        // Note, currently for Barretenberg plonk, if the signature fails
        // then the whole circuit fails.
    }
}
