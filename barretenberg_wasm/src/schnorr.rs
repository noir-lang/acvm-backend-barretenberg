use std::convert::TryInto;
use wasmer::Value;

use super::{Barretenberg, FIELD_BYTES, SIG_BYTES};

impl Barretenberg {
    pub fn construct_signature(&mut self, message: &[u8], private_key: [u8; 32]) -> [u8; 64] {
        let message_ptr: usize = 96;
        let private_key_ptr: usize = 64;
        let sig_s_ptr: usize = 0;
        let sig_e_ptr: usize = 32;
        let result_ptr: usize = 0;

        self.transfer_to_heap(&private_key, private_key_ptr);
        self.transfer_to_heap(message, message_ptr);
        self.call_multiple(
            "construct_signature",
            vec![
                &Value::I32(message_ptr as i32),
                &Value::I32(message.len() as i32),
                &Value::I32(private_key_ptr as i32),
                &Value::I32(sig_s_ptr as i32),
                &Value::I32(sig_e_ptr as i32),
            ],
        );

        let sig_bytes = self.slice_memory(result_ptr, result_ptr + SIG_BYTES);
        sig_bytes.try_into().unwrap()
    }

    pub fn construct_public_key(&mut self, private_key: [u8; 32]) -> [u8; 64] {
        let private_key_ptr: usize = 0;
        let result_ptr: usize = 32;

        self.transfer_to_heap(&private_key, private_key_ptr);

        self.call_multiple(
            "compute_public_key",
            vec![
                &Value::I32(private_key_ptr as i32),
                &Value::I32(result_ptr as i32),
            ],
        );

        self.slice_memory(result_ptr, result_ptr + 2 * FIELD_BYTES)
            .try_into()
            .unwrap()
    }

    pub fn verify_signature(&mut self, pub_key: [u8; 64], sig: [u8; 64], message: &[u8]) -> bool {
        let message_ptr: usize = 128;
        let public_key_ptr: usize = 0;
        let sig_s_ptr: usize = 64;
        let sig_e_ptr: usize = 96;

        let (sig_s, sig_e) = sig.split_at(FIELD_BYTES);

        self.transfer_to_heap(&pub_key, public_key_ptr);
        self.transfer_to_heap(sig_s, sig_s_ptr);
        self.transfer_to_heap(sig_e, sig_e_ptr);
        self.transfer_to_heap(message, message_ptr);

        let wasm_value = self.call_multiple(
            "verify_signature",
            vec![
                &Value::I32(message_ptr as i32),
                &Value::I32(message.len() as i32),
                &Value::I32(public_key_ptr as i32),
                &Value::I32(sig_s_ptr as i32),
                &Value::I32(sig_e_ptr as i32),
            ],
        );
        match wasm_value.into_i32() {
            0 => false,
            1 => true,
            _=> unreachable!("verify signature should return a boolean to indicate whether the signature + parameters were valid")
        }

        // Note, currently for Barretenberg plonk, if the signature fails
        // then the whole circuit fails.
    }
}

#[test]
fn basic_interop() {
    let mut barretenberg = Barretenberg::new();

    // First case should pass, standard procedure for Schnorr
    let private_key = [2; 32];
    let message = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let public_key = barretenberg.construct_public_key(private_key);
    let signature = barretenberg.construct_signature(&message, private_key);
    let valid_signature = barretenberg.verify_signature(public_key, signature, &message);
    assert!(valid_signature);

    // Should fail, since the messages are different
    let private_key = [2; 32];
    let message = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let public_key = barretenberg.construct_public_key(private_key);
    let signature = barretenberg.construct_signature(&message, private_key);
    let valid_signature = barretenberg.verify_signature(public_key, signature, &[0, 2]);
    assert!(!valid_signature);

    // Should fail, since the signature is not valid
    let private_key = [2; 32];
    let message = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let signature = [1; 64];

    let public_key = barretenberg.construct_public_key(private_key);
    let valid_signature = barretenberg.verify_signature(public_key, signature, &message);
    assert!(!valid_signature);

    // Should fail, since the public key does not match
    let private_key_a = [1; 32];
    let private_key_b = [2; 32];
    let message = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let public_key_b = barretenberg.construct_public_key(private_key_b);
    let signature_a = barretenberg.construct_signature(&message, private_key_a);
    let valid_signature = barretenberg.verify_signature(public_key_b, signature_a, &message);
    assert!(!valid_signature);

    // Test the first case again, to check if memory is being freed and overwritten properly
    let private_key = [2; 32];
    let message = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let public_key = barretenberg.construct_public_key(private_key);
    let signature = barretenberg.construct_signature(&message, private_key);
    let valid_signature = barretenberg.verify_signature(public_key, signature, &message);
    assert!(valid_signature);
}
