use super::Barretenberg;

pub(crate) trait SchnorrSig {
    fn construct_signature(&self, message: &[u8], private_key: [u8; 32]) -> [u8; 64];
    fn construct_public_key(&self, private_key: [u8; 32]) -> [u8; 64];
    fn verify_signature(&self, pub_key: [u8; 64], sig: [u8; 64], message: &[u8]) -> bool;
}

#[cfg(feature = "native")]
impl SchnorrSig for Barretenberg {
    fn construct_signature(&self, message: &[u8], private_key: [u8; 32]) -> [u8; 64] {
        let (sig_s, sig_e) = barretenberg_sys::schnorr::construct_signature(message, private_key);

        let sig_bytes: [u8; 64] = [sig_s, sig_e].concat().try_into().unwrap();
        sig_bytes
    }

    fn construct_public_key(&self, private_key: [u8; 32]) -> [u8; 64] {
        barretenberg_sys::schnorr::construct_public_key(&private_key)
    }

    fn verify_signature(&self, pub_key: [u8; 64], sig: [u8; 64], message: &[u8]) -> bool {
        let (sig_s, sig_e) = sig.split_at(32);

        let sig_s: [u8; 32] = sig_s.try_into().unwrap();
        let sig_e: [u8; 32] = sig_e.try_into().unwrap();

        barretenberg_sys::schnorr::verify_signature(pub_key, sig_s, sig_e, message)

        // Note, currently for Barretenberg plonk, if the signature fails
        // then the whole circuit fails.
    }
}

#[cfg(not(feature = "native"))]
impl SchnorrSig for Barretenberg {
    fn construct_signature(&self, message: &[u8], private_key: [u8; 32]) -> [u8; 64] {
        use super::{FIELD_BYTES, WASM_SCRATCH_BYTES};
        use wasmer::Value;

        let sig_s_ptr: usize = 0;
        let sig_e_ptr: usize = sig_s_ptr + FIELD_BYTES;
        let private_key_ptr: usize = sig_e_ptr + FIELD_BYTES;
        let message_ptr: usize = private_key_ptr + private_key.len();
        assert!(
            message_ptr + message.len() < WASM_SCRATCH_BYTES,
            "Message overran wasm scratch space"
        );

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

        let sig_s_bytes = self.slice_memory(sig_s_ptr, FIELD_BYTES);
        let sig_e_bytes = self.slice_memory(sig_e_ptr, FIELD_BYTES);
        let sig_s: [u8; 32] = sig_s_bytes.try_into().unwrap();
        let sig_e: [u8; 32] = sig_e_bytes.try_into().unwrap();

        let sig_bytes: [u8; 64] = [sig_s, sig_e].concat().try_into().unwrap();
        sig_bytes
    }

    #[allow(dead_code)]
    fn construct_public_key(&self, private_key: [u8; 32]) -> [u8; 64] {
        use super::FIELD_BYTES;
        use wasmer::Value;

        let private_key_ptr: usize = 0;
        let result_ptr: usize = private_key_ptr + FIELD_BYTES;

        self.transfer_to_heap(&private_key, private_key_ptr);

        self.call_multiple(
            "compute_public_key",
            vec![
                &Value::I32(private_key_ptr as i32),
                &Value::I32(result_ptr as i32),
            ],
        );

        self.slice_memory(result_ptr, 2 * FIELD_BYTES)
            .try_into()
            .unwrap()
    }

    fn verify_signature(&self, pub_key: [u8; 64], sig: [u8; 64], message: &[u8]) -> bool {
        use super::{FIELD_BYTES, WASM_SCRATCH_BYTES};
        use wasmer::Value;

        let (sig_s, sig_e) = sig.split_at(FIELD_BYTES);

        let public_key_ptr: usize = 0;
        let sig_s_ptr: usize = public_key_ptr + pub_key.len();
        let sig_e_ptr: usize = sig_s_ptr + sig_s.len();
        let message_ptr: usize = sig_e_ptr + sig_e.len();
        assert!(
            message_ptr + message.len() < WASM_SCRATCH_BYTES,
            "Message overran wasm scratch space"
        );

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
    let barretenberg = Barretenberg::new();

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
