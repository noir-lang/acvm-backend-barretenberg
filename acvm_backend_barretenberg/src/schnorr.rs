use super::Barretenberg;

impl Barretenberg {
    #[allow(dead_code)]
    pub(crate) fn construct_signature(&self, message: &[u8], private_key: [u8; 32]) -> [u8; 64] {
        cfg_if::cfg_if! {
            if #[cfg(feature = "native")] {
                let (s, e) = barretenberg_sys::schnorr::construct_signature(message, private_key);
                let sig_bytes: [u8; 64] = [s, e].concat().try_into().unwrap();
                sig_bytes
            } else {
                use wasmer::Value;

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
        }
    }

    #[allow(dead_code)]
    pub(crate) fn construct_public_key(&self, private_key: [u8; 32]) -> [u8; 64] {
        cfg_if::cfg_if! {
            if #[cfg(feature = "native")] {
                barretenberg_sys::schnorr::construct_public_key(&private_key)
            } else {
                use wasmer::Value;

                self.transfer_to_heap(&private_key, 0);

                self.call_multiple("compute_public_key", vec![&Value::I32(0), &Value::I32(32)]);

                self.slice_memory(32, 96).try_into().unwrap()
            }
        }
    }

    pub(crate) fn verify_signature(
        &self,
        pub_key: [u8; 64],
        sig: [u8; 64],
        message: &[u8],
    ) -> bool {
        cfg_if::cfg_if! {
            if #[cfg(feature = "native")] {
                barretenberg_sys::schnorr::verify_signature(
                    pub_key,
                    sig[0..32].try_into().unwrap(),
                    sig[32..64].try_into().unwrap(),
                    message,
                )
            } else {
                use wasmer::Value;

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
                    0 => false,
                    1 => true,
                    _=> unreachable!("verify signature should return a boolean to indicate whether the signature + parameters were valid")
                }
            }
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
