use crate::FIELD_BYTES;

use super::Barretenberg;

pub(crate) struct SchnorrSignature {
    s: [u8; FIELD_BYTES],
    e: [u8; FIELD_BYTES],
}

impl From<[u8; 2 * FIELD_BYTES]> for SchnorrSignature {
    fn from(value: [u8; 2 * FIELD_BYTES]) -> Self {
        let (sig_s, sig_e) = value.split_at(FIELD_BYTES);

        // These cannot panic as we're just bisecting the array.
        let s: [u8; FIELD_BYTES] = sig_s.try_into().unwrap();
        let e: [u8; FIELD_BYTES] = sig_e.try_into().unwrap();
        SchnorrSignature { s, e }
    }
}

pub(crate) trait SchnorrSig {
    fn construct_signature(&self, message: &[u8], private_key: [u8; 32]) -> SchnorrSignature;
    fn construct_public_key(&self, private_key: [u8; 32]) -> [u8; 64];
    fn verify_signature(&self, pub_key: [u8; 64], sig: SchnorrSignature, message: &[u8]) -> bool;
}

#[cfg(feature = "native")]
impl SchnorrSig for Barretenberg {
    fn construct_signature(&self, message: &[u8], private_key: [u8; 32]) -> SchnorrSignature {
        let (sig_s, sig_e) = barretenberg_sys::schnorr::construct_signature(message, private_key);

        SchnorrSignature { s: sig_s, e: sig_e }
    }

    fn construct_public_key(&self, private_key: [u8; 32]) -> [u8; 64] {
        barretenberg_sys::schnorr::construct_public_key(&private_key)
    }

    fn verify_signature(&self, pub_key: [u8; 64], sig: SchnorrSignature, message: &[u8]) -> bool {
        // Note, currently for Barretenberg plonk, if the signature fails then the whole circuit fails.
        barretenberg_sys::schnorr::verify_signature(pub_key, sig.s, sig.e, message)
    }
}

#[cfg(not(feature = "native"))]
impl SchnorrSig for Barretenberg {
    fn construct_signature(&self, message: &[u8], private_key: [u8; 32]) -> SchnorrSignature {
        use super::wasm::WASM_SCRATCH_BYTES;

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
                &message_ptr.into(),
                &message.len().into(),
                &private_key_ptr.into(),
                &sig_s_ptr.into(),
                &sig_e_ptr.into(),
            ],
        );

        SchnorrSignature {
            s: self.read_memory(sig_s_ptr),
            e: self.read_memory(sig_e_ptr),
        }
    }

    #[allow(dead_code)]
    fn construct_public_key(&self, private_key: [u8; 32]) -> [u8; 64] {
        let private_key_ptr: usize = 0;
        let result_ptr: usize = private_key_ptr + FIELD_BYTES;

        self.transfer_to_heap(&private_key, private_key_ptr);

        self.call_multiple(
            "compute_public_key",
            vec![&private_key_ptr.into(), &result_ptr.into()],
        );

        self.read_memory(result_ptr)
    }

    fn verify_signature(&self, pub_key: [u8; 64], sig: SchnorrSignature, message: &[u8]) -> bool {
        use super::wasm::WASM_SCRATCH_BYTES;

        let public_key_ptr: usize = 0;
        let sig_s_ptr: usize = public_key_ptr + pub_key.len();
        let sig_e_ptr: usize = sig_s_ptr + sig.s.len();
        let message_ptr: usize = sig_e_ptr + sig.e.len();
        assert!(
            message_ptr + message.len() < WASM_SCRATCH_BYTES,
            "Message overran wasm scratch space"
        );

        self.transfer_to_heap(&pub_key, public_key_ptr);
        self.transfer_to_heap(&sig.s, sig_s_ptr);
        self.transfer_to_heap(&sig.e, sig_e_ptr);
        self.transfer_to_heap(message, message_ptr);

        let wasm_value = self.call_multiple(
            "verify_signature",
            vec![
                &message_ptr.into(),
                &message.len().into(),
                &public_key_ptr.into(),
                &sig_s_ptr.into(),
                &sig_e_ptr.into(),
            ],
        );

        wasm_value.bool()
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
    let signature = SchnorrSignature::from([1; 64]);

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
