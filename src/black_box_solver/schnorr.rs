use super::BarretenbergBlackBoxSolver;
use crate::Error;

pub(crate) trait SchnorrSig {
    fn construct_signature(
        &self,
        message: &[u8],
        private_key: [u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), Error>;
    fn construct_public_key(&self, private_key: [u8; 32]) -> Result<[u8; 64], Error>;
    fn verify_signature(
        &self,
        pub_key: [u8; 64],
        sig_s: [u8; 32],
        sig_e: [u8; 32],
        message: &[u8],
    ) -> Result<bool, Error>;
}

impl SchnorrSig for BarretenbergBlackBoxSolver {
    fn construct_signature(
        &self,
        message: &[u8],
        private_key: [u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), Error> {
        Ok(barretenberg_sys::schnorr::construct_signature(
            message,
            private_key,
        ))
    }

    fn construct_public_key(&self, private_key: [u8; 32]) -> Result<[u8; 64], Error> {
        Ok(barretenberg_sys::schnorr::construct_public_key(
            &private_key,
        ))
    }

    fn verify_signature(
        &self,
        pub_key: [u8; 64],
        sig_s: [u8; 32],
        sig_e: [u8; 32],
        message: &[u8],
    ) -> Result<bool, Error> {
        Ok(barretenberg_sys::schnorr::verify_signature(
            pub_key, sig_s, sig_e, message,
        ))

        // Note, currently for Barretenberg plonk, if the signature fails
        // then the whole circuit fails.
    }
}

#[test]
fn basic_interop() -> Result<(), Error> {
    let barretenberg = Barretenberg::new();

    // First case should pass, standard procedure for Schnorr
    let private_key = [2; 32];
    let message = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let public_key = barretenberg.construct_public_key(private_key)?;
    let (sig_s, sig_e) = barretenberg.construct_signature(&message, private_key)?;
    let valid_signature = barretenberg.verify_signature(public_key, sig_s, sig_e, &message)?;
    assert!(valid_signature);

    // Should fail, since the messages are different
    let private_key = [2; 32];
    let message = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let public_key = barretenberg.construct_public_key(private_key)?;
    let (sig_s, sig_e) = barretenberg.construct_signature(&message, private_key)?;
    let valid_signature = barretenberg.verify_signature(public_key, sig_s, sig_e, &[0, 2])?;
    assert!(!valid_signature);

    // Should fail, since the signature is not valid
    let private_key = [2; 32];
    let message = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let sig_s = [1; 32];
    let sig_e = [1; 32];

    let public_key = barretenberg.construct_public_key(private_key)?;
    let valid_signature = barretenberg.verify_signature(public_key, sig_s, sig_e, &message)?;
    assert!(!valid_signature);

    // Should fail, since the public key does not match
    let private_key_a = [1; 32];
    let private_key_b = [2; 32];
    let message = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let public_key_b = barretenberg.construct_public_key(private_key_b)?;
    let (sig_s, sig_e) = barretenberg.construct_signature(&message, private_key_a)?;
    let valid_signature = barretenberg.verify_signature(public_key_b, sig_s, sig_e, &message)?;
    assert!(!valid_signature);

    // Test the first case again, to check if memory is being freed and overwritten properly
    let private_key = [2; 32];
    let message = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    let public_key = barretenberg.construct_public_key(private_key)?;
    let (sig_s, sig_e) = barretenberg.construct_signature(&message, private_key)?;
    let valid_signature = barretenberg.verify_signature(public_key, sig_s, sig_e, &message)?;
    assert!(valid_signature);
    Ok(())
}
