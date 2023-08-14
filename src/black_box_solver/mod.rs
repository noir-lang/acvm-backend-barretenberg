use acvm::{acir::BlackBoxFunc, BlackBoxFunctionSolver, BlackBoxResolutionError, FieldElement};

use self::{pedersen::Pedersen, scalar_mul::ScalarMul, schnorr::SchnorrSig};

mod pedersen;
mod scalar_mul;
mod schnorr;

pub struct BarretenbergBlackBoxSolver;

impl BlackBoxFunctionSolver for BarretenbergBlackBoxSolver {
    fn schnorr_verify(
        &self,
        public_key_x: &FieldElement,
        public_key_y: &FieldElement,
        signature: &[u8],
        message: &[u8],
    ) -> Result<bool, BlackBoxResolutionError> {
        let pub_key: Vec<u8> = public_key_x
            .to_be_bytes()
            .into_iter()
            .chain(public_key_y.to_be_bytes())
            .collect();
        let pub_key: [u8; 64] = pub_key.try_into().unwrap();

        let sig_s: [u8; 32] = signature[0..32].try_into().unwrap();
        let sig_e: [u8; 32] = signature[32..64].try_into().unwrap();

        let valid_signature = self
            .verify_signature(pub_key, sig_s, sig_e, message)
            .map_err(|err| {
                BlackBoxResolutionError::Failed(BlackBoxFunc::SchnorrVerify, err.to_string())
            })?;

        Ok(valid_signature)
    }

    fn pedersen(
        &self,
        inputs: &[FieldElement],
        domain_separator: u32,
    ) -> Result<(FieldElement, FieldElement), BlackBoxResolutionError> {
        self.encrypt(inputs.to_vec(), domain_separator)
            .map_err(|err| BlackBoxResolutionError::Failed(BlackBoxFunc::Pedersen, err.to_string()))
    }

    fn fixed_base_scalar_mul(
        &self,
        input: &FieldElement,
    ) -> Result<(FieldElement, FieldElement), BlackBoxResolutionError> {
        self.fixed_base(input).map_err(|err| {
            BlackBoxResolutionError::Failed(BlackBoxFunc::FixedBaseScalarMul, err.to_string())
        })
    }
}
