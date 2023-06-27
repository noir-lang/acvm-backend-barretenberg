use acvm::acir::BlackBoxFunc;
use acvm::pwg::OpcodeResolutionError;
use acvm::{BlackBoxFunctionSolver, FieldElement};

use crate::pedersen::Pedersen;
use crate::scalar_mul::ScalarMul;
use crate::schnorr::SchnorrSig;
use crate::Barretenberg;

impl BlackBoxFunctionSolver for Barretenberg {
    fn schnorr_verify(
        &self,
        public_key_x: &FieldElement,
        public_key_y: &FieldElement,
        signature_s: &FieldElement,
        signature_e: &FieldElement,
        message: &[u8],
    ) -> Result<bool, OpcodeResolutionError> {
        // In barretenberg, if the signature fails, then the whole thing fails.

        let pub_key_x: Vec<u8> = public_key_x.to_be_bytes();
        let pub_key_y: Vec<u8> = public_key_y.to_be_bytes();

        let pub_key_bytes: Vec<u8> = pub_key_x.iter().copied().chain(pub_key_y).collect();
        let pub_key: [u8; 64] = pub_key_bytes.try_into().map_err(|v: Vec<u8>| {
            OpcodeResolutionError::BlackBoxFunctionFailed(
                BlackBoxFunc::SchnorrVerify,
                format!("expected pubkey size {} but received {}", 64, v.len()),
            )
        })?;

        let signature_s: [u8; 32] = signature_s.to_be_bytes().try_into().unwrap();
        let signature_e: [u8; 32] = signature_e.to_be_bytes().try_into().unwrap();

        let valid_signature = self
            .verify_signature(pub_key, signature_s, signature_e, &message)
            .map_err(|err| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    err.to_string(),
                )
            })?;
        if !valid_signature {
            dbg!("signature has failed to verify");
        }

        Ok(valid_signature)
    }

    fn pedersen(
        &self,
        inputs: &[FieldElement],
        domain_separator: u32,
    ) -> Result<(FieldElement, FieldElement), OpcodeResolutionError> {
        self.encrypt(inputs.to_vec(), domain_separator)
            .map_err(|err| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::Pedersen,
                    err.to_string(),
                )
            })
    }

    fn fixed_base_scalar_mul(
        &self,
        input: &FieldElement,
    ) -> Result<(FieldElement, FieldElement), OpcodeResolutionError> {
        self.fixed_base(input).map_err(|err| {
            OpcodeResolutionError::BlackBoxFunctionFailed(
                BlackBoxFunc::FixedBaseScalarMul,
                err.to_string(),
            )
        })
    }
}
