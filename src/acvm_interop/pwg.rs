use acvm::acir::circuit::opcodes::FunctionInput;
use acvm::acir::native_types::{Witness, WitnessMap};
use acvm::acir::BlackBoxFunc;
use acvm::pwg::{witness_to_value, OpcodeResolution, OpcodeResolutionError};
use acvm::{FieldElement, PartialWitnessGenerator};

use crate::pedersen::Pedersen;
use crate::scalar_mul::ScalarMul;
use crate::schnorr::SchnorrSig;
use crate::Barretenberg;

impl PartialWitnessGenerator for Barretenberg {
    fn schnorr_verify(
        &self,
        initial_witness: &mut WitnessMap,
        public_key_x: &FunctionInput,
        public_key_y: &FunctionInput,
        signature: &[FunctionInput],
        message: &[FunctionInput],
        output: &Witness,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        // In barretenberg, if the signature fails, then the whole thing fails.

        let pub_key_x = witness_to_value(initial_witness, public_key_x.witness)?.to_be_bytes();
        let pub_key_y = witness_to_value(initial_witness, public_key_y.witness)?.to_be_bytes();

        let pub_key_bytes: Vec<u8> = pub_key_x
            .iter()
            .copied()
            .chain(pub_key_y.to_vec())
            .collect();
        let pub_key: [u8; 64] = pub_key_bytes.try_into().map_err(|v: Vec<u8>| {
            OpcodeResolutionError::BlackBoxFunctionFailed(
                BlackBoxFunc::SchnorrVerify,
                format!("expected pubkey size {} but received {}", 64, v.len()),
            )
        })?;

        let mut signature = signature.iter();
        let mut sig_s = [0u8; 32];
        for (i, sig) in sig_s.iter_mut().enumerate() {
            let _sig_i = signature.next().ok_or_else(|| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    format!("sig_s should be 32 bytes long, found only {i} bytes"),
                )
            })?;
            let sig_i = witness_to_value(initial_witness, _sig_i.witness)?;
            *sig = *sig_i.to_be_bytes().last().ok_or_else(|| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    "could not get last bytes".into(),
                )
            })?;
        }
        let mut sig_e = [0u8; 32];
        for (i, sig) in sig_e.iter_mut().enumerate() {
            let _sig_i = signature.next().ok_or_else(|| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    format!("sig_e should be 32 bytes long, found only {i} bytes"),
                )
            })?;
            let sig_i = witness_to_value(initial_witness, _sig_i.witness)?;
            *sig = *sig_i.to_be_bytes().last().ok_or_else(|| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    "could not get last bytes".into(),
                )
            })?;
        }

        let mut message_bytes = Vec::new();
        for msg in message.iter() {
            let msg_i_field = witness_to_value(initial_witness, msg.witness)?;
            let msg_i = *msg_i_field.to_be_bytes().last().ok_or_else(|| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    "could not get last bytes".into(),
                )
            })?;
            message_bytes.push(msg_i);
        }

        let valid_signature = self
            .verify_signature(pub_key, sig_s, sig_e, &message_bytes)
            .map_err(|err| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    err.to_string(),
                )
            })?;
        if !valid_signature {
            dbg!("signature has failed to verify");
        }

        initial_witness.insert(*output, FieldElement::from(valid_signature));
        Ok(OpcodeResolution::Solved)
    }

    fn pedersen(
        &self,
        initial_witness: &mut WitnessMap,
        inputs: &[FunctionInput],
        _domain_separator: u32,
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        let scalars: Result<Vec<_>, _> = inputs
            .iter()
            .map(|input| witness_to_value(initial_witness, input.witness))
            .collect();
        let scalars: Vec<_> = scalars?.into_iter().cloned().collect();

        let (res_x, res_y) = self.encrypt(scalars, 0).map_err(|err| {
            OpcodeResolutionError::BlackBoxFunctionFailed(BlackBoxFunc::Pedersen, err.to_string())
        })?;
        initial_witness.insert(outputs[0], res_x);
        initial_witness.insert(outputs[1], res_y);
        Ok(OpcodeResolution::Solved)
    }

    fn fixed_base_scalar_mul(
        &self,
        initial_witness: &mut WitnessMap,
        input: &FunctionInput,
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        let scalar = witness_to_value(initial_witness, input.witness)?;

        let (pub_x, pub_y) = self.fixed_base(scalar).map_err(|err| {
            OpcodeResolutionError::BlackBoxFunctionFailed(
                BlackBoxFunc::FixedBaseScalarMul,
                err.to_string(),
            )
        })?;

        initial_witness.insert(outputs[0], pub_x);
        initial_witness.insert(outputs[1], pub_y);
        Ok(OpcodeResolution::Solved)
    }
}
