use acvm::acir::circuit::opcodes::FunctionInput;
use acvm::acir::native_types::{Witness, WitnessMap};
use acvm::acir::BlackBoxFunc;
use acvm::pwg::{insert_value, witness_to_value, OpcodeResolution, OpcodeResolutionError};
use acvm::{FieldElement, PartialWitnessGenerator};

use crate::pedersen::Pedersen;
use crate::scalar_mul::ScalarMul;
use crate::schnorr::SchnorrSig;
use crate::Barretenberg;

impl PartialWitnessGenerator for Barretenberg {
    fn schnorr_verify(
        &self,
        initial_witness: &mut WitnessMap,
        public_key_x: FunctionInput,
        public_key_y: FunctionInput,
        signature_s: FunctionInput,
        signature_e: FunctionInput,
        message: &[FunctionInput],
        output: Witness,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        // In barretenberg, if the signature fails, then the whole thing fails.

        let pub_key_x: Vec<u8> =
            witness_to_value(initial_witness, public_key_x.witness)?.to_be_bytes();
        let pub_key_y: Vec<u8> =
            witness_to_value(initial_witness, public_key_y.witness)?.to_be_bytes();

        let pub_key_bytes: Vec<u8> = pub_key_x.iter().copied().chain(pub_key_y).collect();
        let pub_key: [u8; 64] = pub_key_bytes.try_into().map_err(|v: Vec<u8>| {
            OpcodeResolutionError::BlackBoxFunctionFailed(
                BlackBoxFunc::SchnorrVerify,
                format!("expected pubkey size {} but received {}", 64, v.len()),
            )
        })?;

        let signature_s: [u8; 32] = witness_to_value(initial_witness, signature_s.witness)?
            .to_be_bytes()
            .try_into()
            .map_err(|v: Vec<u8>| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    format!("expected signature_s size {} but received {}", 32, v.len()),
                )
            })?;
        let signature_e: [u8; 32] = witness_to_value(initial_witness, signature_e.witness)?
            .to_be_bytes()
            .try_into()
            .map_err(|v: Vec<u8>| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    format!("expected signature_3 size {} but received {}", 32, v.len()),
                )
            })?;

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
            .verify_signature(pub_key, signature_s, signature_e, &message_bytes)
            .map_err(|err| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    err.to_string(),
                )
            })?;
        if !valid_signature {
            dbg!("signature has failed to verify");
        }

        insert_value(
            &output,
            FieldElement::from(valid_signature),
            initial_witness,
        )?;
        Ok(OpcodeResolution::Solved)
    }

    fn pedersen(
        &self,
        initial_witness: &mut WitnessMap,
        inputs: &[FunctionInput],
        domain_separator: u32,
        outputs: (Witness, Witness),
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        let scalars: Result<Vec<_>, _> = inputs
            .iter()
            .map(|input| witness_to_value(initial_witness, input.witness))
            .collect();
        let scalars: Vec<_> = scalars?.into_iter().cloned().collect();

        let (res_x, res_y) = self.encrypt(scalars, domain_separator).map_err(|err| {
            OpcodeResolutionError::BlackBoxFunctionFailed(BlackBoxFunc::Pedersen, err.to_string())
        })?;
        insert_value(&outputs.0, res_x, initial_witness)?;
        insert_value(&outputs.1, res_y, initial_witness)?;
        Ok(OpcodeResolution::Solved)
    }

    fn fixed_base_scalar_mul(
        &self,
        initial_witness: &mut WitnessMap,
        input: FunctionInput,
        outputs: (Witness, Witness),
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        let scalar = witness_to_value(initial_witness, input.witness)?;

        let (pub_x, pub_y) = self.fixed_base(scalar).map_err(|err| {
            OpcodeResolutionError::BlackBoxFunctionFailed(
                BlackBoxFunc::FixedBaseScalarMul,
                err.to_string(),
            )
        })?;

        insert_value(&outputs.0, pub_x, initial_witness)?;
        insert_value(&outputs.1, pub_y, initial_witness)?;
        Ok(OpcodeResolution::Solved)
    }
}
