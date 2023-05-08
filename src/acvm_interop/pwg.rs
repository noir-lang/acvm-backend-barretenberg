use acvm::acir::circuit::opcodes::FunctionInput;
use acvm::acir::BlackBoxFunc;
use acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use acvm::pwg::{hash, logic, range, signature, witness_to_value, OpcodeResolution};
use acvm::FieldElement;
use acvm::{OpcodeResolutionError, PartialWitnessGenerator};

use std::collections::BTreeMap;

use crate::pedersen::Pedersen;
use crate::scalar_mul::ScalarMul;
use crate::schnorr::SchnorrSig;
use crate::Barretenberg;

mod merkle;

impl PartialWitnessGenerator for Barretenberg {
    fn aes(
        &self,
        _initial_witness: &mut BTreeMap<Witness, FieldElement>,
        _inputs: &[FunctionInput],
        _outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        Err(OpcodeResolutionError::UnsupportedBlackBoxFunc(
            BlackBoxFunc::AES,
        ))
    }

    fn and(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        logic::and(
            initial_witness,
            &BlackBoxFuncCall {
                name: BlackBoxFunc::AND,
                inputs: inputs.to_vec(),
                outputs: outputs.to_vec(),
            },
        )
    }

    fn xor(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        logic::xor(
            initial_witness,
            &BlackBoxFuncCall {
                name: BlackBoxFunc::XOR,
                inputs: inputs.to_vec(),
                outputs: outputs.to_vec(),
            },
        )
    }

    fn range(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        range::solve_range_opcode(
            initial_witness,
            &BlackBoxFuncCall {
                name: BlackBoxFunc::RANGE,
                inputs: inputs.to_vec(),
                outputs: outputs.to_vec(),
            },
        )
    }

    fn sha256(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        hash::sha256(
            initial_witness,
            &BlackBoxFuncCall {
                name: BlackBoxFunc::SHA256,
                inputs: inputs.to_vec(),
                outputs: outputs.to_vec(),
            },
        )
    }

    fn blake2s(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        hash::blake2s256(
            initial_witness,
            &BlackBoxFuncCall {
                name: BlackBoxFunc::Blake2s,
                inputs: inputs.to_vec(),
                outputs: outputs.to_vec(),
            },
        )
    }

    fn compute_merkle_root(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        let mut inputs_iter = inputs.iter();

        let _leaf = inputs_iter.next().expect("expected a leaf");
        let leaf = witness_to_value(initial_witness, _leaf.witness)?;

        let _index = inputs_iter.next().expect("expected an index");
        let index = witness_to_value(initial_witness, _index.witness)?;

        let hash_path: Result<Vec<_>, _> = inputs_iter
            .map(|input| witness_to_value(initial_witness, input.witness))
            .collect();

        let computed_merkle_root = merkle::compute_merkle_root(
            |left, right| self.compress_native(left, right),
            hash_path?,
            index,
            leaf,
        )
        .map_err(|err| {
            OpcodeResolutionError::BlackBoxFunctionFailed(
                BlackBoxFunc::ComputeMerkleRoot,
                err.to_string(),
            )
        })?;

        initial_witness.insert(outputs[0], computed_merkle_root);
        Ok(OpcodeResolution::Solved)
    }

    fn schnorr_verify(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        // In barretenberg, if the signature fails, then the whole thing fails.

        let mut inputs_iter = inputs.iter();

        let _pub_key_x = inputs_iter
            .next()
            .expect("expected `x` component for public key");
        let pub_key_x = witness_to_value(initial_witness, _pub_key_x.witness)?.to_be_bytes();

        let _pub_key_y = inputs_iter
            .next()
            .expect("expected `y` component for public key");
        let pub_key_y = witness_to_value(initial_witness, _pub_key_y.witness)?.to_be_bytes();

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

        let mut sig_s: [u8; 32] = [0u8; 32];
        for (i, sig) in sig_s.iter_mut().enumerate() {
            let _sig_i = inputs_iter.next().ok_or_else(|| {
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
        let mut sig_e: [u8; 32] = [0u8; 32];
        for (i, sig) in sig_e.iter_mut().enumerate() {
            let _sig_i = inputs_iter.next().ok_or_else(|| {
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

        let mut message = Vec::new();
        for msg in inputs_iter {
            let msg_i_field = witness_to_value(initial_witness, msg.witness)?;
            let msg_i = *msg_i_field.to_be_bytes().last().ok_or_else(|| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    "could not get last bytes".into(),
                )
            })?;
            message.push(msg_i);
        }

        let valid_signature = self
            .verify_signature(pub_key, sig_s, sig_e, &message)
            .map_err(|err| {
                OpcodeResolutionError::BlackBoxFunctionFailed(
                    BlackBoxFunc::SchnorrVerify,
                    err.to_string(),
                )
            })?;
        if !valid_signature {
            dbg!("signature has failed to verify");
        }

        initial_witness.insert(outputs[0], FieldElement::from(valid_signature));
        Ok(OpcodeResolution::Solved)
    }

    fn pedersen(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        let scalars: Result<Vec<_>, _> = inputs
            .iter()
            .map(|input| witness_to_value(initial_witness, input.witness))
            .collect();
        let scalars: Vec<_> = scalars?.into_iter().cloned().collect();

        let (res_x, res_y) = self.encrypt(scalars).map_err(|err| {
            OpcodeResolutionError::BlackBoxFunctionFailed(BlackBoxFunc::Pedersen, err.to_string())
        })?;
        initial_witness.insert(outputs[0], res_x);
        initial_witness.insert(outputs[1], res_y);
        Ok(OpcodeResolution::Solved)
    }

    fn hash_to_field128_security(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        hash::hash_to_field_128_security(
            initial_witness,
            &BlackBoxFuncCall {
                name: BlackBoxFunc::HashToField128Security,
                inputs: inputs.to_vec(),
                outputs: outputs.to_vec(),
            },
        )
    }

    fn ecdsa_secp256k1(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        signature::ecdsa::secp256k1_prehashed(
            initial_witness,
            &BlackBoxFuncCall {
                name: BlackBoxFunc::EcdsaSecp256k1,
                inputs: inputs.to_vec(),
                outputs: outputs.to_vec(),
            },
        )
    }

    fn fixed_base_scalar_mul(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        let scalar = witness_to_value(initial_witness, inputs[0].witness)?;

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

    fn keccak256(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        hash::keccak256(
            initial_witness,
            &BlackBoxFuncCall {
                name: BlackBoxFunc::Keccak256,
                inputs: inputs.to_vec(),
                outputs: outputs.to_vec(),
            },
        )
    }
}
