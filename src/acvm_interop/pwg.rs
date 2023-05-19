use acvm::acir::circuit::opcodes::FunctionInput;
use acvm::acir::native_types::{Witness, WitnessMap};
use acvm::acir::BlackBoxFunc;
use acvm::pwg::{hash, logic, range, signature, witness_to_value};
use acvm::{pwg::OpcodeResolution, FieldElement};
use acvm::{OpcodeResolutionError, PartialWitnessGenerator};

use crate::pedersen::Pedersen;
use crate::scalar_mul::ScalarMul;
use crate::schnorr::SchnorrSig;
use crate::Barretenberg;

mod merkle;

impl PartialWitnessGenerator for Barretenberg {
    fn aes(
        &self,
        _initial_witness: &mut WitnessMap,
        _inputs: &[FunctionInput],
        _outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        Err(OpcodeResolutionError::UnsupportedBlackBoxFunc(
            BlackBoxFunc::AES,
        ))
    }

    fn and(
        &self,
        initial_witness: &mut WitnessMap,
        lhs: &FunctionInput,
        rhs: &FunctionInput,
        output: &Witness,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        logic::and(initial_witness, lhs, rhs, output)
    }

    fn xor(
        &self,
        initial_witness: &mut WitnessMap,
        lhs: &FunctionInput,
        rhs: &FunctionInput,
        output: &Witness,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        logic::xor(initial_witness, lhs, rhs, output)
    }

    fn range(
        &self,
        initial_witness: &mut WitnessMap,
        input: &FunctionInput,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        range::solve_range_opcode(initial_witness, input)
    }

    fn sha256(
        &self,
        initial_witness: &mut WitnessMap,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        hash::sha256(initial_witness, inputs, outputs)
    }

    fn blake2s(
        &self,
        initial_witness: &mut WitnessMap,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        hash::blake2s256(initial_witness, inputs, outputs)
    }

    fn compute_merkle_root(
        &self,
        initial_witness: &mut WitnessMap,
        leaf: &FunctionInput,
        index: &FunctionInput,
        hash_path: &[FunctionInput],
        output: &Witness,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        let leaf = witness_to_value(initial_witness, leaf.witness)?;

        let index = witness_to_value(initial_witness, index.witness)?;

        let hash_path: Result<Vec<_>, _> = hash_path
            .iter()
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

        initial_witness.insert(*output, computed_merkle_root);
        Ok(OpcodeResolution::Solved)
    }

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

        fn to_u8_vec(
            initial_witness: &WitnessMap,
            inputs: &[FunctionInput],
        ) -> Result<Vec<u8>, OpcodeResolutionError> {
            let mut result = Vec::with_capacity(inputs.len());
            for input in inputs {
                let witness_value_bytes =
                    witness_to_value(initial_witness, input.witness)?.to_be_bytes();
                let byte: &u8 = witness_value_bytes.last().ok_or_else(|| {
                    OpcodeResolutionError::BlackBoxFunctionFailed(
                        BlackBoxFunc::SchnorrVerify,
                        "could not get last byte".into(),
                    )
                })?;
                result.push(*byte);
            }
            Ok(result)
        }

        let pub_key_x = witness_to_value(initial_witness, public_key_x.witness)?.to_be_bytes();
        let pub_key_y = witness_to_value(initial_witness, public_key_y.witness)?.to_be_bytes();

        let pub_key_bytes: Vec<u8> = pub_key_x.iter().copied().chain(pub_key_y).collect();
        let pub_key: [u8; 64] = pub_key_bytes.try_into().map_err(|v: Vec<u8>| {
            OpcodeResolutionError::BlackBoxFunctionFailed(
                BlackBoxFunc::SchnorrVerify,
                format!("expected pubkey size {} but received {}", 64, v.len()),
            )
        })?;

        let signature_bytes: [u8; 64] =
            to_u8_vec(initial_witness, signature)?
                .try_into()
                .map_err(|v: Vec<u8>| {
                    OpcodeResolutionError::BlackBoxFunctionFailed(
                        BlackBoxFunc::SchnorrVerify,
                        format!("expected signature size {} but received {}", 64, v.len()),
                    )
                })?;

        let sig_s: [u8; 32] = signature_bytes[0..32]
            .try_into()
            .expect("bisecting 64 element array into 2 32 element arrays");
        let sig_e: [u8; 32] = signature_bytes[32..64]
            .try_into()
            .expect("bisecting 64 element array into 2 32 element arrays");

        let message_bytes = to_u8_vec(initial_witness, message)?;

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

    fn hash_to_field_128_security(
        &self,
        initial_witness: &mut WitnessMap,
        inputs: &[FunctionInput],
        output: &Witness,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        hash::hash_to_field_128_security(initial_witness, inputs, output)
    }

    fn ecdsa_secp256k1(
        &self,
        initial_witness: &mut WitnessMap,
        public_key_x: &[FunctionInput],
        public_key_y: &[FunctionInput],
        signature: &[FunctionInput],
        message: &[FunctionInput],
        outputs: &Witness,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        signature::ecdsa::secp256k1_prehashed(
            initial_witness,
            public_key_x,
            public_key_y,
            signature,
            message,
            *outputs,
        )
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

    fn keccak256(
        &self,
        initial_witness: &mut WitnessMap,
        inputs: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        hash::keccak256(initial_witness, inputs, outputs)
    }
}
