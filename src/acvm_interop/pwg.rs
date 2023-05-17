use acvm::acir::circuit::opcodes::FunctionInput;
use acvm::acir::native_types::{Witness, WitnessMap};
use acvm::acir::BlackBoxFunc;
use acvm::pwg::{hash, logic, range, signature, witness_to_value};
use acvm::{pwg::OpcodeResolution, FieldElement};
use acvm::{OpcodeResolutionError, PartialWitnessGenerator};

use crate::pedersen::Pedersen;
use crate::recursion::Recursion;
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

    fn verify_proof(
        &self,
        initial_witness: &mut WitnessMap,
        key: &[FunctionInput],
        proof: &[FunctionInput],
        public_inputs: &[FunctionInput],
        key_hash: &FunctionInput,
        input_aggregation_object: &[FunctionInput],
        // TODO: might not need this at all as the current bberg impl fetches it from the verification key
        _nested_aggregation_object: &[FunctionInput],
        outputs: &[Witness],
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        // Sanity check that we have the correct aggregation object size
        assert_eq!(input_aggregation_object.len(), 16);
        assert_eq!(outputs.len(), 16);

        let mut key_iter = key.iter();
        let mut key_array = [FieldElement::zero(); 114];
        for (i, vk_i) in key_array.iter_mut().enumerate() {
            // TODO: change these to ok_or_else
            let _vk_i = key_iter.next().unwrap_or_else(|| {
                panic!("missing rest of vkey. Tried to get field {i} but failed")
            });
            *vk_i = *witness_to_value(initial_witness, _vk_i.witness)?;
        }
        let key = key_array.to_vec();

        let num_public_inputs = public_inputs.len();

        let mut proof_iter = proof.iter();
        let mut proof = Vec::with_capacity(93 + num_public_inputs);
        for (i, proof_i) in proof.iter_mut().enumerate() {
            let _proof_i = proof_iter.next().unwrap_or_else(|| {
                panic!("missing rest of proof. Tried to get field {i} but failed")
            });
            *proof_i = *witness_to_value(initial_witness, _proof_i.witness)?;
        }

        let mut public_inputs_iter = public_inputs.iter();
        let mut public_inputs = Vec::with_capacity(num_public_inputs);
        for (i, public_input_i) in public_inputs.iter_mut().enumerate() {
            let _public_input_i = public_inputs_iter.next().unwrap_or_else(|| {
                panic!("missing rest of proof. Tried to get field {i} but failed")
            });
            *public_input_i = *witness_to_value(initial_witness, _public_input_i.witness)?;
        }

        let key_hash = witness_to_value(initial_witness, key_hash.witness)?.to_be_bytes();

        let mut input_agg_obj_iter = input_aggregation_object.iter();
        let mut input_aggregation_object = [FieldElement::zero(); 16];
        for (i, var_i) in input_aggregation_object.iter_mut().enumerate() {
            let _var_i = input_agg_obj_iter.next().unwrap_or_else(|| {
                panic!("missing rest of proof. Tried to get field {i} but failed")
            });
            *var_i = *witness_to_value(initial_witness, _var_i.witness)?;
        }

        // TODO: nested aggregation object should be a part of the verification key
        // and be unnecessary to accept as inputs/outputs

        let output_aggregation_object = self.verify_proof_(
            key,
            proof,
            num_public_inputs as u32,
            input_aggregation_object,
        );

        for i in 0..output_aggregation_object.len() {
            initial_witness.insert(outputs[i], output_aggregation_object[i]);
        }
        Ok(OpcodeResolution::Solved)
    }
}
