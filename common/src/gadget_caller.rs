use std::collections::BTreeMap;

use acvm::{
    acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness, BlackBoxFunc},
    pwg::{self, witness_to_value},
    FieldElement, OpcodeResolutionError,
};
use blake2::{Blake2s, Digest};

use crate::merkle::PathHasher;

// To avoid code duplication, we create a trait
// which encapsulates all of the shared methods
// that the PWG needs from Barretenberg
pub trait BarretenbergShared: PathHasher {
    fn new() -> Self;
    fn verify_signature(
        &mut self,
        pub_key: [u8; 64],
        sig: [u8; 64],
        message: &[u8],
    ) -> FieldElement;
    fn fixed_base(&mut self, input: &FieldElement) -> (FieldElement, FieldElement);
    fn encrypt(&mut self, inputs: Vec<FieldElement>) -> (FieldElement, FieldElement);
}

pub fn solve_blackbox_func_call<B: BarretenbergShared>(
    initial_witness: &mut BTreeMap<Witness, FieldElement>,
    gadget_call: &BlackBoxFuncCall,
) -> Result<(), OpcodeResolutionError> {
    match gadget_call.name {
        BlackBoxFunc::SHA256 => pwg::hash::sha256(initial_witness, gadget_call),
        BlackBoxFunc::Blake2s => pwg::hash::blake2s(initial_witness, gadget_call),
        BlackBoxFunc::EcdsaSecp256k1 => {
            pwg::signature::ecdsa::secp256k1_prehashed(initial_witness, gadget_call)?
        }
        BlackBoxFunc::AES => {
            return Err(OpcodeResolutionError::UnsupportedBlackBoxFunc(
                gadget_call.name,
            ))
        }
        BlackBoxFunc::MerkleMembership => {
            let mut inputs_iter = gadget_call.inputs.iter();

            let _root = inputs_iter.next().expect("expected a root");
            let root = witness_to_value(initial_witness, _root.witness)?;

            let _leaf = inputs_iter.next().expect("expected a leaf");
            let leaf = witness_to_value(initial_witness, _leaf.witness)?;

            let _index = inputs_iter.next().expect("expected an index");
            let index = witness_to_value(initial_witness, _index.witness)?;

            let hash_path: Result<Vec<_>, _> = inputs_iter
                .map(|input| witness_to_value(initial_witness, input.witness))
                .collect();

            let result = crate::merkle::check_membership::<B>(hash_path?, root, index, leaf);

            initial_witness.insert(gadget_call.outputs[0], result);
        }
        BlackBoxFunc::SchnorrVerify => {
            // In barretenberg, if the signature fails, then the whole thing fails.
            //

            let mut inputs_iter = gadget_call.inputs.iter();

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
            let pub_key: [u8; 64] = pub_key_bytes.try_into().unwrap();

            let mut signature = [0u8; 64];
            for (i, sig) in signature.iter_mut().enumerate() {
                let _sig_i = inputs_iter.next().unwrap_or_else(|| {
                    panic!("signature should be 64 bytes long, found only {i} bytes")
                });
                let sig_i = witness_to_value(initial_witness, _sig_i.witness)?;
                *sig = *sig_i.to_be_bytes().last().unwrap()
            }

            let mut message = Vec::new();
            for msg in inputs_iter {
                let msg_i_field = witness_to_value(initial_witness, msg.witness)?;
                let msg_i = *msg_i_field.to_be_bytes().last().unwrap();
                message.push(msg_i);
            }

            let mut barretenberg = <B as BarretenbergShared>::new();

            let result = barretenberg.verify_signature(pub_key, signature, &message);
            if result != FieldElement::one() {
                dbg!("signature has failed to verify");
            }

            initial_witness.insert(gadget_call.outputs[0], result);
        }
        BlackBoxFunc::Pedersen => {
            let inputs_iter = gadget_call.inputs.iter();

            let scalars: Result<Vec<_>, _> = inputs_iter
                .map(|input| witness_to_value(initial_witness, input.witness))
                .collect();
            let scalars: Vec<_> = scalars?.into_iter().cloned().collect();
            let mut barretenberg = <B as BarretenbergShared>::new();

            let (res_x, res_y) = barretenberg.encrypt(scalars);
            initial_witness.insert(gadget_call.outputs[0], res_x);
            initial_witness.insert(gadget_call.outputs[1], res_y);
        }
        BlackBoxFunc::HashToField128Security => {
            // Deal with Blake2s -- XXX: It's not possible for pwg to know that it is Blake2s
            // We need to get this method from the backend
            let mut hasher = <Blake2s as blake2::Digest>::new();

            // 0. For each input in the vector of inputs, check if we have their witness assignments (Can do this outside of match, since they all have inputs)
            for input_index in gadget_call.inputs.iter() {
                let witness = &input_index.witness;
                let num_bits = input_index.num_bits;

                let assignment = witness_to_value(initial_witness, *witness)?;

                let bytes = assignment.fetch_nearest_bytes(num_bits as usize);

                hasher.update(bytes);
            }
            let result = hasher.finalize();

            let reduced_res = FieldElement::from_be_bytes_reduce(&result);
            assert_eq!(gadget_call.outputs.len(), 1);

            initial_witness.insert(gadget_call.outputs[0], reduced_res);
        }
        BlackBoxFunc::FixedBaseScalarMul => {
            let scalar = witness_to_value(initial_witness, gadget_call.inputs[0].witness)?;

            let mut barretenberg = <B as BarretenbergShared>::new();
            let (pub_x, pub_y) = barretenberg.fixed_base(scalar);

            initial_witness.insert(gadget_call.outputs[0], pub_x);
            initial_witness.insert(gadget_call.outputs[1], pub_y);
        }
        BlackBoxFunc::AND | BlackBoxFunc::XOR => {
            acvm::pwg::logic::solve_logic_opcode(initial_witness, gadget_call)?
        }
        BlackBoxFunc::RANGE => acvm::pwg::range::solve_range_opcode(initial_witness, gadget_call)?,
    }
    Ok(())
}
