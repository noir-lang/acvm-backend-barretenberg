// Aztec uses a `TurboFormat` object in order to bridge the gap between Rust and C++.
// This serializer converts the IR into the `TurboFormat` which can then be fed into the WASM file
use crate::barretenberg_structures::{
    Blake2sConstraint, Constraint, ConstraintSystem, EcdsaConstraint, FixedBaseScalarMulConstraint,
    HashToFieldConstraint, LogicConstraint, MerkleMembershipConstraint, PedersenConstraint,
    RangeConstraint, SchnorrConstraint, Sha256Constraint,
};
use acvm::acir::circuit::{Circuit, Opcode};
use acvm::acir::native_types::Expression;
use acvm::acir::BlackBoxFunc;
use acvm::FieldElement;

/// Converts an `IR` into the `StandardFormat` constraint system
pub fn serialize_circuit(circuit: &Circuit) -> ConstraintSystem {
    // Create constraint system
    let mut constraints: Vec<Constraint> = Vec::new();
    let mut range_constraints: Vec<RangeConstraint> = Vec::new();
    let mut logic_constraints: Vec<LogicConstraint> = Vec::new();
    let mut sha256_constraints: Vec<Sha256Constraint> = Vec::new();
    let mut blake2s_constraints: Vec<Blake2sConstraint> = Vec::new();
    let mut pedersen_constraints: Vec<PedersenConstraint> = Vec::new();
    let mut merkle_membership_constraints: Vec<MerkleMembershipConstraint> = Vec::new();
    let mut schnorr_constraints: Vec<SchnorrConstraint> = Vec::new();
    let mut ecdsa_secp256k1_constraints: Vec<EcdsaConstraint> = Vec::new();
    let mut fixed_base_scalar_mul_constraints: Vec<FixedBaseScalarMulConstraint> = Vec::new();
    let mut hash_to_field_constraints: Vec<HashToFieldConstraint> = Vec::new();

    for gate in circuit.opcodes.iter() {
        match gate {
            Opcode::Arithmetic(expression) => {
                let constraint = serialize_arithmetic_gates(expression);
                constraints.push(constraint);
            }
            Opcode::BlackBoxFuncCall(gadget_call) => {
                match gadget_call.name {
                    BlackBoxFunc::RANGE => {
                        assert_eq!(gadget_call.inputs.len(), 1);
                        assert_eq!(gadget_call.outputs.len(), 0);

                        let function_input = &gadget_call.inputs[0];
                        let witness = function_input.witness;
                        let num_bits = function_input.num_bits;

                        let range_constraint = RangeConstraint {
                            a: witness.witness_index() as i32,
                            num_bits: num_bits as i32,
                        };
                        range_constraints.push(range_constraint);
                    }
                    BlackBoxFunc::AND | BlackBoxFunc::XOR => {
                        assert_eq!(gadget_call.inputs.len(), 2);
                        assert_eq!(gadget_call.outputs.len(), 1);

                        let function_input_lhs = &gadget_call.inputs[0];
                        let witness_lhs = function_input_lhs.witness;

                        let function_input_rhs = &gadget_call.inputs[1];
                        let witness_rhs = function_input_rhs.witness;

                        let function_output = &gadget_call.outputs[0];

                        assert_eq!(function_input_lhs.num_bits, function_input_rhs.num_bits);
                        let num_bits = function_input_rhs.num_bits;

                        if gadget_call.name == BlackBoxFunc::AND {
                            let and = LogicConstraint::and(
                                witness_lhs.witness_index() as i32,
                                witness_rhs.witness_index() as i32,
                                function_output.witness_index() as i32,
                                num_bits as i32,
                            );
                            logic_constraints.push(and);
                        } else if gadget_call.name == BlackBoxFunc::XOR {
                            let xor = LogicConstraint::xor(
                                witness_lhs.witness_index() as i32,
                                witness_rhs.witness_index() as i32,
                                function_output.witness_index() as i32,
                                num_bits as i32,
                            );
                            logic_constraints.push(xor);
                        } else {
                            unreachable!("expected either an AND or XOR opcode")
                        }
                    }
                    BlackBoxFunc::SHA256 => {
                        let mut sha256_inputs: Vec<(i32, i32)> = Vec::new();
                        for input in gadget_call.inputs.iter() {
                            let witness_index = input.witness.witness_index() as i32;
                            let num_bits = input.num_bits as i32;
                            sha256_inputs.push((witness_index, num_bits));
                        }

                        assert_eq!(gadget_call.outputs.len(), 32);

                        let mut outputs_iter = gadget_call.outputs.iter();
                        let mut result = [0i32; 32];
                        for (i, res) in result.iter_mut().enumerate() {
                            let out_byte = outputs_iter.next().unwrap_or_else(|| {
                                panic!("missing rest of output. Tried to get byte {i} but failed")
                            });

                            let out_byte_index = out_byte.witness_index() as i32;
                            *res = out_byte_index
                        }
                        let sha256_constraint = Sha256Constraint {
                            inputs: sha256_inputs,
                            result,
                        };

                        sha256_constraints.push(sha256_constraint);
                    }
                    BlackBoxFunc::Blake2s => {
                        let mut blake2s_inputs: Vec<(i32, i32)> = Vec::new();
                        for input in gadget_call.inputs.iter() {
                            let witness_index = input.witness.witness_index() as i32;
                            let num_bits = input.num_bits as i32;
                            blake2s_inputs.push((witness_index, num_bits));
                        }

                        assert_eq!(gadget_call.outputs.len(), 32);

                        let mut outputs_iter = gadget_call.outputs.iter();
                        let mut result = [0i32; 32];
                        for (i, res) in result.iter_mut().enumerate() {
                            let out_byte = outputs_iter.next().unwrap_or_else(|| {
                                panic!("missing rest of output. Tried to get byte {i} but failed")
                            });

                            let out_byte_index = out_byte.witness_index() as i32;
                            *res = out_byte_index
                        }
                        let blake2s_constraint = Blake2sConstraint {
                            inputs: blake2s_inputs,
                            result,
                        };

                        blake2s_constraints.push(blake2s_constraint);
                    }
                    BlackBoxFunc::MerkleMembership => {
                        let mut inputs_iter = gadget_call.inputs.iter().peekable();

                        // root
                        let root = {
                            let root_input = inputs_iter.next().expect("missing Merkle root");
                            root_input.witness.witness_index() as i32
                        };
                        // leaf
                        let leaf = {
                            let leaf_input = inputs_iter
                                .next()
                                .expect("missing leaf to check membership for");
                            leaf_input.witness.witness_index() as i32
                        };
                        // index
                        let index = {
                            let index_input = inputs_iter.next().expect("missing index for leaf");
                            index_input.witness.witness_index() as i32
                        };

                        if inputs_iter.peek().is_none() {
                            unreachable!("cannot check membership without a hash path")
                        }

                        let mut hash_path = Vec::new();
                        for path_elem in inputs_iter {
                            let path_elem_index = path_elem.witness.witness_index() as i32;

                            hash_path.push(path_elem_index);
                        }

                        // result
                        let result = gadget_call.outputs[0].witness_index() as i32;

                        let constraint = MerkleMembershipConstraint {
                            hash_path,
                            root,
                            leaf,
                            index,
                            result,
                        };

                        merkle_membership_constraints.push(constraint);
                    }
                    BlackBoxFunc::SchnorrVerify => {
                        let mut inputs_iter = gadget_call.inputs.iter();

                        // pub_key_x
                        let public_key_x = {
                            let pub_key_x = inputs_iter
                                .next()
                                .expect("missing `x` component for public key");
                            pub_key_x.witness.witness_index() as i32
                        };
                        // pub_key_y
                        let public_key_y = {
                            let pub_key_y = inputs_iter
                                .next()
                                .expect("missing `y` component for public key");
                            pub_key_y.witness.witness_index() as i32
                        };
                        // signature
                        let mut signature = [0i32; 64];
                        for (i, sig) in signature.iter_mut().enumerate() {
                            let sig_byte = inputs_iter.next().unwrap_or_else(|| {
                                panic!(
                                    "missing rest of signature. Tried to get byte {i} but failed",
                                )
                            });
                            let sig_byte_index = sig_byte.witness.witness_index() as i32;
                            *sig = sig_byte_index
                        }

                        // The rest of the input is the message
                        let mut message = Vec::new();
                        for msg in inputs_iter {
                            let msg_byte_index = msg.witness.witness_index() as i32;
                            message.push(msg_byte_index);
                        }

                        // result
                        let result = gadget_call.outputs[0].witness_index() as i32;

                        let constraint = SchnorrConstraint {
                            message,
                            signature,
                            public_key_x,
                            public_key_y,
                            result,
                        };

                        schnorr_constraints.push(constraint);
                    }
                    BlackBoxFunc::Pedersen => {
                        let mut inputs = Vec::new();
                        for scalar in gadget_call.inputs.iter() {
                            let scalar_index = scalar.witness.witness_index() as i32;
                            inputs.push(scalar_index);
                        }

                        let result_x = gadget_call.outputs[0].witness_index() as i32;
                        let result_y = gadget_call.outputs[1].witness_index() as i32;

                        let constraint = PedersenConstraint {
                            inputs,
                            result_x,
                            result_y,
                        };

                        pedersen_constraints.push(constraint);
                    }
                    BlackBoxFunc::HashToField128Security => {
                        let mut hash_to_field_inputs: Vec<(i32, i32)> = Vec::new();
                        for input in gadget_call.inputs.iter() {
                            let witness_index = input.witness.witness_index() as i32;
                            let num_bits = input.num_bits as i32;
                            hash_to_field_inputs.push((witness_index, num_bits));
                        }

                        assert_eq!(gadget_call.outputs.len(), 1);

                        let result = gadget_call.outputs[0].witness_index() as i32;

                        let hash_to_field_constraint = HashToFieldConstraint {
                            inputs: hash_to_field_inputs,
                            result,
                        };

                        hash_to_field_constraints.push(hash_to_field_constraint);
                    }
                    BlackBoxFunc::EcdsaSecp256k1 => {
                        let mut inputs_iter = gadget_call.inputs.iter();

                        // public key x
                        let mut public_key_x = [0i32; 32];
                        for (i, pkx) in public_key_x.iter_mut().enumerate() {
                            let x_byte = inputs_iter.next().unwrap_or_else(|| panic!("missing rest of x component for public key. Tried to get byte {i} but failed"));
                            let x_byte_index = x_byte.witness.witness_index() as i32;
                            *pkx = x_byte_index;
                        }

                        // public key y
                        let mut public_key_y = [0i32; 32];
                        for (i, pky) in public_key_y.iter_mut().enumerate() {
                            let y_byte = inputs_iter.next().unwrap_or_else(|| panic!("missing rest of y component for public key. Tried to get byte {i} but failed"));
                            let y_byte_index = y_byte.witness.witness_index() as i32;
                            *pky = y_byte_index;
                        }

                        // signature
                        let mut signature = [0i32; 64];
                        for (i, sig) in signature.iter_mut().enumerate() {
                            let sig_byte = inputs_iter.next().unwrap_or_else(|| {
                                panic!(
                                    "missing rest of signature. Tried to get byte {i} but failed",
                                )
                            });
                            let sig_byte_index = sig_byte.witness.witness_index() as i32;
                            *sig = sig_byte_index;
                        }

                        // The rest of the input is the message
                        let mut hashed_message = Vec::new();
                        for msg in inputs_iter {
                            let msg_byte_index = msg.witness.witness_index() as i32;
                            hashed_message.push(msg_byte_index);
                        }

                        // result
                        let result = gadget_call.outputs[0].witness_index() as i32;

                        let constraint = EcdsaConstraint {
                            hashed_message,
                            signature,
                            public_key_x,
                            public_key_y,
                            result,
                        };

                        ecdsa_secp256k1_constraints.push(constraint);
                    }
                    BlackBoxFunc::FixedBaseScalarMul => {
                        assert_eq!(gadget_call.inputs.len(), 1);
                        let scalar = gadget_call.inputs[0].witness.witness_index() as i32;

                        assert_eq!(gadget_call.outputs.len(), 2);
                        let pubkey_x = gadget_call.outputs[0].witness_index() as i32;
                        let pubkey_y = gadget_call.outputs[1].witness_index() as i32;

                        let fixed_base_scalar_mul = FixedBaseScalarMulConstraint {
                            scalar,
                            pubkey_x,
                            pubkey_y,
                        };

                        fixed_base_scalar_mul_constraints.push(fixed_base_scalar_mul);
                    }
                    BlackBoxFunc::Keccak256 => panic!("Keccak256 has not yet been implemented"),
                    BlackBoxFunc::AES => panic!("AES has not yet been implemented"),
                };
            }
            Opcode::Directive(_) | Opcode::Block(_, _) => {
                // Directives and Blocks are only needed by the pwg
            }
        }
    }

    // Create constraint system
    ConstraintSystem {
        var_num: circuit.current_witness_index + 1, // number of witnesses is the witness index + 1;
        public_inputs: circuit.public_inputs.indices(),
        logic_constraints,
        range_constraints,
        sha256_constraints,
        merkle_membership_constraints,
        pedersen_constraints,
        schnorr_constraints,
        ecdsa_secp256k1_constraints,
        blake2s_constraints,
        hash_to_field_constraints,
        constraints,
        fixed_base_scalar_mul_constraints,
    }
}

#[allow(non_snake_case)]
fn serialize_arithmetic_gates(gate: &Expression) -> Constraint {
    let mut a: i32 = 0;
    let mut b: i32 = 0;
    let mut c: i32 = 0;
    let mut qm: FieldElement = FieldElement::zero();
    let mut ql: FieldElement = FieldElement::zero();
    let mut qr: FieldElement = FieldElement::zero();
    let mut qo: FieldElement = FieldElement::zero();

    // check mul gate
    if !gate.mul_terms.is_empty() {
        let mul_term = &gate.mul_terms[0];
        qm = mul_term.0;

        // Get wL term
        let wL = &mul_term.1;
        a = wL.witness_index() as i32;

        // Get wR term
        let wR = &mul_term.2;
        b = wR.witness_index() as i32;
    }

    // If there is only one simplified fan term,
    // then put it in qO * wO
    // This is in case, the qM term is non-zero
    if gate.linear_combinations.len() == 1 {
        let qO_wO_term = &gate.linear_combinations[0];
        qo = qO_wO_term.0;

        let wO = &qO_wO_term.1;
        c = wO.witness_index() as i32;
    }

    // XXX: This is a code smell. Refactor to be better. Maybe change Barretenberg to take vectors
    // If there is more than one term,
    // Then add normally
    if gate.linear_combinations.len() == 2 {
        let qL_wL_term = &gate.linear_combinations[0];
        ql = qL_wL_term.0;

        let wL = &qL_wL_term.1;
        a = wL.witness_index() as i32;

        let qR_wR_term = &gate.linear_combinations[1];
        qr = qR_wR_term.0;

        let wR = &qR_wR_term.1;
        b = wR.witness_index() as i32;
    }

    if gate.linear_combinations.len() == 3 {
        let qL_wL_term = &gate.linear_combinations[0];
        ql = qL_wL_term.0;

        let wL = &qL_wL_term.1;
        a = wL.witness_index() as i32;

        let qR_wR_term = &gate.linear_combinations[1];
        qr = qR_wR_term.0;

        let wR = &qR_wR_term.1;
        b = wR.witness_index() as i32;

        let qO_wO_term = &gate.linear_combinations[2];
        qo = qO_wO_term.0;

        let wO = &qO_wO_term.1;
        c = wO.witness_index() as i32;
    }

    // Add the qc term
    let qc = gate.q_c;

    Constraint {
        a,
        b,
        c,
        qm,
        ql,
        qr,
        qo,
        qc,
    }
}
