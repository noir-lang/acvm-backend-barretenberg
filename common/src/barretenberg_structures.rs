use acvm::acir::circuit::{Circuit, Opcode};
use acvm::acir::native_types::Expression;
use acvm::acir::BlackBoxFunc;

pub use acvm::FieldElement as Scalar;

#[derive(Debug, Clone)]
pub struct Assignments(Vec<Scalar>);
pub type WitnessAssignments = Assignments;

// This is a separate impl so the constructor can get the wasm_bindgen macro in the future
impl Assignments {
    pub fn new() -> Assignments {
        Assignments(vec![])
    }
}

impl Assignments {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let witness_len = self.0.len() as u32;
        buffer.extend_from_slice(&witness_len.to_be_bytes());

        for assignment in self.0.iter() {
            buffer.extend_from_slice(&assignment.to_be_bytes());
        }

        buffer
    }

    pub fn push_i32(&mut self, value: i32) {
        self.0.push(Scalar::from(value as i128));
    }
    pub fn push(&mut self, value: Scalar) {
        self.0.push(value);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl IntoIterator for Assignments {
    type Item = Scalar;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<Vec<Scalar>> for Assignments {
    fn from(w: Vec<Scalar>) -> Assignments {
        Assignments(w)
    }
}

impl Default for Assignments {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Hash, Debug)]
pub struct Constraint {
    pub a: i32,
    pub b: i32,
    pub c: i32,
    pub qm: Scalar,
    pub ql: Scalar,
    pub qr: Scalar,
    pub qo: Scalar,
    pub qc: Scalar,
}

impl Constraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        // serialize Wires
        buffer.extend_from_slice(&self.a.to_be_bytes());
        buffer.extend_from_slice(&self.b.to_be_bytes());
        buffer.extend_from_slice(&self.c.to_be_bytes());

        // serialize selectors
        buffer.extend_from_slice(&self.qm.to_be_bytes());
        buffer.extend_from_slice(&self.ql.to_be_bytes());
        buffer.extend_from_slice(&self.qr.to_be_bytes());
        buffer.extend_from_slice(&self.qo.to_be_bytes());
        buffer.extend_from_slice(&self.qc.to_be_bytes());

        buffer
    }
}

#[derive(Clone, Hash, Debug)]
pub struct RangeConstraint {
    pub a: i32,
    pub num_bits: i32,
}

impl RangeConstraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        // Serializing Wires
        buffer.extend_from_slice(&self.a.to_be_bytes());
        buffer.extend_from_slice(&self.num_bits.to_be_bytes());

        buffer
    }
}
#[derive(Clone, Hash, Debug)]
pub struct EcdsaConstraint {
    pub hashed_message: Vec<i32>,
    pub signature: [i32; 64],
    pub public_key_x: [i32; 32],
    pub public_key_y: [i32; 32],
    pub result: i32,
}

impl EcdsaConstraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let message_len = (self.hashed_message.len()) as u32;
        buffer.extend_from_slice(&message_len.to_be_bytes());
        for constraint in self.hashed_message.iter() {
            buffer.extend_from_slice(&constraint.to_be_bytes());
        }

        let sig_len = (self.signature.len()) as u32;
        buffer.extend_from_slice(&sig_len.to_be_bytes());
        for sig_byte in self.signature.iter() {
            buffer.extend_from_slice(&sig_byte.to_be_bytes());
        }

        let pub_key_x_len = (self.public_key_x.len()) as u32;
        buffer.extend_from_slice(&pub_key_x_len.to_be_bytes());
        for x_byte in self.public_key_x.iter() {
            buffer.extend_from_slice(&x_byte.to_be_bytes());
        }

        let pub_key_y_len = (self.public_key_y.len()) as u32;
        buffer.extend_from_slice(&pub_key_y_len.to_be_bytes());
        for y_byte in self.public_key_y.iter() {
            buffer.extend_from_slice(&y_byte.to_be_bytes());
        }

        buffer.extend_from_slice(&self.result.to_be_bytes());

        buffer
    }
}
#[derive(Clone, Hash, Debug)]
pub struct SchnorrConstraint {
    pub message: Vec<i32>,
    pub signature: [i32; 64],
    pub public_key_x: i32,
    pub public_key_y: i32,
    pub result: i32,
}

impl SchnorrConstraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let message_len = (self.message.len()) as u32;
        buffer.extend_from_slice(&message_len.to_be_bytes());
        for constraint in self.message.iter() {
            buffer.extend_from_slice(&constraint.to_be_bytes());
        }

        let sig_len = (self.signature.len()) as u32;
        buffer.extend_from_slice(&sig_len.to_be_bytes());
        for sig_byte in self.signature.iter() {
            buffer.extend_from_slice(&sig_byte.to_be_bytes());
        }

        buffer.extend_from_slice(&self.public_key_x.to_be_bytes());
        buffer.extend_from_slice(&self.public_key_y.to_be_bytes());
        buffer.extend_from_slice(&self.result.to_be_bytes());

        buffer
    }
}
#[derive(Clone, Hash, Debug)]
pub struct MerkleMembershipConstraint {
    pub hash_path: Vec<i32>,
    pub root: i32,
    pub leaf: i32,
    pub index: i32,
    pub result: i32,
}

impl MerkleMembershipConstraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let hash_path_len = self.hash_path.len() as u32;

        buffer.extend_from_slice(&hash_path_len.to_be_bytes());
        for constraint in self.hash_path.iter() {
            buffer.extend_from_slice(&constraint.to_be_bytes());
        }

        buffer.extend_from_slice(&self.root.to_be_bytes());
        buffer.extend_from_slice(&self.leaf.to_be_bytes());
        buffer.extend_from_slice(&self.result.to_be_bytes());
        buffer.extend_from_slice(&self.index.to_be_bytes());

        buffer
    }
}

#[derive(Clone, Hash, Debug)]
pub struct Sha256Constraint {
    pub inputs: Vec<(i32, i32)>,
    pub result: [i32; 32],
}

impl Sha256Constraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let inputs_len = self.inputs.len() as u32;
        buffer.extend_from_slice(&inputs_len.to_be_bytes());
        for constraint in self.inputs.iter() {
            buffer.extend_from_slice(&constraint.0.to_be_bytes());
            buffer.extend_from_slice(&constraint.1.to_be_bytes());
        }

        let result_len = self.result.len() as u32;
        buffer.extend_from_slice(&result_len.to_be_bytes());
        for constraint in self.result.iter() {
            buffer.extend_from_slice(&constraint.to_be_bytes());
        }

        buffer
    }
}
#[derive(Clone, Hash, Debug)]
pub struct Blake2sConstraint {
    pub inputs: Vec<(i32, i32)>,
    pub result: [i32; 32],
}

impl Blake2sConstraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let inputs_len = self.inputs.len() as u32;
        buffer.extend_from_slice(&inputs_len.to_be_bytes());
        for constraint in self.inputs.iter() {
            buffer.extend_from_slice(&constraint.0.to_be_bytes());
            buffer.extend_from_slice(&constraint.1.to_be_bytes());
        }

        let result_len = self.result.len() as u32;
        buffer.extend_from_slice(&result_len.to_be_bytes());
        for constraint in self.result.iter() {
            buffer.extend_from_slice(&constraint.to_be_bytes());
        }

        buffer
    }
}
#[derive(Clone, Hash, Debug)]
pub struct HashToFieldConstraint {
    pub inputs: Vec<(i32, i32)>,
    pub result: i32,
}

impl HashToFieldConstraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let inputs_len = self.inputs.len() as u32;
        buffer.extend_from_slice(&inputs_len.to_be_bytes());
        for constraint in self.inputs.iter() {
            buffer.extend_from_slice(&constraint.0.to_be_bytes());
            buffer.extend_from_slice(&constraint.1.to_be_bytes());
        }

        buffer.extend_from_slice(&self.result.to_be_bytes());

        buffer
    }
}
#[derive(Clone, Hash, Debug)]
pub struct PedersenConstraint {
    pub inputs: Vec<i32>,
    pub result_x: i32,
    pub result_y: i32,
}

impl PedersenConstraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let inputs_len = self.inputs.len() as u32;
        buffer.extend_from_slice(&inputs_len.to_be_bytes());
        for constraint in self.inputs.iter() {
            buffer.extend_from_slice(&constraint.to_be_bytes());
        }

        buffer.extend_from_slice(&self.result_x.to_be_bytes());
        buffer.extend_from_slice(&self.result_y.to_be_bytes());

        buffer
    }
}
#[derive(Clone, Hash, Debug)]
pub struct FixedBaseScalarMulConstraint {
    pub scalar: i32,
    pub pubkey_x: i32,
    pub pubkey_y: i32,
}

impl FixedBaseScalarMulConstraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        // Serializing Wires
        buffer.extend_from_slice(&self.scalar.to_be_bytes());
        buffer.extend_from_slice(&self.pubkey_x.to_be_bytes());
        buffer.extend_from_slice(&self.pubkey_y.to_be_bytes());

        buffer
    }
}

#[derive(Clone, Hash, Debug)]
pub struct LogicConstraint {
    pub a: i32,
    pub b: i32,
    pub result: i32,
    pub num_bits: i32,
    pub is_xor_gate: bool,
}

impl LogicConstraint {
    pub fn and(a: i32, b: i32, result: i32, num_bits: i32) -> LogicConstraint {
        LogicConstraint {
            a,
            b,
            result,
            num_bits,
            is_xor_gate: false,
        }
    }
    pub fn xor(a: i32, b: i32, result: i32, num_bits: i32) -> LogicConstraint {
        LogicConstraint {
            a,
            b,
            result,
            num_bits,
            is_xor_gate: true,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        // Serializing Wires
        buffer.extend_from_slice(&self.a.to_be_bytes());
        buffer.extend_from_slice(&self.b.to_be_bytes());
        buffer.extend_from_slice(&self.result.to_be_bytes());
        buffer.extend_from_slice(&self.num_bits.to_be_bytes());
        buffer.extend_from_slice(&i32::to_be_bytes(self.is_xor_gate as i32));

        buffer
    }
}

#[derive(Clone, Hash, Debug)]
pub struct RecursionConstraint {
    pub key: Vec<i32>,   // UP size is 115
    pub proof: Vec<i32>, // UP size is 94
    pub public_input: i32,
    pub key_hash: i32,
    pub input_aggregation_object: [i32; 16],
    pub output_aggregation_object: [i32; 16],
}

impl RecursionConstraint {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        let vk_len = (self.key.len()) as u32;
        buffer.extend_from_slice(&vk_len.to_be_bytes());
        for constraint in self.key.iter() {
            buffer.extend_from_slice(&constraint.to_be_bytes());
        }

        let proof_len = (self.proof.len()) as u32;
        buffer.extend_from_slice(&proof_len.to_be_bytes());
        for constraint in self.proof.iter() {
            buffer.extend_from_slice(&constraint.to_be_bytes());
        }

        buffer.extend_from_slice(&self.public_input.to_be_bytes());

        buffer.extend_from_slice(&self.key_hash.to_be_bytes());

        // The aggregation objects are both array's in barretenberg
        // Thus, we do not need to write the length
        for constraint in self.input_aggregation_object.iter() {
            buffer.extend_from_slice(&constraint.to_be_bytes());
        }

        for constraint in self.output_aggregation_object.iter() {
            buffer.extend_from_slice(&constraint.to_be_bytes());
        }

        buffer
    }
}

#[derive(Clone, Hash, Debug, Default)]
pub struct ConstraintSystem {
    var_num: u32,
    public_inputs: Vec<u32>,

    logic_constraints: Vec<LogicConstraint>,
    range_constraints: Vec<RangeConstraint>,
    sha256_constraints: Vec<Sha256Constraint>,
    merkle_membership_constraints: Vec<MerkleMembershipConstraint>,
    schnorr_constraints: Vec<SchnorrConstraint>,
    ecdsa_secp256k1_constraints: Vec<EcdsaConstraint>,
    blake2s_constraints: Vec<Blake2sConstraint>,
    pedersen_constraints: Vec<PedersenConstraint>,
    hash_to_field_constraints: Vec<HashToFieldConstraint>,
    fixed_base_scalar_mul_constraints: Vec<FixedBaseScalarMulConstraint>,
    recursion_constraints: Vec<RecursionConstraint>,
    constraints: Vec<Constraint>,
}

// This is a separate impl so the constructor can get the wasm_bindgen macro in the future
impl ConstraintSystem {
    pub fn new() -> Self {
        ConstraintSystem::default()
    }
}

// Builder-style impl, but we use all data types that can be defaulted so we don't need a separate builder struct
// TODO(blaine): Add #[cfg(test)] once this project is merged into a single crate
impl ConstraintSystem {
    pub fn var_num(mut self, var_num: u32) -> Self {
        self.var_num = var_num;
        self
    }

    pub fn public_inputs(mut self, public_inputs: Vec<u32>) -> Self {
        self.public_inputs = public_inputs;
        self
    }

    pub fn logic_constraints(mut self, logic_constraints: Vec<LogicConstraint>) -> Self {
        self.logic_constraints = logic_constraints;
        self
    }

    pub fn range_constraints(mut self, range_constraints: Vec<RangeConstraint>) -> Self {
        self.range_constraints = range_constraints;
        self
    }

    pub fn sha256_constraints(mut self, sha256_constraints: Vec<Sha256Constraint>) -> Self {
        self.sha256_constraints = sha256_constraints;
        self
    }

    pub fn merkle_membership_constraints(
        mut self,
        merkle_membership_constraints: Vec<MerkleMembershipConstraint>,
    ) -> Self {
        self.merkle_membership_constraints = merkle_membership_constraints;
        self
    }

    pub fn schnorr_constraints(mut self, schnorr_constraints: Vec<SchnorrConstraint>) -> Self {
        self.schnorr_constraints = schnorr_constraints;
        self
    }

    pub fn ecdsa_secp256k1_constraints(
        mut self,
        ecdsa_secp256k1_constraints: Vec<EcdsaConstraint>,
    ) -> Self {
        self.ecdsa_secp256k1_constraints = ecdsa_secp256k1_constraints;
        self
    }

    pub fn blake2s_constraints(mut self, blake2s_constraints: Vec<Blake2sConstraint>) -> Self {
        self.blake2s_constraints = blake2s_constraints;
        self
    }

    pub fn pedersen_constraints(mut self, pedersen_constraints: Vec<PedersenConstraint>) -> Self {
        self.pedersen_constraints = pedersen_constraints;
        self
    }

    pub fn hash_to_field_constraints(
        mut self,
        hash_to_field_constraints: Vec<HashToFieldConstraint>,
    ) -> Self {
        self.hash_to_field_constraints = hash_to_field_constraints;
        self
    }

    pub fn fixed_base_scalar_mul_constraints(
        mut self,
        fixed_base_scalar_mul_constraints: Vec<FixedBaseScalarMulConstraint>,
    ) -> Self {
        self.fixed_base_scalar_mul_constraints = fixed_base_scalar_mul_constraints;
        self
    }

    pub fn recursion_constraints(
        mut self,
        recursion_constraints: Vec<RecursionConstraint>,
    ) -> Self {
        self.recursion_constraints = recursion_constraints;
        self
    }

    pub fn constraints(mut self, constraints: Vec<Constraint>) -> Self {
        self.constraints = constraints;
        self
    }
}

impl ConstraintSystem {
    pub fn public_inputs_size(&self) -> usize {
        self.public_inputs.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();

        // Push lengths onto the buffer
        buffer.extend_from_slice(&self.var_num.to_be_bytes());

        let pi_len = self.public_inputs.len() as u32;
        buffer.extend_from_slice(&pi_len.to_be_bytes());
        for pub_input in self.public_inputs.iter() {
            buffer.extend_from_slice(&pub_input.to_be_bytes());
        }

        // Serialize each Logic constraint
        let logic_constraints_len = self.logic_constraints.len() as u32;
        buffer.extend_from_slice(&logic_constraints_len.to_be_bytes());
        for constraint in self.logic_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        // Serialize each Range constraint
        let range_constraints_len = self.range_constraints.len() as u32;
        buffer.extend_from_slice(&range_constraints_len.to_be_bytes());
        for constraint in self.range_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        // Serialize each Sha256 constraint
        let sha256_constraints_len = self.sha256_constraints.len() as u32;
        buffer.extend_from_slice(&sha256_constraints_len.to_be_bytes());
        for constraint in self.sha256_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        // Serialize each Merkle Membership constraint
        let merkle_membership_constraints_len = self.merkle_membership_constraints.len() as u32;
        buffer.extend_from_slice(&merkle_membership_constraints_len.to_be_bytes());
        for constraint in self.merkle_membership_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        // Serialize each Schnorr constraint
        let schnorr_len = self.schnorr_constraints.len() as u32;
        buffer.extend_from_slice(&schnorr_len.to_be_bytes());
        for constraint in self.schnorr_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        // Serialize each ECDSA constraint
        let ecdsa_len = self.ecdsa_secp256k1_constraints.len() as u32;
        buffer.extend_from_slice(&ecdsa_len.to_be_bytes());
        for constraint in self.ecdsa_secp256k1_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        // Serialize each Blake2s constraint
        let blake2s_len = self.blake2s_constraints.len() as u32;
        buffer.extend_from_slice(&blake2s_len.to_be_bytes());
        for constraint in self.blake2s_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        // Serialize each Pedersen constraint
        let pedersen_len = self.pedersen_constraints.len() as u32;
        buffer.extend_from_slice(&pedersen_len.to_be_bytes());
        for constraint in self.pedersen_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        // Serialize each HashToField constraint
        let h2f_len = self.hash_to_field_constraints.len() as u32;
        buffer.extend_from_slice(&h2f_len.to_be_bytes());
        for constraint in self.hash_to_field_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        // Serialize each HashToField constraint
        let fixed_base_scalar_mul_len = self.fixed_base_scalar_mul_constraints.len() as u32;
        buffer.extend_from_slice(&fixed_base_scalar_mul_len.to_be_bytes());
        for constraint in self.fixed_base_scalar_mul_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        let recursion_constraints_len = self.recursion_constraints.len() as u32;
        buffer.extend_from_slice(&recursion_constraints_len.to_be_bytes());
        for constraint in self.recursion_constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        // Serialize each Arithmetic constraint
        let constraints_len = self.constraints.len() as u32;
        buffer.extend_from_slice(&constraints_len.to_be_bytes());
        for constraint in self.constraints.iter() {
            buffer.extend(&constraint.to_bytes());
        }

        buffer
    }
}

impl From<&Circuit> for ConstraintSystem {
    /// Converts an `IR` into the `StandardFormat` constraint system
    fn from(circuit: &Circuit) -> Self {
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
        let mut recursion_constaints: Vec<RecursionConstraint> = Vec::new();

        for gate in circuit.opcodes.iter() {
            match gate {
                Opcode::Arithmetic(expression) => {
                    let constraint = serialize_arithmetic_gates(&expression);
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
                                    panic!(
                                        "missing rest of output. Tried to get byte {i} but failed"
                                    )
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
                                    panic!(
                                        "missing rest of output. Tried to get byte {i} but failed"
                                    )
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
                                let index_input =
                                    inputs_iter.next().expect("missing index for leaf");
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
                        BlackBoxFunc::VerifyProof => {
                            dbg!(gadget_call.inputs.len());
                            dbg!(gadget_call.outputs.len());
                            let mut inputs_iter = gadget_call.inputs.iter();

                            let mut key = Vec::with_capacity(115);
                            for (i, vk_witness) in key.iter_mut().enumerate() {
                                let vk_field = inputs_iter.next().unwrap_or_else(|| {
                                    panic!(
                                        "missing rest of vkey. Tried to get field {i} but failed"
                                    )
                                });
                                let vk_field_index = vk_field.witness.witness_index() as i32;
                                *vk_witness = vk_field_index;
                            }

                            let mut proof = Vec::with_capacity(94);
                            for (i, proof_witness) in proof.iter_mut().enumerate() {
                                let proof_field = inputs_iter.next().unwrap_or_else(|| {
                                    panic!(
                                        "missing rest of proof. Tried to get field {i} but failed"
                                    )
                                });
                                let proof_field_index = proof_field.witness.witness_index() as i32;
                                *proof_witness = proof_field_index;
                            }

                            let public_input = inputs_iter
                                .next()
                                .unwrap_or_else(|| panic!("there is no public input witness"))
                                .witness
                                .witness_index()
                                as i32;

                            // TODO: look into inserting this ourselves somewhere
                            // we shouldn't be exposing this to the user
                            let key_hash = inputs_iter
                                .next()
                                .unwrap_or_else(|| panic!("there is no key hash witness"))
                                .witness
                                .witness_index() as i32;

                            // TODO: there is no input aggregation object handled yet, so we assign every value in the object a witness index of `0`
                            let input_aggregation_object = [0i32; 16];

                            let mut outputs_iter = gadget_call.outputs.iter();

                            let mut output_aggregation_object = [0i32; 16];
                            for (i, var) in output_aggregation_object.iter_mut().enumerate() {
                                let var_field = outputs_iter.next().unwrap_or_else(|| panic!("missing rest of output aggregation object. Tried to get byte {i} but failed"));
                                let var_field_index = var_field.witness_index() as i32;
                                *var = var_field_index;
                            }

                            let recursion_constraint = RecursionConstraint {
                                key,
                                proof,
                                public_input,
                                key_hash,
                                input_aggregation_object,
                                output_aggregation_object,
                            };

                            recursion_constaints.push(recursion_constraint);
                        }
                        BlackBoxFunc::Keccak256 => panic!("Keccak256 has not yet been implemented"),
                        BlackBoxFunc::AES => panic!("AES has not yet been implemented"),
                    };
                }
                Opcode::Directive(_) | Opcode::Oracle(_) => {
                    // Directives & Oracles are only needed by the pwg
                }
                Opcode::Block(_) | Opcode::RAM(_) | Opcode::ROM(_) => {
                    // TODO: implement serialization to match BB's interface
                }
            }
        }

        // Create constraint system
        ConstraintSystem {
            var_num: circuit.current_witness_index + 1, // number of witnesses is the witness index + 1;
            public_inputs: circuit.public_inputs().indices(),
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
            recursion_constraints: vec![], // TODO: implement BlackBoxFunc::VerifyProof
            fixed_base_scalar_mul_constraints,
        }
    }
}

#[allow(non_snake_case)]
fn serialize_arithmetic_gates(gate: &Expression) -> Constraint {
    let mut a = 0;
    let mut b = 0;
    let mut c = 0;
    let mut qm = Scalar::zero();
    let mut ql = Scalar::zero();
    let mut qr = Scalar::zero();
    let mut qo = Scalar::zero();

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
