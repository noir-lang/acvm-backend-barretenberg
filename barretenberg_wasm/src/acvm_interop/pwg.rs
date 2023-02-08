use common::acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use common::acvm::FieldElement;
use common::acvm::PartialWitnessGenerator;
use std::collections::BTreeMap;

mod gadget_call;
pub mod merkle;

use self::gadget_call::GadgetCaller;
use super::Plonk;

impl PartialWitnessGenerator for Plonk {
    fn solve_black_box_function_call(
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        func_call: &BlackBoxFuncCall,
    ) -> Result<(), common::acvm::OpcodeResolutionError> {
        GadgetCaller::solve_blackbox_func_call(initial_witness, func_call)
    }
}
