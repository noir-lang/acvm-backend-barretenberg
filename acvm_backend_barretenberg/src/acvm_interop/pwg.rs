use common::acvm::acir::{circuit::opcodes::BlackBoxFuncCall, native_types::Witness};
use common::acvm::{FieldElement, OpcodeResolution};
use common::acvm::{OpcodeResolutionError, PartialWitnessGenerator};
use std::collections::BTreeMap;

mod black_box_functions;
mod merkle;

use self::black_box_functions::BlackBoxFuncCaller;
use super::Plonk;

impl PartialWitnessGenerator for Plonk {
    fn solve_black_box_function_call(
        &self,
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        func_call: &BlackBoxFuncCall,
    ) -> Result<OpcodeResolution, OpcodeResolutionError> {
        BlackBoxFuncCaller::solve_black_box_func_call(initial_witness, func_call)
    }
}
