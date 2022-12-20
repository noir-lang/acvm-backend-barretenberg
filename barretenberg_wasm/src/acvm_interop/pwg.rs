use common::acvm::acir::{self, circuit::gate::GadgetCall, native_types::Witness};
use common::acvm::FieldElement;
use common::acvm::PartialWitnessGenerator;
use std::collections::BTreeMap;

mod gadget_call;
pub mod merkle;

use self::gadget_call::GadgetCaller;
use super::Plonk;

impl PartialWitnessGenerator for Plonk {
    fn solve_gadget_call(
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        gc: &GadgetCall,
    ) -> Result<(), acir::OPCODE> {
        GadgetCaller::solve_gadget_call(initial_witness, gc)
    }
}
