use acvm::acir::{self, circuit::gate::GadgetCall, native_types::Witness};
use acvm::FieldElement;
use acvm::PartialWitnessGenerator;
use std::collections::BTreeMap;

use super::Plonk;

impl PartialWitnessGenerator for Plonk {
    fn solve_gadget_call(
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        gc: &GadgetCall,
    ) -> Result<(), acir::OPCODE> {
        todo!("there is no pwg for the js cli, we could hook up the wasm pwg here")
        // GadgetCaller::solve_gadget_call(initial_witness, gc)
    }
}
