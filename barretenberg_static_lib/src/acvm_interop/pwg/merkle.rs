// TODO: remove once this module is used
#![allow(dead_code)]
use crate::Barretenberg;
use common::acvm::FieldElement;
use common::merkle::PathHasher;

impl PathHasher for Barretenberg {
    fn hash(&mut self, left: &FieldElement, right: &FieldElement) -> FieldElement {
        self.compress_native(left, right)
    }

    fn new() -> Self {
        Barretenberg::new()
    }
}
