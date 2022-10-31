pub mod blake2s;
pub mod composer;
pub use common::crs;
pub mod pedersen;
mod pippenger;
pub mod scalar_mul;
pub mod schnorr;

use acvm::FieldElement;
use std::convert::TryInto;

pub struct Barretenberg;

pub fn field_to_array(f: &FieldElement) -> [u8; 32] {
    let v = f.to_bytes();
    let result: [u8; 32] = v.try_into().unwrap_or_else(|v: Vec<u8>| {
        panic!("Expected a Vec of length {} but it was {}", 32, v.len())
    });
    result
}

impl Default for Barretenberg {
    fn default() -> Self {
        Self::new()
    }
}

impl Barretenberg {
    pub fn new() -> Barretenberg {
        Barretenberg
    }
}
