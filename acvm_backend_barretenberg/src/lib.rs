#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]

mod acvm_interop;
mod barretenberg;
mod blake2s;
mod composer;
#[cfg(all(feature = "native", test))]
mod crs;
mod pedersen;
mod pippenger;
mod scalar_mul;
mod schnorr;

pub use acvm_interop::Plonk;

use barretenberg::Barretenberg;

// This function is only necessary to match the interface of `barretenberg-sys`.
#[cfg(feature = "native")]
fn field_to_array(f: &common::acvm::FieldElement) -> [u8; 32] {
    let v = f.to_be_bytes();
    let result: [u8; 32] = v.try_into().unwrap_or_else(|v: Vec<u8>| {
        panic!("Expected a Vec of length {} but it was {}", 32, v.len())
    });
    result
}

#[test]
fn smoke() {
    let mut b = Barretenberg::new();
    let (x, y) = b.encrypt(vec![
        common::acvm::FieldElement::zero(),
        common::acvm::FieldElement::one(),
    ]);
    dbg!(x.to_hex(), y.to_hex());
}
