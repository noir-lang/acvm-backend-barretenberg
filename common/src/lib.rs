#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]

pub mod barretenberg_structures;

#[cfg(feature = "std")]
pub mod crs;
pub mod merkle;

pub mod proof;

// Re-export acvm
pub use acvm;
