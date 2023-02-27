#![warn(unused_crate_dependencies, unused_extern_crates)]

pub mod barretenberg_structures;
pub mod contract;
pub mod gadget_caller;

#[cfg(feature = "std")]
pub mod crs;
pub mod merkle;
pub mod serialiser;

// Re-export acvm
pub use acvm;
