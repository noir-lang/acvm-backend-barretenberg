#![warn(unused_crate_dependencies, unused_extern_crates)]
#![warn(unreachable_pub)]

pub mod barretenberg_structures;
pub mod black_box_functions;
pub mod contract;

#[cfg(feature = "std")]
pub mod crs;
pub mod merkle;
pub mod serializer;

pub mod proof;

// Re-export acvm
pub use acvm;
