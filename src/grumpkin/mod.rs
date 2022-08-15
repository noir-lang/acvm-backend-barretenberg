// We need a grumpkin module here to ensure that the rust version of grumpkin is interopable
// with the C++ version of grumpkin.
//
// The most notable difference is the serialisation strategy that the C++
// code uses, which is non-standard.

pub mod interop_tests;
