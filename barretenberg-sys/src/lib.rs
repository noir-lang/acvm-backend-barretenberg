// Suppress the flurry of warnings caused by using "C" naming conventions
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// This matches bindgen::Builder output
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod blake2s;
pub mod composer;
pub mod pedersen;
pub mod pippenger;
pub mod schnorr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn pedersen() {
        let input = vec![0; 64];
        blake2s::hash_to_field(&input);

        let f_zero = [0_u8; 32];
        let mut f_one = [0_u8; 32];
        f_one[31] = 1;
        let got = pedersen::compress_native(&f_zero, &f_one);
        assert_eq!(
            "229fb88be21cec523e9223a21324f2e305aea8bff9cdbcb3d0c6bba384666ea1",
            hex::encode(got)
        );
    }
}
