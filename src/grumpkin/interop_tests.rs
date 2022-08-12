use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger256, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use grumpkin::{Fq, SWAffine, SWProjective};

#[test]
fn c_plus_plus_interop_generator() {
    // Copied from the C++ codebase
    let expected_x = "0000000000000000000000000000000000000000000000000000000000000001";
    let expected_y = "0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c";

    let gen = SWAffine::prime_subgroup_generator();

    assert!(gen.is_on_curve());
    assert!(gen.is_in_correct_subgroup_assuming_on_curve());

    let mut bytes_x = Vec::new();
    let mut bytes_y = Vec::new();
    gen.x.serialize(&mut bytes_x).unwrap();
    gen.y.serialize(&mut bytes_y).unwrap();

    bytes_x.reverse();
    bytes_y.reverse();

    assert_eq!(hex::encode(bytes_x), expected_x);
    assert_eq!(hex::encode(bytes_y), expected_y);
}
fn deserialise_fq(bytes: &[u8]) -> Option<Fq> {
    assert_eq!(bytes.len(), 32);

    let mut tmp = BigInteger256([0, 0, 0, 0]);

    tmp.0[3] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
    tmp.0[2] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
    tmp.0[1] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
    tmp.0[0] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());

    Fq::from_repr(tmp)
}

fn deserialise_point(x_bytes: &[u8], y_bytes: &[u8]) -> Option<SWAffine> {
    let x = deserialise_fq(x_bytes)?;
    let y = deserialise_fq(y_bytes)?;
    let is_infinity = false; // none of the generators should be points at infinity
    Some(SWAffine::new(x, y, is_infinity))
}

#[test]
fn c_plus_plus_interop_generator_deserialise() {
    // Copied from the C++ codebase
    let expected_x = "0000000000000000000000000000000000000000000000000000000000000001";
    let expected_y = "0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c";

    let x_bytes = hex::decode(expected_x).unwrap();
    let y_bytes = hex::decode(expected_y).unwrap();
    let got_point = deserialise_point(&x_bytes, &y_bytes).unwrap();

    let expected_point = SWAffine::prime_subgroup_generator();

    assert_eq!(got_point, expected_point)
}
