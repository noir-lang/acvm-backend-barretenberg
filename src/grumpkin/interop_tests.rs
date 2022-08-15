#[cfg(test)]
mod tests {
    use crate::grumpkin::*;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{BigInteger256, One, PrimeField, Zero};
    use ark_serialize::CanonicalSerialize;
    use grumpkin::{Fq, SWAffine};

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

    #[test]
    fn c_interop_derive_generators() {
        for [x_hex, y_hex] in GENERATORS {
            let x_bytes = hex::decode(x_hex).unwrap();
            let y_bytes = hex::decode(y_hex).unwrap();
            let point = deserialise_point(&x_bytes, &y_bytes).unwrap();
            assert!(point.is_on_curve());
            assert!(point.is_in_correct_subgroup_assuming_on_curve());
        }
    }
}
