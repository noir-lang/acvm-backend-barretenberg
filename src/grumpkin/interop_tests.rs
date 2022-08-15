#[cfg(test)]
mod tests {
    use crate::{barretenberg_rs::Barretenberg, grumpkin::*};
    use acvm::FieldElement;
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

        assert_eq!(aztec_fr_to_hex(gen.x), expected_x);
        assert_eq!(aztec_fr_to_hex(gen.y), expected_y);
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

    #[test]
    fn matches_with_barretenberg() {
        let mut barretenberg = Barretenberg::new();
        let (x, y) = barretenberg.encrypt(vec![FieldElement::one(), FieldElement::one()]);

        let pedersen_hash = pedersen(&[Fr::one(), Fr::one()]).into_affine();

        assert_eq!(x.to_hex(), aztec_fr_to_hex(pedersen_hash.x));
        assert_eq!(y.to_hex(), aztec_fr_to_hex(pedersen_hash.y))
    }

    fn aztec_fr_to_hex(field: Fq) -> String {
        let mut bytes = Vec::new();

        field.serialize(&mut bytes).unwrap();
        bytes.reverse();

        hex::encode(bytes)
    }
}
