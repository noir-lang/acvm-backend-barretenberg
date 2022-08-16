#[cfg(test)]
mod tests {
    use crate::{barretenberg_rs::Barretenberg, grumpkin::*};
    use acvm::FieldElement;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::{BigInteger256, One, PrimeField, Zero};
    use ark_serialize::CanonicalSerialize;
    use grumpkin::{Fq, SWAffine};
    use rand::Rng;
    
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
        let q = FieldElement::try_from_str("17631683881184975370165255887551781615748388533673675138860").unwrap();
        println!("q: {:?}", q.to_hex());
        let mut barretenberg = Barretenberg::new();
        let (x, y) = barretenberg.encrypt(vec![FieldElement::one(), FieldElement::one()]);

        let pedersen_hash = pedersen(&[Fr::one(), Fr::one()]).into_affine();

        assert_eq!(x.to_hex(), aztec_fr_to_hex(pedersen_hash.x));
        assert_eq!(y.to_hex(), aztec_fr_to_hex(pedersen_hash.y))
    }

    #[test]
    fn random_matches() {
        let mut barretenberg = Barretenberg::new();
        let mut aztec_inputs: Vec<FieldElement> = Vec::new();
        let mut grumpkin_inputs: Vec<Fr> = Vec::new();
        
        for _ in 0..5 {
            let num: u128 = rand::thread_rng().gen_range(0..100 as u128);

            aztec_inputs.push(FieldElement::from(num));
            grumpkin_inputs.push(Fr::from(num));
        }

        let (x, y) = barretenberg.encrypt(aztec_inputs);

        let pedersen_hash = pedersen(&grumpkin_inputs).into_affine();

        let ped_naive_hash = pedersen_naive(&grumpkin_inputs.clone()).into_affine();
        assert_eq!(aztec_fr_to_hex(pedersen_hash.x), aztec_fr_to_hex(ped_naive_hash.x));

        assert_eq!(x.to_hex(), aztec_fr_to_hex(pedersen_hash.x));
        assert_eq!(y.to_hex(), aztec_fr_to_hex(pedersen_hash.y))
    } 

    #[test]
    fn fixed_based_matches() {
        let x = FieldElement::from(5 as u128);
        // let x = FieldElement::from_hex("0x0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c").unwrap();
        println!("x: {:?}", x);
        println!("x bytes: {:?}", x.to_bytes());
        fixed_base(x.to_bytes().as_slice())
    }


}
