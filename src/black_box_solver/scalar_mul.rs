use acvm::FieldElement;

use super::BarretenbergBlackBoxSolver;
use crate::{Error, FIELD_BYTES};

pub(crate) trait ScalarMul {
    fn fixed_base(&self, input: &FieldElement) -> Result<(FieldElement, FieldElement), Error>;
}

impl ScalarMul for BarretenbergBlackBoxSolver {
    fn fixed_base(&self, input: &FieldElement) -> Result<(FieldElement, FieldElement), Error> {
        use crate::native::field_to_array;

        let result_bytes = barretenberg_sys::schnorr::construct_public_key(&field_to_array(input)?);

        let (pubkey_x_bytes, pubkey_y_bytes) = result_bytes.split_at(FIELD_BYTES);
        assert!(pubkey_x_bytes.len() == FIELD_BYTES);
        assert!(pubkey_y_bytes.len() == FIELD_BYTES);

        let pubkey_x = FieldElement::from_be_bytes_reduce(pubkey_x_bytes);
        let pubkey_y = FieldElement::from_be_bytes_reduce(pubkey_y_bytes);
        Ok((pubkey_x, pubkey_y))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn smoke_test() -> Result<(), Error> {
        let barretenberg = BarretenbergBlackBoxSolver::new();
        let input = FieldElement::one();

        let res = barretenberg.fixed_base(&input)?;
        let x = "0000000000000000000000000000000000000000000000000000000000000001";
        let y = "0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c";

        assert_eq!(x, res.0.to_hex());
        assert_eq!(y, res.1.to_hex());
        Ok(())
    }
}
