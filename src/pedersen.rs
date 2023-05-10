use acvm::FieldElement;

use super::{Barretenberg, Error};

pub(crate) trait Pedersen {
    fn compress_native(
        &self,
        left: &FieldElement,
        right: &FieldElement,
    ) -> Result<FieldElement, Error>;
    fn compress_many(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, Error>;
    fn encrypt(&self, inputs: Vec<FieldElement>) -> Result<(FieldElement, FieldElement), Error>;
}

#[cfg(feature = "native")]
impl Pedersen for Barretenberg {
    fn compress_native(
        &self,
        left: &FieldElement,
        right: &FieldElement,
    ) -> Result<FieldElement, Error> {
        use super::FeatureError;

        let result_bytes = barretenberg_sys::pedersen::compress_native(
            left.to_be_bytes()
                .as_slice()
                .try_into()
                .map_err(|source| FeatureError::FieldElementSlice { source })?,
            right
                .to_be_bytes()
                .as_slice()
                .try_into()
                .map_err(|source| FeatureError::FieldElementSlice { source })?,
        );

        Ok(FieldElement::from_be_bytes_reduce(&result_bytes))
    }

    #[allow(dead_code)]
    fn compress_many(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, Error> {
        use super::native::field_to_array;

        let mut inputs_buf = Vec::new();
        for f in inputs {
            inputs_buf.push(field_to_array(&f)?);
        }
        let result_bytes = barretenberg_sys::pedersen::compress_many(&inputs_buf);

        Ok(FieldElement::from_be_bytes_reduce(&result_bytes))
    }

    fn encrypt(&self, inputs: Vec<FieldElement>) -> Result<(FieldElement, FieldElement), Error> {
        use super::native::field_to_array;

        let mut inputs_buf = Vec::new();
        for f in inputs {
            inputs_buf.push(field_to_array(&f)?);
        }
        let (point_x_bytes, point_y_bytes) = barretenberg_sys::pedersen::encrypt(&inputs_buf);

        let point_x = FieldElement::from_be_bytes_reduce(&point_x_bytes);
        let point_y = FieldElement::from_be_bytes_reduce(&point_y_bytes);

        Ok((point_x, point_y))
    }
}

#[cfg(not(feature = "native"))]
impl Pedersen for Barretenberg {
    fn compress_native(
        &self,
        left: &FieldElement,
        right: &FieldElement,
    ) -> Result<FieldElement, Error> {
        use super::FIELD_BYTES;

        let lhs_ptr: usize = 0;
        let rhs_ptr: usize = lhs_ptr + FIELD_BYTES;
        let result_ptr: usize = rhs_ptr + FIELD_BYTES;

        self.transfer_to_heap(&left.to_be_bytes(), lhs_ptr);
        self.transfer_to_heap(&right.to_be_bytes(), rhs_ptr);

        self.call_multiple(
            "pedersen_plookup_compress_fields",
            vec![&lhs_ptr.into(), &rhs_ptr.into(), &result_ptr.into()],
        )?;

        let result_bytes: [u8; FIELD_BYTES] = self.read_memory(result_ptr);
        Ok(FieldElement::from_be_bytes_reduce(&result_bytes))
    }

    #[allow(dead_code)]
    fn compress_many(&self, inputs: Vec<FieldElement>) -> Result<FieldElement, Error> {
        use super::FIELD_BYTES;
        use crate::barretenberg_structures::Assignments;

        let input_buf = Assignments::from(inputs).to_bytes();
        let input_ptr = self.allocate(&input_buf)?;
        let result_ptr: usize = 0;

        self.call_multiple(
            "pedersen_plookup_compress",
            vec![&input_ptr, &result_ptr.into()],
        )?;

        let result_bytes: [u8; FIELD_BYTES] = self.read_memory(result_ptr);
        Ok(FieldElement::from_be_bytes_reduce(&result_bytes))
    }

    fn encrypt(&self, inputs: Vec<FieldElement>) -> Result<(FieldElement, FieldElement), Error> {
        use super::FIELD_BYTES;
        use crate::barretenberg_structures::Assignments;

        let input_buf = Assignments::from(inputs).to_bytes();
        let input_ptr = self.allocate(&input_buf)?;
        let result_ptr: usize = 0;

        self.call_multiple(
            "pedersen_plookup_commit",
            vec![&input_ptr, &result_ptr.into()],
        )?;

        let result_bytes: [u8; 2 * FIELD_BYTES] = self.read_memory(result_ptr);
        let (point_x_bytes, point_y_bytes) = result_bytes.split_at(FIELD_BYTES);

        let point_x = FieldElement::from_be_bytes_reduce(point_x_bytes);
        let point_y = FieldElement::from_be_bytes_reduce(point_y_bytes);

        Ok((point_x, point_y))
    }
}

#[test]
fn basic_interop() -> Result<(), Error> {
    // Expected values were taken from Barretenberg by running `crypto::pedersen::compress_native`
    // printing the result in hex to `std::cout` and copying
    struct Test<'a> {
        input_left: FieldElement,
        input_right: FieldElement,
        expected_hex: &'a str,
    }

    let tests = vec![
        Test {
            input_left: FieldElement::zero(),
            input_right: FieldElement::one(),
            expected_hex: "0x11831f49876c313f2a9ec6d8d521c7ce0b6311c852117e340bfe27fd1ac096ef",
        },
        Test {
            input_left: FieldElement::one(),
            input_right: FieldElement::one(),
            expected_hex: "0x1044a769e185fcdf077c8289a6bf87c5c77ff9561cab69d39fadd90a07ee4af4",
        },
        Test {
            input_left: FieldElement::one(),
            input_right: FieldElement::zero(),
            expected_hex: "0x17d213c8fe83e89a2f3190933d437a3e231124e0383e6dc6a7b6e6358833e427",
        },
    ];

    let barretenberg = Barretenberg::new();
    for test in tests {
        let expected = FieldElement::from_hex(test.expected_hex).unwrap();

        let got = barretenberg.compress_native(&test.input_left, &test.input_right)?;
        let got_many = barretenberg.compress_many(vec![test.input_left, test.input_right])?;
        assert_eq!(got, expected);
        assert_eq!(got, got_many);
    }
    Ok(())
}

#[test]
fn pedersen_hash_to_point() -> Result<(), Error> {
    let barretenberg = Barretenberg::new();
    let (x, y) = barretenberg.encrypt(vec![FieldElement::zero(), FieldElement::one()])?;
    let expected_x = FieldElement::from_hex(
        "0x11831f49876c313f2a9ec6d8d521c7ce0b6311c852117e340bfe27fd1ac096ef",
    )
    .unwrap();
    let expected_y = FieldElement::from_hex(
        "0x0ecf9d98be4597a88c46a7e0fa8836b57a7dcb41ee30f8d8787b11cc259c83fa",
    )
    .unwrap();

    assert_eq!(expected_x.to_hex(), x.to_hex());
    assert_eq!(expected_y.to_hex(), y.to_hex());
    Ok(())
}
