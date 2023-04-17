use common::acvm::FieldElement;

use super::Barretenberg;

impl Barretenberg {
    pub(crate) fn compress_native(
        &mut self,
        left: &FieldElement,
        right: &FieldElement,
    ) -> FieldElement {
        cfg_if::cfg_if! {
            if #[cfg(feature = "native")] {
                let result_bytes = barretenberg_sys::pedersen::compress_native(
                    left.to_be_bytes().as_slice().try_into().unwrap(),
                    right.to_be_bytes().as_slice().try_into().unwrap(),
                );
            } else {
                use wasmer::Value;

                let lhs_ptr = self.allocate(&left.to_be_bytes()); // 0..32
                let rhs_ptr = self.allocate(&right.to_be_bytes()); // 32..64
                let result_ptr = Value::I32(64); // 64..96
                self.call_multiple(
                    "pedersen_plookup_compress_fields",
                    vec![&lhs_ptr, &rhs_ptr, &result_ptr],
                );

                let result_bytes = self.slice_memory(64, 96);
            }
        }
        FieldElement::from_be_bytes_reduce(&result_bytes)
    }

    #[allow(dead_code)]
    pub(crate) fn compress_many(&mut self, inputs: Vec<FieldElement>) -> FieldElement {
        cfg_if::cfg_if! {
            if #[cfg(feature = "native")] {
                use super::field_to_array;

                let mut inputs_buf = Vec::new();
                for f in inputs {
                    inputs_buf.push(field_to_array(&f));
                }
                let result_bytes = barretenberg_sys::pedersen::compress_many(&inputs_buf);
            } else {
                use wasmer::Value;
                use common::barretenberg_structures::Assignments;

                let input_buf = Assignments(inputs).to_bytes();
                let input_ptr = self.allocate(&input_buf);

                self.call_multiple(
                    "pedersen_plookup_compress",
                    vec![&input_ptr, &Value::I32(0)],
                );

                let result_bytes = self.slice_memory(0, 32);
            }
        }
        FieldElement::from_be_bytes_reduce(&result_bytes)
    }

    pub(crate) fn encrypt(&mut self, inputs: Vec<FieldElement>) -> (FieldElement, FieldElement) {
        cfg_if::cfg_if! {
            if #[cfg(feature = "native")] {
                use super::field_to_array;

                let mut inputs_buf = Vec::new();
                for f in inputs {
                    inputs_buf.push(field_to_array(&f));
                }
                let (point_x_bytes, point_y_bytes) = barretenberg_sys::pedersen::encrypt(&inputs_buf);
                let point_x = FieldElement::from_be_bytes_reduce(&point_x_bytes);
                let point_y = FieldElement::from_be_bytes_reduce(&point_y_bytes);

                (point_x, point_y)
            } else {
                use wasmer::Value;
                use common::barretenberg_structures::Assignments;

                let input_buf = Assignments(inputs).to_bytes();
                let input_ptr = self.allocate(&input_buf);

                let result_ptr = Value::I32(32);
                self.call_multiple("pedersen_plookup_commit", vec![&input_ptr, &result_ptr]);

                let result_bytes = self.slice_memory(32, 96);
                let (point_x_bytes, point_y_bytes) = result_bytes.split_at(32);
                assert!(point_x_bytes.len() == 32);
                assert!(point_y_bytes.len() == 32);

                let point_x = FieldElement::from_be_bytes_reduce(point_x_bytes);
                let point_y = FieldElement::from_be_bytes_reduce(point_y_bytes);

                (point_x, point_y)
            }
        }
    }
}

#[test]
fn basic_interop() {
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

    let mut barretenberg = Barretenberg::new();
    for test in tests {
        let expected = FieldElement::from_hex(test.expected_hex).unwrap();

        let got = barretenberg.compress_native(&test.input_left, &test.input_right);
        let got_many = barretenberg.compress_many(vec![test.input_left, test.input_right]);
        assert_eq!(got, expected);
        assert_eq!(got, got_many);
    }
}

#[test]
fn pedersen_hash_to_point() {
    let mut barretenberg = Barretenberg::new();
    let (x, y) = barretenberg.encrypt(vec![FieldElement::zero(), FieldElement::one()]);
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
}
