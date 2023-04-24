use common::acvm::FieldElement;
use wasmer::Value;

use common::barretenberg_structures::Assignments;

use super::{Barretenberg, FIELD_BYTES};

impl Barretenberg {
    pub fn compress_native(&mut self, left: &FieldElement, right: &FieldElement) -> FieldElement {
        let lhs_ptr = self.allocate(&left.to_be_bytes());
        let rhs_ptr = self.allocate(&right.to_be_bytes());
        let result_ptr: usize = 64;
        self.call_multiple(
            "pedersen_plookup_compress_fields",
            vec![&lhs_ptr, &rhs_ptr, &Value::I32(result_ptr as i32)],
        );

        let result_bytes = self.slice_memory(result_ptr, FIELD_BYTES);
        FieldElement::from_be_bytes_reduce(&result_bytes)
    }

    pub fn compress_many(&mut self, inputs: Vec<FieldElement>) -> FieldElement {
        let input_buf = Assignments::from(inputs).to_bytes();
        let input_ptr = self.allocate(&input_buf);
        let result_ptr: usize = 0;

        self.call_multiple(
            "pedersen_plookup_compress",
            vec![&input_ptr, &Value::I32(result_ptr as i32)],
        );

        let result_bytes = self.slice_memory(result_ptr, FIELD_BYTES);
        FieldElement::from_be_bytes_reduce(&result_bytes)
    }

    pub fn encrypt(&mut self, inputs: Vec<FieldElement>) -> (FieldElement, FieldElement) {
        let input_buf = Assignments::from(inputs).to_bytes();
        let input_ptr = self.allocate(&input_buf);
        let result_ptr: usize = 32;

        self.call_multiple(
            "pedersen_plookup_commit",
            vec![&input_ptr, &Value::I32(result_ptr as i32)],
        );

        let result_bytes = self.slice_memory(result_ptr, 2 * FIELD_BYTES);
        let (point_x_bytes, point_y_bytes) = result_bytes.split_at(32);
        assert!(point_x_bytes.len() == FIELD_BYTES);
        assert!(point_y_bytes.len() == FIELD_BYTES);

        let point_x = FieldElement::from_be_bytes_reduce(point_x_bytes);
        let point_y = FieldElement::from_be_bytes_reduce(point_y_bytes);

        (point_x, point_y)
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
