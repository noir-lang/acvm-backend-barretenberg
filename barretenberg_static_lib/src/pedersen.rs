use common::acvm::FieldElement;

use super::field_to_array;
use super::Barretenberg;

impl Barretenberg {
    pub fn compress_native(&mut self, left: &FieldElement, right: &FieldElement) -> FieldElement {
        let result_bytes = barretenberg_wrapper::pedersen::compress_native(
            left.to_be_bytes().as_slice().try_into().unwrap(),
            right.to_be_bytes().as_slice().try_into().unwrap(),
        );
        FieldElement::from_be_bytes_reduce(&result_bytes)
    }

    pub fn compress_many(&mut self, inputs: Vec<FieldElement>) -> FieldElement {
        let mut inputs_buf = Vec::new();
        for f in inputs {
            inputs_buf.push(field_to_array(&f));
        }
        let result = barretenberg_wrapper::pedersen::compress_many(&inputs_buf);
        FieldElement::from_be_bytes_reduce(&result)
    }

    pub fn encrypt(&mut self, inputs: Vec<FieldElement>) -> (FieldElement, FieldElement) {
        let mut inputs_buf = Vec::new();
        for f in inputs {
            inputs_buf.push(field_to_array(&f));
        }
        let (point_x_bytes, point_y_bytes) = barretenberg_wrapper::pedersen::encrypt(&inputs_buf);
        let point_x = FieldElement::from_be_bytes_reduce(&point_x_bytes);
        let point_y = FieldElement::from_be_bytes_reduce(&point_y_bytes);

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
            expected_hex: "0x229fb88be21cec523e9223a21324f2e305aea8bff9cdbcb3d0c6bba384666ea1",
        },
        Test {
            input_left: FieldElement::one(),
            input_right: FieldElement::one(),
            expected_hex: "0x26425ddf29b4af6ee91008e8dbcbee975653170eee849efd75abf8301dee114e",
        },
        Test {
            input_left: FieldElement::one(),
            input_right: FieldElement::zero(),
            expected_hex: "0x08f3cb4f0fdd7a9ef130c6d4590af6750b1475161020a198a56eced45078ccf2",
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
        "0x229fb88be21cec523e9223a21324f2e305aea8bff9cdbcb3d0c6bba384666ea1",
    )
    .unwrap();
    let expected_y = FieldElement::from_hex(
        "0x296b4b4605e586a91caa3202baad557628a8c56d0a1d6dff1a7ca35aed3029d5",
    )
    .unwrap();

    assert_eq!(expected_x.to_hex(), x.to_hex());
    assert_eq!(expected_y.to_hex(), y.to_hex());
}
