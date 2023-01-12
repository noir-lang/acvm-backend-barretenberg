// TODO: remove once this module is used
#![allow(dead_code)]
use crate::Barretenberg;
use common::acvm::FieldElement;
use common::merkle::PathHasher;

impl PathHasher for Barretenberg {
    fn hash(&mut self, left: &FieldElement, right: &FieldElement) -> FieldElement {
        self.compress_native(left, right)
    }

    fn new() -> Self {
        Barretenberg::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use common::merkle::{MerkleTree, MessageHasher};

    #[test]
    fn basic_interop_initial_root() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        // Test that the initial root is computed correctly
        let tree: MerkleTree<blake2::Blake2s, Barretenberg> = MerkleTree::new(3, &temp_dir);
        // Copied from barretenberg by copying the stdout from MemoryTree
        let expected_hex = "15371ccc70f5b567da373f8698b5b5ea382cddc1b6940e9141e5db93f67182f7";
        assert_eq!(tree.root().to_hex(), expected_hex)
    }
    #[test]
    fn basic_interop_hashpath() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        // Test that the hashpath is correct
        let tree: MerkleTree<blake2::Blake2s, Barretenberg> = MerkleTree::new(3, &temp_dir);

        let path = tree.get_hash_path(0);

        let expected_hash_path = vec![
            (
                "1cdcf02431ba623767fe389337d011df1048dcc24b98ed81cec97627bab454a0",
                "1cdcf02431ba623767fe389337d011df1048dcc24b98ed81cec97627bab454a0",
            ),
            (
                "0833de91a69b13953edec6be92977bad49f0dbac520ec8f63d723f7692a446b8",
                "0833de91a69b13953edec6be92977bad49f0dbac520ec8f63d723f7692a446b8",
            ),
            (
                "0bf4c916dd193a7ac4748d91063d7244214d70cb2e338eb2cfff1fa4b5f1633d",
                "0bf4c916dd193a7ac4748d91063d7244214d70cb2e338eb2cfff1fa4b5f1633d",
            ),
        ];

        for (got, expected_segment) in path.into_iter().zip(expected_hash_path) {
            assert_eq!(got.0.to_hex().as_str(), expected_segment.0);
            assert_eq!(got.1.to_hex().as_str(), expected_segment.1)
        }
    }

    #[test]
    fn basic_interop_update() {
        // Test that computing the HashPath is correct
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let mut tree: MerkleTree<blake2::Blake2s, Barretenberg> = MerkleTree::new(3, &temp_dir);

        tree.update_message(0, &[0; 64]);
        tree.update_message(1, &[1; 64]);
        tree.update_message(2, &[2; 64]);
        tree.update_message(3, &[3; 64]);
        tree.update_message(4, &[4; 64]);
        tree.update_message(5, &[5; 64]);
        tree.update_message(6, &[6; 64]);
        let root = tree.update_message(7, &[7; 64]);

        assert_eq!(
            "2ef749aee0274b151c91428ace22da4f661a7a6dd0b698a8e2b80e24fabc8432",
            root.to_hex()
        );

        let path = tree.get_hash_path(2);

        let expected_hash_path = vec![
            (
                "06c2335d6f7acb84bbc7d0892cefebb7ca31169a89024f24814d5785e0d05324",
                "12dc36b01cbd8a6248b04e08f0ec91aa6d11a91f030b4a7b1460281859942185",
            ),
            (
                "21d48844c83a28acd68c4d0bca69dba8cffd44be2e5556f9463fd23ae8071e83",
                "2118e107a5638f06644237aad2ffe4486b3a91e4fdf85ea49259245e80488503",
            ),
            (
                "05c41ef199bde4a704a819fd53c16b6c28fbd76e617d6f7b93c1b1a8aab77040",
                "24c3f41728cbf0a7ab449d6701f0c45e888e02535128189d7a3b9ac5f715c439",
            ),
        ];

        for (got, expected_segment) in path.into_iter().zip(expected_hash_path) {
            assert_eq!(got.0.to_hex().as_str(), expected_segment.0);
            assert_eq!(got.1.to_hex().as_str(), expected_segment.1)
        }
    }

    #[test]
    fn test_check_membership() {
        struct Test<'a> {
            // Index of the leaf in the MerkleTree
            index: &'a str,
            // Returns true if the leaf is indeed a part of the MerkleTree at the specified index
            result: bool,
            // The message is used to derive the leaf at `index` by using the specified hash
            message: Vec<u8>,
            // If this is true, then before checking for membership
            // we update the tree with the message at that index
            should_update_tree: bool,
            error_msg: &'a str,
        }
        // Note these test cases are not independent.
        // i.e. If you update index 0, then this will be saved for the next test
        let tests = vec![
        Test {
            index : "0",
            result : true,
            message : vec![0;64],
            should_update_tree: false,
            error_msg : "this should always be true, since the tree is initialised with 64 zeroes"
        },
        Test {
            index : "0",
            result : false,
            message : vec![10;64],
            should_update_tree: false,
            error_msg : "this should be false, since the tree was not updated, however the message which derives the leaf has changed"
        },
        Test {
            index : "0",
            result : true,
            message : vec![1;64],
            should_update_tree: true,
            error_msg : "this should be true, since we are updating the tree"
        },
        Test {
            index : "0",
            result : true,
            message : vec![1;64],
            should_update_tree: false,
            error_msg : "this should be true since the index at 4 has not been changed yet, so it would be [0;64]"
        },
        Test {
            index : "4",
            result : true,
            message : vec![0;64],
            should_update_tree: false,
            error_msg : "this should be true since the index at 4 has not been changed yet, so it would be [0;64]"
        },
    ];

        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let mut msg_hasher: blake2::Blake2s = MessageHasher::new();

        let mut tree: MerkleTree<blake2::Blake2s, Barretenberg> = MerkleTree::new(3, &temp_dir);

        for test_vector in tests {
            let index = FieldElement::try_from_str(test_vector.index).unwrap();
            let index_as_usize: usize = test_vector.index.parse().unwrap();
            let mut index_bits = index.bits();
            index_bits.reverse();

            let leaf = msg_hasher.hash(&test_vector.message);

            let mut root = tree.root();
            if test_vector.should_update_tree {
                root = tree.update_message(index_as_usize, &test_vector.message);
            }

            let hash_path = tree.get_hash_path(index_as_usize);
            let mut hash_path_ref = Vec::new();
            for (i, path_pair) in hash_path.into_iter().enumerate() {
                let path_bit = index_bits[i];
                let hash = if !path_bit { path_pair.1 } else { path_pair.0 };
                hash_path_ref.push(hash);
            }
            let hash_path_ref = hash_path_ref.iter().collect();
            let result = common::merkle::check_membership::<Barretenberg>(
                hash_path_ref,
                &root,
                &index,
                &leaf,
            );
            let is_leaf_in_true = result == FieldElement::one();

            assert!(
                is_leaf_in_true == test_vector.result,
                "{}",
                test_vector.error_msg
            );
        }
    }
}
