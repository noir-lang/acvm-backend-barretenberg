use crate::{pedersen::Pedersen, Barretenberg};
use common::{acvm::FieldElement, merkle::PathHasher};

impl PathHasher for Barretenberg {
    fn hash(&self, left: &FieldElement, right: &FieldElement) -> FieldElement {
        self.compress_native(left, right)
    }

    fn new() -> Self {
        Barretenberg::new()
    }
}

// TODO: alter this method so that it only processes one hash per level rather than overriding
// the one of leaves for each level of the hash path
pub(super) fn check_membership(
    path_hasher: &impl PathHasher,
    hash_path: Vec<&FieldElement>,
    root: &FieldElement,
    index: &FieldElement,
    leaf: &FieldElement,
) -> bool {
    let mut index_bits = index.bits();
    index_bits.reverse();

    let mut current = *leaf;

    for (i, path_elem) in hash_path.into_iter().enumerate() {
        let path_bit = index_bits[i];
        let (hash_left, hash_right) = if !path_bit {
            (current, *path_elem)
        } else {
            (*path_elem, current)
        };
        current = path_hasher.hash(&hash_left, &hash_right);
    }

    &current == root
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
        let expected_hex = "04ccfbbb859b8605546e03dcaf41393476642859ff7f99446c054b841f0e05c8";
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
                "0b5e9666e7323ce925c28201a97ddf4144ac9d148448ed6f49f9008719c1b85b",
                "0b5e9666e7323ce925c28201a97ddf4144ac9d148448ed6f49f9008719c1b85b",
            ),
            (
                "22ec636f8ad30ef78c42b7fe2be4a4cacf5a445cfb5948224539f59a11d70775",
                "22ec636f8ad30ef78c42b7fe2be4a4cacf5a445cfb5948224539f59a11d70775",
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
            "0ef8e14db4762ebddadb23b2225f93ca200a4c9bd37130b4d028c971bbad16b5",
            root.to_hex()
        );

        let path = tree.get_hash_path(2);

        let expected_hash_path = vec![
            (
                "06c2335d6f7acb84bbc7d0892cefebb7ca31169a89024f24814d5785e0d05324",
                "12dc36b01cbd8a6248b04e08f0ec91aa6d11a91f030b4a7b1460281859942185",
            ),
            (
                "1f399ea0d6aaf602c7cbcb6ae8cda0e6b6487836c017163888ed4fd38b548389",
                "220dd1b310caa4a6af755b4c893d956c48f31642b487164b258f2973aac2c28f",
            ),
            (
                "25cbb3084647221ffcb535945bb65bd70e0809834dc7a6d865a3f2bb046cdc29",
                "2cc463fc8c9a4eda416f3e490876672f644708dd0330a915f6835d8396fa8f20",
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
            error_msg : "this should always be true, since the tree is initialized with 64 zeroes"
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
            let is_leaf_in_tree =
                super::check_membership(&Barretenberg::new(), hash_path_ref, &root, &index, &leaf);

            assert_eq!(
                is_leaf_in_tree, test_vector.result,
                "{}",
                test_vector.error_msg
            );
        }
    }

    // This test uses `update_leaf` directly rather than `update_message`
    #[test]
    fn simple_shield() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();

        let mut tree: MerkleTree<blake2::Blake2s, Barretenberg> = MerkleTree::new(3, &temp_dir);

        let barretenberg = Barretenberg::new();
        let pubkey_x = FieldElement::from_hex(
            "0x0bff8247aa94b08d1c680d7a3e10831bd8c8cf2ea2c756b0d1d89acdcad877ad",
        )
        .unwrap();
        let pubkey_y = FieldElement::from_hex(
            "0x2a5d7253a6ed48462fedb2d350cc768d13956310f54e73a8a47914f34a34c5c4",
        )
        .unwrap();
        let (note_commitment_x, _) = barretenberg.encrypt(vec![pubkey_x, pubkey_y]);
        dbg!(note_commitment_x.to_hex());
        let leaf = note_commitment_x;

        let index = FieldElement::try_from_str("0").unwrap();
        let index_as_usize: usize = 0_usize;
        let mut index_bits = index.bits();
        index_bits.reverse();

        let root = tree.update_leaf(index_as_usize, leaf);

        let hash_path = tree.get_hash_path(index_as_usize);
        let mut hash_path_ref = Vec::new();
        for (i, path_pair) in hash_path.into_iter().enumerate() {
            let path_bit = index_bits[i];
            let hash = if !path_bit { path_pair.1 } else { path_pair.0 };
            hash_path_ref.push(hash);
        }
        let hash_path_ref = hash_path_ref.iter().collect();
        let is_leaf_in_tree =
            super::check_membership(&Barretenberg::new(), hash_path_ref, &root, &index, &leaf);

        assert!(is_leaf_in_tree)
    }
}
