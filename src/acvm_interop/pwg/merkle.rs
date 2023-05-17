use acvm::FieldElement;

use crate::Error;

pub(super) fn compute_merkle_root(
    hash_func: impl Fn(&FieldElement, &FieldElement) -> Result<FieldElement, Error>,
    hash_path: Vec<&FieldElement>,
    index: &FieldElement,
    leaf: &FieldElement,
) -> Result<FieldElement, Error> {
    let mut index_bits: Vec<bool> = index.bits();
    index_bits.reverse();

    assert!(
        hash_path.len() <= index_bits.len(),
        "hash path exceeds max depth of tree"
    );
    index_bits.into_iter().zip(hash_path.into_iter()).fold(
        Ok(*leaf),
        |current_node, (path_bit, path_elem)| match current_node {
            Ok(current_node) => {
                let (left, right) = if !path_bit {
                    (&current_node, path_elem)
                } else {
                    (path_elem, &current_node)
                };
                hash_func(left, right)
            }
            Err(_) => current_node,
        },
    )
}

#[cfg(test)]
mod tests {
    use crate::merkle::{MerkleTree, MessageHasher};
    use crate::Error;
    use crate::{pedersen::Pedersen, Barretenberg};
    use acvm::FieldElement;

    #[test]
    fn test_check_membership() -> Result<(), Error> {
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

        let mut msg_hasher: blake2::Blake2s256 = MessageHasher::new();

        let mut tree: MerkleTree<blake2::Blake2s256, Barretenberg> = MerkleTree::new(3);

        for test_vector in tests {
            let index = FieldElement::try_from_str(test_vector.index).unwrap();
            let index_as_usize: usize = test_vector.index.parse().unwrap();
            let mut index_bits = index.bits();
            index_bits.reverse();

            let leaf = msg_hasher.hash(&test_vector.message);

            let mut root = tree.root();
            if test_vector.should_update_tree {
                root = tree.update_message(index_as_usize, &test_vector.message)?;
            }

            let hash_path = tree.get_hash_path(index_as_usize);
            let mut hash_path_ref = Vec::new();
            for (i, path_pair) in hash_path.into_iter().enumerate() {
                let path_bit = index_bits[i];
                let hash = if !path_bit { path_pair.1 } else { path_pair.0 };
                hash_path_ref.push(hash);
            }
            let hash_path_ref = hash_path_ref.iter().collect();

            let bb = Barretenberg::new();
            let computed_merkle_root = super::compute_merkle_root(
                |left, right| bb.compress_native(left, right),
                hash_path_ref,
                &index,
                &leaf,
            )?;
            let is_leaf_in_tree = root == computed_merkle_root;

            assert_eq!(
                is_leaf_in_tree, test_vector.result,
                "{}",
                test_vector.error_msg
            );
        }

        Ok(())
    }

    // This test uses `update_leaf` directly rather than `update_message`
    #[test]
    fn simple_shield() -> Result<(), Error> {
        let mut tree: MerkleTree<blake2::Blake2s256, Barretenberg> = MerkleTree::new(3);

        let barretenberg = Barretenberg::new();
        let pubkey_x = FieldElement::from_hex(
            "0x0bff8247aa94b08d1c680d7a3e10831bd8c8cf2ea2c756b0d1d89acdcad877ad",
        )
        .unwrap();
        let pubkey_y = FieldElement::from_hex(
            "0x2a5d7253a6ed48462fedb2d350cc768d13956310f54e73a8a47914f34a34c5c4",
        )
        .unwrap();
        let (note_commitment_x, _) = barretenberg.encrypt(vec![pubkey_x, pubkey_y])?;
        dbg!(note_commitment_x.to_hex());
        let leaf = note_commitment_x;

        let index = FieldElement::try_from_str("0").unwrap();
        let index_as_usize: usize = 0_usize;
        let mut index_bits = index.bits();
        index_bits.reverse();

        let root = tree.update_leaf(index_as_usize, leaf)?;

        let hash_path = tree.get_hash_path(index_as_usize);
        let mut hash_path_ref = Vec::new();
        for (i, path_pair) in hash_path.into_iter().enumerate() {
            let path_bit = index_bits[i];
            let hash = if !path_bit { path_pair.1 } else { path_pair.0 };
            hash_path_ref.push(hash);
        }
        let hash_path_ref = hash_path_ref.iter().collect();
        let bb = Barretenberg::new();
        let computed_merkle_root = super::compute_merkle_root(
            |left, right| bb.compress_native(left, right),
            hash_path_ref,
            &index,
            &leaf,
        )?;

        assert_eq!(root, computed_merkle_root);

        Ok(())
    }
}
