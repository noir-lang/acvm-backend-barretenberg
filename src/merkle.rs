// TODO(#166): Rework this module to return results
use acvm::FieldElement;
use std::{collections::BTreeMap, convert::TryInto};

use crate::{pedersen::Pedersen, Barretenberg, Error};

// Hashes the leaves up the path, on the way to the root
pub(crate) trait PathHasher {
    fn new() -> Self;
    fn hash(&self, left: &FieldElement, right: &FieldElement) -> Result<FieldElement, Error>;
}

impl PathHasher for Barretenberg {
    fn hash(&self, left: &FieldElement, right: &FieldElement) -> Result<FieldElement, Error> {
        self.compress_native(left, right)
    }

    fn new() -> Self {
        Barretenberg::new()
    }
}

// Hashes the message into a leaf
pub(crate) trait MessageHasher {
    fn new() -> Self;
    fn hash(&mut self, msg: &[u8]) -> FieldElement;
}

impl MessageHasher for blake2::Blake2s256 {
    fn new() -> Self {
        use blake2::Digest;
        <blake2::Blake2s256 as Digest>::new()
    }

    fn hash(&mut self, msg: &[u8]) -> FieldElement {
        use blake2::Digest;

        self.update(msg);

        let res = self.clone().finalize();
        self.reset();
        FieldElement::from_be_bytes_reduce(&res[..])
    }
}

// This impl should be redone in a more efficient and readable way.
// We should have a separate impl for SparseMerkle and regular merkle
// With Regular merkle we need to ensure that updates are done sequentially
//
// With sparse merkle, one can update at any index

type HashPath = Vec<(FieldElement, FieldElement)>;

#[allow(dead_code)]
fn flatten_path(path: Vec<(FieldElement, FieldElement)>) -> Vec<FieldElement> {
    path.into_iter()
        .flat_map(|(left, right)| std::iter::once(left).chain(std::iter::once(right)))
        .collect()
}

pub(crate) struct MerkleTree<MH: MessageHasher, PH: PathHasher> {
    depth: u32,
    total_size: u32,
    db: BTreeMap<&'static [u8], Vec<u8>>,
    preimages_tree: BTreeMap<[u8; 16], Vec<u8>>,
    hashes_tree: BTreeMap<[u8; 16], Vec<u8>>,
    barretenberg: PH,
    msg_hasher: MH,
}

impl<MH: MessageHasher, PH: PathHasher> MerkleTree<MH, PH> {
    pub(crate) fn new(depth: u32) -> Self {
        let barretenberg = PH::new();
        let mut msg_hasher = MH::new();

        assert!((1..=20).contains(&depth)); // Why can depth != 0 and depth not more than 20?

        let db = BTreeMap::new();
        let preimages_tree = BTreeMap::new();
        let hashes_tree = BTreeMap::new();

        let total_size = 1u32 << depth;

        let mut hashes: Vec<_> = (0..total_size * 2 - 2)
            .map(|_| FieldElement::zero())
            .collect();

        let zero_message = [0u8; 64];
        let pre_images = (0..total_size).map(|_| zero_message.to_vec());

        let mut current = msg_hasher.hash(&zero_message);

        let mut offset = 0usize;
        let mut layer_size = total_size as usize; // XXX: On 32 bit architectures, this `as` cast may silently truncate, when total_size > 2^32?
        while offset < hashes.len() {
            for i in 0..layer_size {
                hashes[offset + i] = current;
            }
            current = barretenberg.hash(&current, &current).unwrap();

            offset += layer_size;
            layer_size /= 2;
        }

        let mut merkle_tree = MerkleTree {
            depth,
            total_size,
            barretenberg,
            db,
            preimages_tree,
            hashes_tree,
            msg_hasher,
        };

        let root = current;
        merkle_tree.insert_root(root);

        for (index, hash) in hashes.into_iter().enumerate() {
            merkle_tree.insert_hash(index as u32, hash)
        }

        for (index, image) in pre_images.into_iter().enumerate() {
            merkle_tree.insert_preimage(index as u32, image)
        }

        merkle_tree.insert_depth(depth);
        merkle_tree.insert_empty_index(0);

        merkle_tree
    }

    fn insert_root(&mut self, value: FieldElement) {
        self.db.insert("ROOT".as_bytes(), value.to_be_bytes());
    }

    fn fetch_root(&self) -> FieldElement {
        let value = self
            .db
            .get("ROOT".as_bytes())
            .expect("merkle root should always be present");
        FieldElement::from_be_bytes_reduce(value)
    }

    fn insert_depth(&mut self, value: u32) {
        self.db
            .insert("DEPTH".as_bytes(), value.to_be_bytes().into());
    }

    fn fetch_depth(&self) -> u32 {
        let value = self
            .db
            .get("DEPTH".as_bytes())
            .expect("depth should always be present");
        u32::from_be_bytes(value.to_vec().try_into().unwrap())
    }

    fn insert_empty_index(&mut self, index: u32) {
        // First fetch the depth to see that this is less than
        let depth = self.fetch_depth();
        let total_size = 1 << depth;
        if index > total_size {
            panic!("trying to insert at index {index}, but total width is {total_size}")
        }
        self.db
            .insert("EMPTY".as_bytes(), index.to_be_bytes().into());
    }

    fn fetch_empty_index(&self) -> u32 {
        let value = self
            .db
            .get("EMPTY".as_bytes())
            .expect("empty index should always be present");
        u32::from_be_bytes(value.to_vec().try_into().unwrap())
    }

    fn insert_preimage(&mut self, index: u32, value: Vec<u8>) {
        let index = index as u128;
        self.preimages_tree.insert(index.to_be_bytes(), value);
    }

    #[allow(dead_code)]
    fn fetch_preimage(&self, index: usize) -> Vec<u8> {
        let index = index as u128;
        self.preimages_tree
            .get(&index.to_be_bytes())
            .unwrap()
            .to_vec()
    }

    fn fetch_hash(&self, index: usize) -> FieldElement {
        let index = index as u128;

        let i_vec = self.hashes_tree.get(&index.to_be_bytes()).unwrap();
        FieldElement::from_be_bytes_reduce(i_vec)
    }

    fn insert_hash(&mut self, index: u32, hash: FieldElement) {
        let index = index as u128;

        self.hashes_tree
            .insert(index.to_be_bytes(), hash.to_be_bytes());
    }

    fn find_hash_from_value(&self, leaf_value: &FieldElement) -> Option<u128> {
        for index_db_lef_hash in self.hashes_tree.iter() {
            let (key, db_leaf_hash) = index_db_lef_hash;
            let index = u128::from_be_bytes(key.to_vec().try_into().unwrap());

            if db_leaf_hash.to_vec() == leaf_value.to_be_bytes() {
                return Some(index);
            }
        }
        None
    }

    pub(crate) fn get_hash_path(&self, mut index: usize) -> HashPath {
        let mut path = HashPath::with_capacity(self.depth as usize);

        let mut offset = 0usize;
        let mut layer_size = self.total_size;
        for _ in 0..self.depth {
            index &= (!0) - 1;
            path.push((
                self.fetch_hash(offset + index),
                self.fetch_hash(offset + index + 1),
            ));
            offset += layer_size as usize;
            layer_size /= 2;
            index /= 2;
        }
        path
    }
    /// Updates the message at index and computes the new tree root
    pub(crate) fn update_message(
        &mut self,
        index: usize,
        new_message: &[u8],
    ) -> Result<FieldElement, Error> {
        let current = self.msg_hasher.hash(new_message);
        self.insert_preimage(index as u32, new_message.to_vec());
        self.update_leaf(index, current)
    }

    fn check_if_index_valid_and_increment(&mut self, mut index: usize) {
        // Fetch the empty index
        let empty_index = self.fetch_empty_index() as usize;
        if empty_index == index {
            // increment the empty index
            index += 1;
            self.insert_empty_index(index as u32);
        } else {
            panic!("this is an regular append-only merkle tree. Tried to insert at {index}, but next empty is at {empty_index}");
        }
    }

    #[allow(dead_code)]
    pub(crate) fn find_index_from_leaf(&self, leaf_value: &FieldElement) -> Option<usize> {
        let index = self.find_hash_from_value(leaf_value);
        index.map(|val| val as usize)
    }

    #[allow(dead_code)]
    // TODO: this gets updated to be -1 on the latest barretenberg branch
    pub(crate) fn find_index_for_empty_leaf(&self) -> usize {
        let index = self.fetch_empty_index();
        index as usize
    }

    /// Update the element at index and compute the new tree root
    pub(crate) fn update_leaf(
        &mut self,
        mut index: usize,
        mut current: FieldElement,
    ) -> Result<FieldElement, Error> {
        // Note that this method does not update the list of messages [preimages]|
        // use `update_message` to do this
        self.check_if_index_valid_and_increment(index);

        let mut offset = 0usize;
        let mut layer_size = self.total_size;
        for _ in 0..self.depth {
            self.insert_hash((offset + index) as u32, current);

            index &= (!0) - 1;
            current = self.barretenberg.hash(
                &self.fetch_hash(offset + index),
                &self.fetch_hash(offset + index + 1),
            )?;

            offset += layer_size as usize;
            layer_size /= 2;
            index /= 2;
        }

        self.insert_root(current);
        Ok(current)
    }

    #[allow(dead_code)]
    /// Gets a message at `index`. This is not the leaf
    pub(crate) fn get_message_at_index(&self, index: usize) -> Vec<u8> {
        self.fetch_preimage(index)
    }

    pub(crate) fn root(&self) -> FieldElement {
        self.fetch_root()
    }

    #[allow(dead_code)]
    pub(crate) fn depth(&self) -> u32 {
        self.depth
    }
}

#[test]
fn basic_interop_initial_root() {
    // Test that the initial root is computed correctly
    let tree: MerkleTree<blake2::Blake2s256, Barretenberg> = MerkleTree::new(3);
    // Copied from barretenberg by copying the stdout from MemoryTree
    let expected_hex = "04ccfbbb859b8605546e03dcaf41393476642859ff7f99446c054b841f0e05c8";
    assert_eq!(tree.root().to_hex(), expected_hex)
}

#[test]
fn basic_interop_hashpath() {
    // Test that the hashpath is correct
    let tree: MerkleTree<blake2::Blake2s256, Barretenberg> = MerkleTree::new(3);

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
fn basic_interop_update() -> Result<(), Error> {
    // Test that computing the HashPath is correct
    let mut tree: MerkleTree<blake2::Blake2s256, Barretenberg> = MerkleTree::new(3);

    tree.update_message(0, &[0; 64])?;
    tree.update_message(1, &[1; 64])?;
    tree.update_message(2, &[2; 64])?;
    tree.update_message(3, &[3; 64])?;
    tree.update_message(4, &[4; 64])?;
    tree.update_message(5, &[5; 64])?;
    tree.update_message(6, &[6; 64])?;
    let root = tree.update_message(7, &[7; 64])?;

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

    Ok(())
}
