// TODO: remove once this module is used
#![allow(dead_code)]
use acvm::FieldElement;
use std::{convert::TryInto, path::Path};

// Hashes the leaves up the path, on the way to the root
pub trait PathHasher {
    fn new() -> Self;
    fn hash(&mut self, left: &FieldElement, right: &FieldElement) -> FieldElement;
}

// Hashes the message into a leaf
pub trait MessageHasher {
    fn new() -> Self;
    fn hash(&mut self, msg: &[u8]) -> FieldElement;
}

impl MessageHasher for blake2::Blake2s {
    fn new() -> Self {
        use blake2::Digest;
        <blake2::Blake2s as Digest>::new()
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

pub(crate) type HashPath = Vec<(FieldElement, FieldElement)>;

pub fn flatten_path(path: Vec<(FieldElement, FieldElement)>) -> Vec<FieldElement> {
    path.into_iter()
        .flat_map(|(left, right)| std::iter::once(left).chain(std::iter::once(right)))
        .collect()
}

pub struct MerkleTree<MH: MessageHasher, PH: PathHasher> {
    depth: u32,
    total_size: u32,
    db: sled::Db,
    barretenberg: PH,
    msg_hasher: MH,
}

fn insert_root(db: &mut sled::Db, value: FieldElement) {
    db.insert("ROOT".as_bytes(), value.to_be_bytes()).unwrap();
}
fn fetch_root(db: &sled::Db) -> FieldElement {
    let value = db
        .get("ROOT".as_bytes())
        .unwrap()
        .expect("merkle root should always be present");
    FieldElement::from_be_bytes_reduce(&value)
}
fn insert_depth(db: &mut sled::Db, value: u32) {
    db.insert("DEPTH".as_bytes(), &value.to_be_bytes()).unwrap();
}
fn fetch_depth(db: &sled::Db) -> u32 {
    let value = db
        .get("DEPTH".as_bytes())
        .unwrap()
        .expect("depth should always be present");
    u32::from_be_bytes(value.to_vec().try_into().unwrap())
}
fn insert_empty_index(db: &mut sled::Db, index: u32) {
    // First fetch the depth to see that this is less than
    let depth = fetch_depth(db);
    let total_size = 1 << depth;
    if index > total_size {
        panic!("trying to insert at index {index}, but total width is {total_size}")
    }
    db.insert("EMPTY".as_bytes(), &index.to_be_bytes()).unwrap();
}
fn fetch_empty_index(db: &sled::Db) -> u32 {
    let value = db
        .get("EMPTY".as_bytes())
        .unwrap()
        .expect("empty index should always be present");
    u32::from_be_bytes(value.to_vec().try_into().unwrap())
}
fn insert_preimage(db: &mut sled::Db, index: u32, value: Vec<u8>) {
    let tree = db.open_tree("preimages").unwrap();

    let index = index as u128;
    tree.insert(index.to_be_bytes(), value).unwrap();
}

fn fetch_preimage(db: &sled::Db, index: usize) -> Vec<u8> {
    let tree = db.open_tree("preimages").unwrap();

    let index = index as u128;
    tree.get(index.to_be_bytes())
        .unwrap()
        .map(|i_vec| i_vec.to_vec())
        .unwrap()
}
fn fetch_hash(db: &sled::Db, index: usize) -> FieldElement {
    let tree = db.open_tree("hashes").unwrap();
    let index = index as u128;

    tree.get(index.to_be_bytes())
        .unwrap()
        .map(|i_vec| FieldElement::from_be_bytes_reduce(&i_vec))
        .unwrap()
}

fn insert_hash(db: &mut sled::Db, index: u32, hash: FieldElement) {
    let tree = db.open_tree("hashes").unwrap();
    let index = index as u128;

    tree.insert(index.to_be_bytes(), hash.to_be_bytes())
        .unwrap();
}

fn find_hash_from_value(db: &sled::Db, leaf_value: &FieldElement) -> Option<u128> {
    let tree = db.open_tree("hashes").unwrap();

    for index_db_lef_hash in tree.iter() {
        let (key, db_leaf_hash) = index_db_lef_hash.unwrap();
        let index = u128::from_be_bytes(key.to_vec().try_into().unwrap());

        if db_leaf_hash.to_vec() == leaf_value.to_be_bytes() {
            return Some(index);
        }
    }
    None
}

impl<MH: MessageHasher, PH: PathHasher> MerkleTree<MH, PH> {
    pub fn from_path<P: AsRef<Path>>(
        path: P,
        barretenberg: PH,
        msg_hasher: MH,
    ) -> MerkleTree<MH, PH> {
        assert!(path.as_ref().exists(), "path does not exist");
        let config = sled::Config::new().path(path);

        let db = config.open().unwrap();

        let depth = fetch_depth(&db);

        let total_size = 1u32 << depth;

        MerkleTree {
            depth,
            total_size,
            barretenberg,
            db,
            msg_hasher,
        }
    }
    pub fn new<P: AsRef<Path>>(depth: u32, path: P) -> MerkleTree<MH, PH> {
        let mut barretenberg = PH::new();
        let mut msg_hasher = MH::new();

        assert!((1..=20).contains(&depth)); // Why can depth != 0 and depth not more than 20?

        let config = sled::Config::new().path(path);
        let mut db = config.open().unwrap();

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
            current = barretenberg.hash(&current, &current);

            offset += layer_size;
            layer_size /= 2;
        }
        let root = current;
        insert_root(&mut db, root);

        for (index, hash) in hashes.into_iter().enumerate() {
            insert_hash(&mut db, index as u32, hash)
        }

        for (index, image) in pre_images.into_iter().enumerate() {
            insert_preimage(&mut db, index as u32, image)
        }

        insert_depth(&mut db, depth);
        insert_empty_index(&mut db, 0);

        MerkleTree {
            depth,
            total_size,
            barretenberg,
            db,
            msg_hasher,
        }
    }

    pub fn get_hash_path(&self, mut index: usize) -> HashPath {
        let mut path = HashPath::with_capacity(self.depth as usize);

        let mut offset = 0usize;
        let mut layer_size = self.total_size;
        for _ in 0..self.depth {
            index &= (!0) - 1;
            path.push((
                fetch_hash(&self.db, offset + index),
                fetch_hash(&self.db, offset + index + 1),
            ));
            offset += layer_size as usize;
            layer_size /= 2;
            index /= 2;
        }
        path
    }
    /// Updates the message at index and computes the new tree root
    pub fn update_message(&mut self, index: usize, new_message: &[u8]) -> FieldElement {
        let current = self.msg_hasher.hash(new_message);

        insert_preimage(&mut self.db, index as u32, new_message.to_vec());
        self.update_leaf(index, current)
    }

    fn check_if_index_valid_and_increment(&mut self, mut index: usize) {
        // Fetch the empty index
        let empty_index = fetch_empty_index(&self.db) as usize;
        if empty_index == index {
            // increment the empty index
            index += 1;
            insert_empty_index(&mut self.db, index as u32);
        } else {
            panic!("this is an regular append-only merkle tree. Tried to insert at {index}, but next empty is at {empty_index}");
        }
    }

    pub fn find_index_from_leaf(&self, leaf_value: &FieldElement) -> Option<usize> {
        let index = find_hash_from_value(&self.db, leaf_value);
        index.map(|val| val as usize)
    }

    // TODO: this gets updated to be -1 on the latest barretenberg branch
    pub fn find_index_for_empty_leaf(&self) -> usize {
        let index = fetch_empty_index(&self.db);
        index as usize
    }

    /// Update the element at index and compute the new tree root
    pub fn update_leaf(&mut self, mut index: usize, mut current: FieldElement) -> FieldElement {
        // Note that this method does not update the list of messages [preimages]|
        // use `update_message` to do this
        self.check_if_index_valid_and_increment(index);

        let mut offset = 0usize;
        let mut layer_size = self.total_size;
        for _ in 0..self.depth {
            insert_hash(&mut self.db, (offset + index) as u32, current);

            index &= (!0) - 1;
            current = self.barretenberg.hash(
                &fetch_hash(&self.db, offset + index),
                &fetch_hash(&self.db, offset + index + 1),
            );

            offset += layer_size as usize;
            layer_size /= 2;
            index /= 2;
        }

        insert_root(&mut self.db, current);
        current
    }
    /// Gets a message at `index`. This is not the leaf
    pub fn get_message_at_index(&self, index: usize) -> Vec<u8> {
        fetch_preimage(&self.db, index)
    }

    pub fn root(&self) -> FieldElement {
        fetch_root(&self.db)
    }
    pub fn depth(&self) -> u32 {
        self.depth
    }
}

// TODO: alter this method so that it only processes one hash per level rather than overriding
// the one of leaves for each level of the hash path
pub fn check_membership<Barretenberg: PathHasher>(
    hash_path: Vec<&FieldElement>,
    root: &FieldElement,
    index: &FieldElement,
    leaf: &FieldElement,
) -> FieldElement {
    let mut barretenberg = Barretenberg::new();

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
        current = barretenberg.hash(&hash_left, &hash_right);
    }
    if &current == root {
        FieldElement::one()
    } else {
        FieldElement::zero()
    }
}
// fn hash(message: &[u8]) -> FieldElement {
//     use blake2::Digest;

//     let mut hasher = blake2::Blake2s::new();
//     hasher.update(message);
//     let res = hasher.finalize();
//     FieldElement::from_be_bytes_reduce(&res[..])
// }
// XXX(FIXME) : Currently, this is very aztec specific, because this PWG does not have
// a way to deal with generic ECC operations
// fn compress_native(
//     barretenberg: &mut Barretenberg,
//     left: &FieldElement,
//     right: &FieldElement,
// ) -> FieldElement {
//     barretenberg.compress_native(left, right)
// }
