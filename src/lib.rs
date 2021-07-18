//! An implementation of the "Merkle Tree-Structured Log" defined in the blog
//! post [Transparent Logs for Skeptical Clients].
//!
//! [Transparent Logs for Skeptical Clients]: https://research.swtch.com/tlog

extern crate digest;

mod error;
mod util;

pub use error::Error;
pub use util::{MemoryStore, Store, TreeID};

use digest::Digest;
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

/// Type alias for nodes in the merkle tree.
pub trait Node: AsRef<[u8]> + Copy + Eq {}
impl<T: AsRef<[u8]> + Copy + Eq> Node for T {}

/// Type alias for a [`HashMap`] containing leaf and tree nodes.
///
/// [`HashMap`]: std::collections::HashMap
pub type Proof<N = [u8; 32]> = HashMap<TreeID, N>;

/// A [Merkle Tree-Structured Log] is a potentially unbalanced merkle tree
/// containing the entries of an append-only log.
///
/// It extends the functionality of a traditional merkle tree by allowing for:
/// - continually appending new entries (even when the length of the log is not
/// a power of two)
/// - providing proofs that a previous log head is a prefix of (contained
/// within) the current log.
///
/// ## Example
/// ```rust
/// use merkle_log::{MemoryStore, MerkleLog, Store};
/// use sha2::Sha256;
///
/// let mut store = MemoryStore::default();
///
/// // first entry
/// let entry = b"hello";
/// let mut log = MerkleLog::<Sha256>::new(&entry);
/// let initial_head = *log.head();
/// let initial_log = log.clone();
/// store.set_leaf(log.head_id(), initial_head).unwrap();
///
/// // second entry
/// let entry = b"world";
/// let new_nodes = log.append(entry, &mut store).unwrap();
/// store.set_many(new_nodes.into_iter()).unwrap();
///
/// // prove existence of initial entry by its digest
/// let proof = log.prove(0, &store).unwrap();
/// assert!(log.verify(0, &initial_head, &proof).unwrap());
/// ```
///
/// [Merkle Tree-Structured Log]: https://research.swtch.com/tlog#merkle_tree-structured_log
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MerkleLog<D: Digest, N = [u8; 32]> {
    /// The index of the log's head.
    index: u64,
    /// The digest of the log's head.
    head: N,
    /// The merkle root of the tree in which this entry is the head.
    root: N,
    /// The underlying digest used by this log.
    #[cfg_attr(feature = "serde", serde(skip))]
    _digest: PhantomData<D>,
}

impl<D, N> MerkleLog<D, N>
where
    D: Digest,
    N: Node + From<digest::Output<D>>,
{
    /// Creates a new [`MerkleLog`] from the first log entry.
    ///
    /// [`MerkleLog`]: crate::MerkleLog
    #[inline]
    pub fn new(entry: impl AsRef<[u8]>) -> Self {
        let head = Self::leaf_hash(entry);
        Self {
            index: 0,
            head,
            root: head,
            _digest: PhantomData,
        }
    }

    /// The unique [`TreeID`] of the current head.
    ///
    /// [`TreeID`]: crate::TreeID
    #[inline(always)]
    pub fn head_id(&self) -> TreeID {
        TreeID::new(0, self.index)
    }

    /// The size of the log.
    #[inline(always)]
    pub fn size(&self) -> u64 {
        self.index + 1
    }

    /// The [`Node`] of the current head.
    ///
    /// [`Node`]: crate::Node
    #[inline(always)]
    pub fn head(&self) -> &N {
        &self.head
    }

    /// The merkle root [`Node`] of the log.
    ///
    /// [`Node`]: crate::Node
    #[inline(always)]
    pub fn root(&self) -> &N {
        &self.root
    }

    /// The unique [`TreeID`] of the current tree root.
    ///
    /// [`TreeID`]: crate::TreeID
    #[inline(always)]
    pub fn root_depth(&self) -> u8 {
        TreeID::root_depth(self.size())
    }

    /// Produces the [`TreeID`]s whose values are required to produce a valid
    /// proof for a particular entry in the log.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::{MemoryStore, MerkleLog, Store, TreeID};
    /// use sha2::Sha256;
    ///
    /// let mut store = MemoryStore::default();
    ///
    /// let entry = b"hello";
    /// let mut log = MerkleLog::<Sha256>::new(&entry);
    /// store.set_leaf(log.head_id(), *log.head()).unwrap();
    ///
    /// let new_nodes = log.append(&entry, &store).unwrap(); // new size 2
    /// store.set_many(new_nodes.into_iter()).unwrap();
    /// let new_nodes = log.append(&entry, &store).unwrap(); // new size 3
    /// store.set_many(new_nodes.into_iter()).unwrap();
    /// assert_eq!(log.proving_ids(1).unwrap(), [TreeID::from(0), TreeID::from(4)].iter().copied().collect());
    ///
    /// let new_nodes = log.append(&entry, &store).unwrap(); // new size 4
    /// store.set_many(new_nodes.into_iter()).unwrap();
    /// assert_eq!(log.proving_ids(1).unwrap(), [TreeID::from(0), TreeID::from(5)].iter().copied().collect());
    /// assert_eq!(log.proving_ids(2).unwrap(), [TreeID::from(1), TreeID::from(6)].iter().copied().collect());
    /// ```
    ///
    /// [`TreeID`]: crate::TreeID
    pub fn proving_ids(&self, entry_index: u64) -> Result<HashSet<TreeID>, Error> {
        let size = self.size();
        let entry_id = TreeID::new(0, entry_index);

        if entry_index > self.index {
            return Err(Error::ProofError(
                "proving index greater than log head index",
            ));
        } else if self.index == 0 {
            return Ok(HashSet::default());
        }

        // if balanced, use traditional merkle tree proof creation
        let root_depth = self.root_depth();
        if size.is_power_of_two() {
            return Ok(entry_id.proving_ids(root_depth, None));
        }

        // otherwise, compute subroots, pushing all but the head
        let subroots = TreeID::subroots(size).ok_or(Error::Overflow)?;
        let mut tree_ids = HashSet::with_capacity(root_depth as usize + subroots.len());
        for subroot_id in subroots.iter() {
            if subroot_id.spans(&entry_id) {
                tree_ids = entry_id.proving_ids(subroot_id.depth(), Some(tree_ids));
            } else {
                tree_ids.insert(*subroot_id);
            }
        }

        Ok(tree_ids)
    }

    /// Creates a proof that an entry is contained within the current log.
    pub fn prove<S: Store<N>>(&self, entry_index: u64, store: &S) -> Result<Proof<N>, Error> {
        store.get_many(self.proving_ids(entry_index)?.iter())
    }

    /// Verifies a proof asserting that the `entry_node` exists at `entry_index`
    /// within the current log.
    pub fn verify(
        &self,
        entry_index: u64,
        entry_node: &N,
        proof: &Proof<N>,
    ) -> Result<bool, Error> {
        let size = self.size();
        let entry_id = TreeID::new(0, entry_index);

        if entry_index > self.index {
            // check if out-of-bounds
            return Err(Error::OutOfBounds);
        } else if size == 1 {
            // verifying a length-1 log
            // index should be 0 and entry_node should be the log's root
            return Ok(entry_index == self.index
                && entry_node == &self.head
                && entry_node == &self.root);
        }

        // if balanced, use traditional merkle tree verification
        if size.is_power_of_two() {
            let root = Self::tree_hash(entry_id, entry_node, self.root_depth(), proof, None)?;
            return Ok(root == self.root);
        }

        // otherwise
        // compute subroots, join them from right to left
        let subroot_ids = TreeID::subroots(size).ok_or(Error::Overflow)?;
        let mut subroots = subroot_ids
            .iter()
            .filter_map(|subroot_id| match subroot_id {
                _ if self.head_id() == *subroot_id => Some(self.head),
                _ if subroot_id.spans(&entry_id) => {
                    Self::tree_hash(entry_id, entry_node, subroot_id.depth(), proof, None).ok()
                }
                _ => proof.get(subroot_id).copied(),
            })
            .rev();

        let first_subroot = subroots.next();
        let root = subroots.fold(first_subroot, |root, subroot| {
            root.map(|root| Self::node_hash(&subroot, &root))
        });

        Ok(root == Some(self.root))
    }

    /// Produces the [`TreeID`]s whose values are required to append the next
    /// entry to log.
    /// See [`TreeID::appending_ids`] for additional doctests.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::{MemoryStore, MerkleLog, Store, TreeID};
    /// use sha2::Sha256;
    ///
    /// let mut store = MemoryStore::default();
    ///
    /// let entry = b"hello";
    /// let mut log = MerkleLog::<Sha256>::new(&entry);
    /// store.set_leaf(log.head_id(), *log.head()).unwrap();
    /// assert_eq!(log.appending_ids().unwrap(), &[TreeID::from(0)]);
    ///
    /// let new_nodes = log.append(&entry, &store).unwrap(); // new size 2
    /// store.set_many(new_nodes.into_iter()).unwrap();
    /// assert_eq!(log.appending_ids().unwrap(), &[TreeID::from(1)]);
    ///
    /// let new_nodes = log.append(&entry, &store).unwrap(); // new size 3
    /// store.set_many(new_nodes.into_iter()).unwrap();
    /// assert_eq!(log.appending_ids().unwrap(), &[TreeID::from(1), TreeID::from(4)]);
    ///
    /// let new_nodes = log.append(&entry, &store).unwrap(); // new size 4
    /// store.set_many(new_nodes.into_iter()).unwrap();
    /// assert_eq!(log.appending_ids().unwrap(), &[TreeID::from(3)]);
    /// ```
    ///
    /// [`TreeID`]: crate::TreeID
    pub fn appending_ids(&self) -> Result<Vec<TreeID>, Error> {
        TreeID::appending_ids(self.size() + 1).ok_or(Error::Overflow)
    }

    /// Appends a new entry to the log, returning the new permanent [`Node`]s to
    /// store.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::{MerkleLog, MemoryStore, Store, TreeID};
    /// use sha2::Sha256;
    ///
    /// let mut store = MemoryStore::default();
    ///
    /// let mut entry = b"hello";
    /// let mut log = MerkleLog::<Sha256>::new(&entry);
    /// store.set_leaf(log.head_id(), *log.head()).unwrap();
    /// assert_eq!(log.size(), 1);
    /// assert_eq!(log.head_id(), TreeID::from(0));
    ///
    /// let new_nodes = log.append(b"world", &mut store).unwrap();
    /// assert_eq!(log.size(), 2);
    /// assert_eq!(log.head_id(), TreeID::from(2));
    /// assert_eq!(new_nodes.get(&TreeID::from(1)).unwrap(), log.root());
    /// ```
    ///
    /// [`Node`]: crate::Node
    pub fn append<S: Store<N>>(
        &mut self,
        entry: impl AsRef<[u8]>,
        store: &S,
    ) -> Result<HashMap<TreeID, N>, Error> {
        let new_index = self.index + 1;
        let new_head_id = TreeID::new(0, new_index);
        let new_head = Self::leaf_hash(entry.as_ref());

        let appending_ids = self.appending_ids()?;
        let mut current = new_head;
        let mut current_id = new_head_id;
        let mut new_nodes = HashMap::with_capacity(appending_ids.len());

        for subroot_id in appending_ids.iter().rev() {
            let subroot = store.get(&subroot_id)?;
            current = Self::node_hash(&subroot, &current);
            current_id = current_id.parent();

            if current_id == subroot_id.parent() {
                new_nodes.insert(current_id, current);
            }
        }

        new_nodes.insert(new_head_id, new_head);

        self.index = new_index;
        self.head = new_head;
        self.root = current;
        Ok(new_nodes)
    }

    pub(crate) fn tree_hash<S: Store<N>>(
        leaf_id: TreeID,
        leaf_node: &N,
        depth: u8,
        in_store: &S,
        mut out_store: Option<&mut HashMap<TreeID, N>>,
    ) -> Result<N, Error> {
        use std::cmp::Ordering::*;

        let mut current_id = leaf_id;
        let mut current = *leaf_node;
        for _ in 0..depth {
            let sibling_id = current_id.sibling();
            let sibling = in_store.get(&sibling_id)?;

            current = match current_id.cmp(&sibling_id) {
                Less => Self::node_hash(&current, &sibling),
                Greater => Self::node_hash(&sibling, &current),
                _ => unreachable!(),
            };
            current_id = current_id.parent();

            if let Some(ref mut out_store) = out_store {
                out_store.insert(current_id, current);
            }
        }

        Ok(current)
    }

    pub(crate) fn node_hash(left: &N, right: &N) -> N {
        N::from(D::new().chain(left).chain(right).finalize())
    }

    /// Computes the hash of an entry.
    pub(crate) fn leaf_hash(entry: impl AsRef<[u8]>) -> N {
        N::from(D::digest(entry.as_ref()))
    }
}

impl<D: Clone + Digest, N: Node> Copy for MerkleLog<D, N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    type TestLog = MerkleLog<Sha256>;

    // reference trees
    // proving (2), providing [0] w/ static {1}:
    //         x
    //    1      \
    // [0]  (2)   4
    //
    // proving (2), providing [0, 5, 9] w/ static {3, 9}:
    //                   7
    //         3                  x
    //     1       [5]      [9]     \
    // [0]  (2)   4   6    8   10    12
    //
    // proving (26), providing [7, 19, 24] with static {7, 19}:
    //                               15
    //              [7]                               \
    //       3               11             [19]        \
    //   1       5       9       13      17      21      25
    // 0   2   4   6   8  10   12  14  16  18  20  22 [24](26)

    fn new() -> (MemoryStore, TestLog) {
        let mut store = MemoryStore::default();
        let log = TestLog::new(&"hello world");
        store.set_leaf(log.head_id(), *log.head()).unwrap();
        (store, log)
    }

    #[test]
    fn creation() {
        let (_, log) = new();
        assert_eq!(log.head_id(), TreeID::from(0));
        assert_eq!(log.size(), 1);
        assert_eq!(log.head(), log.root());
    }

    #[test]
    fn prove_and_verify() {
        let (mut store, mut log) = new();
        let proof = log.prove(0, &store).unwrap();
        assert!(log.verify(0, log.head(), &proof).expect("failed to verify"));

        for idx in 1..=128u64 {
            let entry = format!("hello world x{}", idx);
            let new_nodes = log.append(&entry, &mut store).expect(&format!(
                "should be able to append \"{}\" at idx {}",
                &entry, idx
            ));
            store.set_many(new_nodes.into_iter()).unwrap();
            assert_eq!(log.size(), idx + 1);

            let proof = log.prove(idx, &store).unwrap();
            assert!(
                log.verify(idx, log.head(), &proof)
                    .expect("failed to verify"),
                "failed verification for log of length {}",
                idx + 1
            );
        }
    }
}
