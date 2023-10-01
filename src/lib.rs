//! An implementation of the "Merkle Tree-Structured Log" defined in the blog
//! post [Transparent Logs for Skeptical Clients].
//!
//! [Transparent Logs for Skeptical Clients]: https://research.swtch.com/tlog

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

mod error;
mod treeid;
mod util;

pub use error::Error;
pub use treeid::TreeID;
pub use util::{Digest, MemoryStore, Store};

use crate::{maybestd::*, util::Either};

#[cfg(not(feature = "std"))]
pub(crate) mod maybestd {
    extern crate alloc;

    pub use alloc::{
        collections::{BTreeMap, BTreeSet},
        vec::Vec,
    };
    pub use core::{iter, marker::PhantomData};
    pub use core2::io::{self, BufRead, Read, Write};
}

#[cfg(feature = "std")]
pub(crate) mod maybestd {
    pub use core2::io::{self, BufRead, Read, Write};
    pub use std::{
        collections::{BTreeMap, BTreeSet},
        iter,
        marker::PhantomData,
        vec::Vec,
    };
}

/// Type alias for nodes in the merkle tree.
pub trait Node: AsRef<[u8]> + Copy + Eq {}
impl<N> Node for N where N: AsRef<[u8]> + Copy + Eq {}

/// Type alias for a [`BTreeMap`] containing leaf and tree nodes.
///
/// [`BTreeMap`]: crate::maybestd::BTreeMap
pub type Proof<N> = BTreeMap<TreeID, N>;

/// A [Merkle Tree-Structured Log] is a potentially unbalanced merkle tree
/// containing the entries of an append-only log (maximum `2^63 + 1` entries).
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
/// use digest::Output;
/// use sha2::Sha256;
///
/// let mut store = MemoryStore::default();
///
/// // first entry
/// let entry = b"hello";
/// let mut log = MerkleLog::<Sha256, [u8; 32]>::new(&entry);
/// let initial_head = *log.head();
/// let initial_log = log.clone();
/// store.set_leaf(log.head_id(), initial_head).unwrap();
///
/// // second entry
/// let entry = b"world";
/// log.append(entry, &mut store).unwrap();
///
/// // prove existence of initial entry by its digest
/// let proof = log.prove(0, &store).unwrap();
/// assert!(log.verify(0, &initial_head, &proof).unwrap());
/// ```
///
/// [Merkle Tree-Structured Log]: https://research.swtch.com/tlog#merkle_tree-structured_log
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshDeserialize, borsh::BorshSerialize)
)]
pub struct MerkleLog<D: Digest<N>, N: Node> {
    /// The digest of the log's head.
    head: N,
    /// The merkle root of the tree in which this entry is the head.
    root: N,
    /// The index of the log's head.
    index: u64,
    /// The underlying digest used by this log.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "borsh", borsh(skip))]
    _digest: PhantomData<D>,
}

impl<D, N> MerkleLog<D, N>
where
    D: Digest<N>,
    N: Node,
{
    /// Creates a new [`MerkleLog`] from the first log entry.
    ///
    /// [`MerkleLog`]: crate::MerkleLog
    #[inline]
    pub fn new(entry: impl AsRef<[u8]>) -> Self {
        let head = D::leaf_digest(entry.as_ref());
        Self {
            index: 0,
            head,
            root: head,
            _digest: PhantomData,
        }
    }

    /// The size of the log.
    #[inline(always)]
    pub const fn len(&self) -> u64 {
        self.index + 1
    }

    /// The [`Node`] of the current head.
    ///
    /// [`Node`]: crate::Node
    #[inline(always)]
    pub const fn head(&self) -> &N {
        &self.head
    }

    /// The unique [`TreeID`] of the current head.
    ///
    /// [`TreeID`]: crate::TreeID
    #[inline(always)]
    pub const fn head_id(&self) -> TreeID {
        TreeID::leaf(self.index)
    }

    /// The merkle root [`Node`] of the log.
    ///
    /// [`Node`]: crate::Node
    #[inline(always)]
    pub const fn root(&self) -> &N {
        &self.root
    }

    /// The unique [`TreeID`] of the current root.
    ///
    /// [`TreeID`]: crate::TreeID
    #[inline(always)]
    pub const fn root_id(&self) -> TreeID {
        TreeID::first(self.root_height())
    }

    /// The unique [`TreeID`] of the current tree root.
    ///
    /// [`TreeID`]: crate::TreeID
    #[inline(always)]
    pub const fn root_height(&self) -> u8 {
        TreeID::root_height(self.len())
    }

    /// Produces the [`TreeID`]s whose values are required to produce a valid
    /// proof of inclusion for a particular leaf entry in the log, starting from
    /// the head.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::{MemoryStore, MerkleLog, Store, TreeID};
    /// use digest::Output;
    /// use sha2::Sha256;
    ///
    /// let mut store = MemoryStore::default();
    ///
    /// let entry = b"hello";
    /// let mut log = MerkleLog::<Sha256, [u8; 32]>::new(&entry);
    /// store.set_leaf(log.head_id(), *log.head()).unwrap();
    ///
    /// log.append(&entry, &mut store).unwrap(); // new size 2
    /// log.append(&entry, &mut store).unwrap(); // new size 3
    /// assert_eq!(log.proving_ids(1).collect::<Vec<_>>(), &[TreeID::from(0), TreeID::from(4)]);
    ///
    /// log.append(&entry, &mut store).unwrap(); // new size 4
    /// assert_eq!(log.proving_ids(1).collect::<Vec<_>>(), &[TreeID::from(0), TreeID::from(5)]);
    /// assert_eq!(log.proving_ids(2).collect::<Vec<_>>(), &[TreeID::from(6), TreeID::from(1)]);
    /// ```
    ///
    /// [`TreeID`]: crate::TreeID
    pub fn proving_ids(&self, entry_index: u64) -> impl Iterator<Item = TreeID> {
        let len = self.len();
        let entry_id = TreeID::leaf(entry_index);

        // if balanced, use traditional merkle tree proof creation
        if len.is_power_of_two() {
            return Either::Left(entry_id.proving_ids(self.root_height()));
        }

        Either::Right(TreeID::subroot_ids(len).flat_map(move |subroot_id| {
            if subroot_id.spans(&entry_id) {
                Either::Left(entry_id.proving_ids(subroot_id.height()))
            } else {
                Either::Right(iter::once(subroot_id))
            }
        }))
    }

    /// Creates a proof that an entry is contained within the current log.
    pub fn prove<S: Store<N>>(&self, entry_index: u64, store: &S) -> Result<Proof<N>, Error> {
        store.get_many(self.proving_ids(entry_index))
    }

    /// Verifies a proof asserting that the `entry_node` exists at `entry_index`
    /// within the current log.
    pub fn verify(
        &self,
        entry_index: u64,
        entry_node: &N,
        proof: &Proof<N>,
    ) -> Result<bool, Error> {
        let len = self.len();
        let entry_id = TreeID::leaf(entry_index);

        if entry_index > self.index {
            // check if out-of-bounds
            return Err(Error::OutOfBounds);
        } else if len == 1 {
            // verifying a length-1 log
            // index should be 0 and entry_node should be the log's root
            return Ok(entry_index == self.index
                && entry_node == &self.head
                && entry_node == &self.root);
        }

        // if balanced, use traditional merkle tree verification
        if len.is_power_of_two() {
            let root = Self::root_hash(entry_id, entry_node, self.root_height(), proof)?;
            return Ok(root == self.root);
        }

        // otherwise
        // compute subroots, join them from right to left
        let head_id = self.head_id();
        let mut subroots = TreeID::subroot_ids(len)
            .filter_map(|subroot_id| match subroot_id {
                _ if &head_id == &subroot_id => Some((head_id, self.head)),
                _ if subroot_id.spans(&entry_id) => {
                    Self::root_hash(entry_id, entry_node, subroot_id.height(), proof)
                        .ok()
                        .map(|subroot| (subroot_id, subroot))
                }
                _ => proof
                    .get(&subroot_id)
                    .copied()
                    .map(|subroot| (subroot_id, subroot)),
            })
            .collect::<Vec<(TreeID, N)>>()
            .into_iter()
            .rev();

        let first_subroot = subroots.next();
        let (_, root) = subroots
            .fold(first_subroot, |root, (subroot_id, subroot)| {
                root.map(|(root_id, root)| D::node_digest((subroot_id, &subroot), (root_id, &root)))
                    .map(|root| (subroot_id.parent(), root))
            })
            .ok_or_else(|| Error::ProofError("failed to compute root digest"))?;

        Ok(root == self.root)
    }

    /// Produces the [`TreeID`]s whose values are required to append the next
    /// entry to log.
    /// See [`TreeID::appending_ids`] for additional doctests.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::{MemoryStore, MerkleLog, Store, TreeID};
    /// use digest::Output;
    /// use sha2::Sha256;
    ///
    /// let mut store = MemoryStore::default();
    ///
    /// let entry = b"hello";
    /// let mut log = MerkleLog::<Sha256, [u8; 32]>::new(&entry);
    /// store.set_leaf(log.head_id(), *log.head()).unwrap();
    /// assert_eq!(log.appending_ids().collect::<Vec<_>>(), &[TreeID::from(0)]);
    ///
    /// log.append(&entry, &mut store).unwrap(); // new size 2
    /// assert_eq!(log.appending_ids().collect::<Vec<_>>(), &[TreeID::from(1)]);
    ///
    /// log.append(&entry, &mut store).unwrap(); // new size 3
    /// assert_eq!(log.appending_ids().collect::<Vec<_>>(), &[TreeID::from(1), TreeID::from(4)]);
    ///
    /// log.append(&entry, &mut store).unwrap(); // new size 4
    /// assert_eq!(log.appending_ids().collect::<Vec<_>>(), &[TreeID::from(3)]);
    /// ```
    ///
    /// [`TreeID`]: crate::TreeID
    #[inline]
    pub fn appending_ids(&self) -> impl Iterator<Item = TreeID> {
        TreeID::appending_ids(self.len() + 1)
    }

    /// Appends a new entry to the log, returning the new permanent [`Node`]s to
    /// store.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::{MerkleLog, MemoryStore, Store, TreeID};
    /// use digest::Output;
    /// use sha2::Sha256;
    ///
    /// let mut store = MemoryStore::default();
    ///
    /// let mut entry = b"hello";
    /// let mut log = MerkleLog::<Sha256, [u8; 32]>::new(&entry);
    /// store.set_leaf(log.head_id(), *log.head()).unwrap();
    /// assert_eq!(log.len(), 1);
    /// assert_eq!(log.head_id(), TreeID::from(0));
    /// assert_eq!(log.head(), store.get(&log.head_id()).unwrap());
    ///
    /// log.append(b"world", &mut store).unwrap();
    /// assert_eq!(log.len(), 2);
    /// assert_eq!(log.head_id(), TreeID::from(2));
    /// assert_eq!(log.root(), store.get(&TreeID::from(1)).unwrap());
    /// ```
    ///
    /// [`Node`]: crate::Node
    pub fn append<S: Store<N>>(
        &mut self,
        entry: impl AsRef<[u8]>,
        store: &mut S,
    ) -> Result<(), Error> {
        let new_index = self.index + 1;
        let new_head_id = TreeID::leaf(new_index);
        let new_head = D::leaf_digest(entry.as_ref());

        let mut current = new_head;
        let mut current_id = new_head_id;
        let mut new_nodes = BTreeMap::new();

        for subroot_id in self
            .appending_ids()
            .collect::<Vec<TreeID>>()
            .into_iter()
            .rev()
        {
            let subroot = store.get(&subroot_id)?;
            current_id = current_id.parent();
            current = D::node_digest((subroot_id, &subroot), (current_id, &current));

            if current_id == subroot_id.parent() {
                new_nodes.insert(current_id, current);
            }
        }

        new_nodes.insert(new_head_id, new_head);
        store.set_many(new_nodes.into_iter())?;

        self.index = new_index;
        self.head = new_head;
        self.root = current;
        Ok(())
    }

    /// Computes the root hash of a balanced merkle tree, starting from the
    /// `leaf_id` node.
    pub(crate) fn root_hash<S: Store<N>>(
        leaf_id: TreeID,
        leaf_node: &N,
        height: u8,
        in_store: &S,
    ) -> Result<N, Error> {
        use core::cmp::Ordering::*;

        let mut current_id = leaf_id;
        let mut current = *leaf_node;
        for _ in 0..height {
            let sibling_id = current_id.sibling();
            let sibling = in_store.get(&sibling_id)?;

            current = match current_id.cmp(&sibling_id) {
                Less => D::node_digest((current_id, &current), (sibling_id, &sibling)),
                Greater => D::node_digest((sibling_id, &sibling), (current_id, &current)),
                _ => unreachable!(),
            };
            current_id = current_id.parent();
        }

        Ok(current)
    }
}

impl<D: Digest<N> + Clone, N: Node> Copy for MerkleLog<D, N> {}
impl<D: Digest<N>, N: Node> PartialEq for MerkleLog<D, N> {
    fn eq(&self, other: &Self) -> bool {
        self.head == other.head
            && self.root == other.root
            && self.index == other.index
            && self._digest == other._digest
    }
}
impl<D: Digest<N>, N: Node> Eq for MerkleLog<D, N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    type TestLog = MerkleLog<Sha256, [u8; 32]>;
    type MemStore = MemoryStore<[u8; 32]>;

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
    // proving (26), providing [7, 19, 21, 24] with static {7, 19}:
    //                               15
    //              [7]                                   \
    //       3               11              [19]          |
    //   1       5       9       13      17       [21]     25
    // 0   2   4   6   8  10   12  14  16  18    20  22 [24](26)

    fn new() -> (MemStore, TestLog) {
        let mut store = MemStore::default();
        let log = TestLog::new(&"hello world");
        let log_head = *log.head();
        store.set_leaf(log.head_id(), log_head).unwrap();
        (store, log)
    }

    #[test]
    fn creation() {
        let (_, log) = new();
        assert_eq!(log.head_id(), TreeID::from(0));
        assert_eq!(log.len(), 1);
        assert_eq!(log.head(), log.root());
    }

    #[test]
    fn prove_and_verify() {
        let (mut store, mut log) = new();
        let proof = log.prove(0, &store).unwrap();
        assert!(log.verify(0, log.head(), &proof).expect("failed to verify"));

        for idx in 1..=128u64 {
            let mut entry = alloc::string::String::new();
            core::fmt::write(&mut entry, format_args!("hello world x{}", idx))
                .expect("failed to generate entry");

            log.append(&entry, &mut store)
                .expect("failed to append entry to log and store");
            assert_eq!(log.len(), idx + 1);

            let proof = log
                .prove(idx, &store)
                .expect("failed to generate inclusion proof from log and store");
            assert!(
                log.verify(idx, log.head(), &proof)
                    .expect("failed to verify"),
                "failed verification for log of length {}",
                idx + 1
            );
        }
    }
}
