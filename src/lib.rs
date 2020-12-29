//! An implementation of the "Merkle Tree-Structured Log" defined in the paper
//! [Transparent Logs for Skeptical Clients].
//!
//! [Transparent Logs for Skeptical Clients]: https://research.swtch.com/tlog

extern crate digest;

mod error;
mod util;

pub use error::Error;
pub use util::{MemoryStore, Store, TreeID};

use digest::Digest;
use std::{collections::HashMap, marker::PhantomData};

/// Type alias for nodes in the merkle tree.
pub type Node = [u8; 32];

/// Type alias for a [`HashMap`] containing leaf and tree nodes.
///
/// [`HashMap`]: std::collections::HashMap
pub type Proof = HashMap<TreeID, Node>;

/// A [Merkle Tree-Structured Log] is a potentially unbalanced merkle tree
/// containing the entries of an append-only log.
///
/// It extends a traditional merkle tree by allowing for:
///
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
/// #[async_std::main]
/// async fn main() {
///     let mut store = MemoryStore::default();
///
///     // first entry
///     let entry = b"hello";
///     let mut log = MerkleLog::<Sha256>::new(&entry, &mut store).await.unwrap();
///     let initial_head = *log.head();
///     let initial_log = log.clone();
///
///     // second entry
///     let entry = b"world";
///     log.append(entry, &mut store).await.unwrap();
///
///     // prove existence of initial entry by its digest
///     let proof = log.prove(0, &initial_head, &store).await.unwrap();
///     assert!(log.verify(0, &initial_head, &proof));
///
///     // prove that head is a prefix of the current log
///     let (prefix_proof, head_proof) = log.prove_prefix(&initial_log, &store).await.unwrap();
///     assert!(log.verify_prefix(&head_proof, &initial_log, &prefix_proof));
/// }
/// ```
///
/// [Merkle Tree-Structured Log]: https://research.swtch.com/tlog#merkle_tree-structured_log
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MerkleLog<D: Digest> {
    /// The index of the log's head.
    index: u64,
    /// The digest of the log's head.
    head: Node,
    /// The merkle root of the tree in which this entry is the head.
    root: Node,
    /// The underlying digest used by this log.
    #[cfg_attr(feature = "serde", serde(skip))]
    _digest: PhantomData<D>,
}

impl<D: Digest> MerkleLog<D> {
    /// Creates a new [`MerkleLog`] from the first log entry.
    #[inline]
    pub async fn new<S: Store>(entry: impl AsRef<[u8]>, store: &mut S) -> Result<Self, Error> {
        let head = Self::leaf_hash(entry.as_ref());
        let log = Self {
            index: 0,
            head,
            root: head,
            _digest: PhantomData,
        };
        store.set(log.head_id(), &log.head).await?;
        Ok(log)
    }

    /// The unique [`TreeID`] of the current tree root.
    /// [`TreeID`]: crate::TreeID
    #[inline(always)]
    pub fn root_id(&self) -> TreeID {
        TreeID::new(TreeID::root_height(self.size()), 0)
    }

    /// The unique [`TreeID`] of the current head.
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

    /// The digest of the current head.
    #[inline(always)]
    pub fn head(&self) -> &Node {
        &self.head
    }

    /// The merkle root of the log.
    #[inline(always)]
    pub fn root(&self) -> &Node {
        &self.root
    }

    /// Creates a proof that a prior entry is contained within the current log.
    pub async fn prove<S: Store>(
        &self,
        entry_index: u64,
        entry_node: &Node,
        store: &S,
    ) -> Result<Proof, Error> {
        let mut proof = Proof::new();
        let size = self.size();
        let entry_id = TreeID::new(0, entry_index);

        if entry_index > self.index {
            return Err(Error::ProofError(
                "proving index greater than log head index",
            ));
        } else if size == 1 {
            return Ok(proof);
        }

        // if balanced, use traditional merkle tree proof creation
        if size.is_power_of_two() {
            return Self::tree_proof(entry_id, entry_node, self.root_id().depth(), proof, store)
                .await;
        }

        // otherwise, compute subroots, pushing all but the head
        let subroot_ids = TreeID::subroots(size);
        for subroot_id in subroot_ids.iter() {
            if subroot_id == &self.head_id() {
                continue;
            } else if subroot_id.spans(&entry_id) {
                proof = Self::tree_proof(entry_id, entry_node, subroot_id.depth(), proof, store)
                    .await?;
            } else {
                proof.insert(*subroot_id, store.get(subroot_id).await?);
            }
        }
        Ok(proof)
    }

    /// Verifies a proof asserting that the`entry_node` exists at `entry_index`
    /// within the current log.
    pub fn verify(&self, entry_index: u64, entry_node: &Node, proof: &Proof) -> bool {
        let size = self.size();
        let entry_id = TreeID::new(0, entry_index);

        if entry_index > self.index {
            // check if out-of-bounds
            return false;
        } else if size == 1 {
            // verifying a length-1 log
            // index should be 0 and entry_node should be the log's root
            return entry_index == self.index && entry_node == &self.root;
        }

        // if balanced, use traditional merkle tree verification
        if size.is_power_of_two() {
            return Self::tree_hash(entry_id, entry_node, self.root_id().depth(), proof)
                .filter(|root| root == &self.root)
                .is_some();
        }

        // otherwise
        // compute subroots, join them from right to left
        let subroot_ids = TreeID::subroots(size);
        let mut subroots = subroot_ids
            .iter()
            .filter_map(|subroot_id| match subroot_id {
                _ if subroot_id == &self.head_id() => Some(self.head),
                _ if subroot_id.spans(&entry_id) => {
                    Self::tree_hash(entry_id, entry_node, subroot_id.depth(), proof)
                }
                _ => proof.get(&subroot_id).copied(),
            })
            .rev();

        let first_subroot = subroots.next();
        let root = subroots.fold(first_subroot, |root, subroot| {
            root.map(|root| Self::node_hash(&subroot, &root))
        });
        root == Some(self.root)
    }

    /// Creates a proof that a prior log head is a prefix of the current log,
    /// as well as a proof that the current head is within the same log.
    ///
    /// This involves producing a set of nodes, some of which are common to the
    /// subtree containing the prefix and the full tree containing both the
    /// prefix and the head. Verifying these proofs should convince the
    /// verifier that both the prefix and the head belong to the same log.
    pub async fn prove_prefix<S: Store>(
        &self,
        prefix: &Self,
        store: &S,
    ) -> Result<(Proof, Proof), Error> {
        let prefix_proof = prefix.prove(prefix.index, &prefix.head, store).await?;
        let head_proof = self.prove(self.index, &self.head, store).await?;
        Ok((prefix_proof, head_proof))
    }

    /// Verifies the prefix and head proofs against a known prefix and the
    /// current log.
    pub fn verify_prefix(&self, head_proof: &Proof, prefix: &Self, prefix_proof: &Proof) -> bool {
        prefix.verify(prefix.index, &prefix.head, prefix_proof)
            && self.verify(self.index, &self.head, head_proof)
    }

    /// Appends a new entry to the log.
    pub async fn append<S: Store>(
        &mut self,
        entry: impl AsRef<[u8]>,
        store: &mut S,
    ) -> Result<Node, Error> {
        let new_head = Self::leaf_hash(entry.as_ref());
        let new_index = self.index + 1;
        let new_size = new_index + 1;
        let new_head_id = TreeID::new(0, new_index);
        store.set(new_head_id, &new_head).await?;

        let root_height = TreeID::root_height(new_size);
        let new_subroot_ids = TreeID::subroots(new_size);
        let last_subroot_id = new_subroot_ids.last().unwrap();

        let mut current_id = new_head_id;
        let mut current = new_head;
        let new_root = if new_subroot_ids.len() == 1 {
            // addition will complete the tree
            // store every parent up to root
            // then compute, store and return root
            for i in 0..root_height {
                let sibling = match i {
                    0 => self.head,
                    _ => store.get(&current_id.sibling()).await?,
                };
                current_id = current_id.parent();
                current = Self::node_hash(&sibling, &current);
                store.set(current_id, &current).await?;
            }
            current
        } else {
            if last_subroot_id != &new_head_id {
                // addition will complete a subtree
                // store every parent up to subroot
                // then compute and return root
                for i in 0..last_subroot_id.depth() {
                    let sibling = match i {
                        0 => self.head,
                        _ => store.get(&current_id.sibling()).await?,
                    };
                    current_id = current_id.parent();
                    current = Self::node_hash(&sibling, &current);
                    store.set(current_id, &current).await?;
                }
            }

            for subroot_id in new_subroot_ids.iter().rev().skip(1) {
                let subroot = store.get(&subroot_id).await?;
                current = Self::node_hash(&subroot, &current);
            }
            current
        };

        self.index = new_index;
        self.head = new_head;
        self.root = new_root;
        Ok(new_head)
    }

    pub(crate) async fn tree_proof<S: Store>(
        leaf_id: TreeID,
        leaf_node: &Node,
        depth: u8,
        mut proof: Proof,
        store: &S,
    ) -> Result<Proof, Error> {
        use std::cmp::Ordering::*;

        let mut current_id = leaf_id;
        let mut current = *leaf_node;
        for _ in 0..depth {
            let sibling_id = current_id.sibling();
            let sibling = store.get(&sibling_id).await?;
            current = match current_id.cmp(&sibling_id) {
                Less => Self::node_hash(&current, &sibling),
                Greater => Self::node_hash(&sibling, &current),
                _ => unreachable!(),
            };
            current_id = current_id.parent();

            proof.insert(sibling_id, sibling);
        }

        Ok(proof)
    }

    pub(crate) fn tree_hash(
        leaf_id: TreeID,
        leaf_node: &Node,
        depth: u8,
        proof: &Proof,
    ) -> Option<Node> {
        use std::cmp::Ordering::*;

        let mut current_id = leaf_id;
        let mut current = *leaf_node;
        for _ in 0..depth {
            let sibling_id = current_id.sibling();
            let sibling = proof.get(&sibling_id)?;
            current = match current_id.cmp(&sibling_id) {
                Less => Self::node_hash(&current, sibling),
                Greater => Self::node_hash(sibling, &current),
                _ => unreachable!(),
            };
            current_id = current_id.parent();
        }
        Some(current)
    }

    pub(crate) fn node_hash(left: &Node, right: &Node) -> Node {
        let mut node = Node::default();
        let digest = D::new().chain(left).chain(right).finalize();
        node.copy_from_slice(digest.as_slice());
        node
    }

    pub(crate) fn leaf_hash(entry: &[u8]) -> Node {
        let mut node = Node::default();
        node.copy_from_slice(D::digest(entry).as_slice());
        node
    }
}

impl<D: Clone + Digest> Copy for MerkleLog<D> where digest::Output<D>: Copy {}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    type Log = MerkleLog<Sha256>;
    static INITIAL_ENTRY: &str = "hello world";

    // reference trees
    // proving (2), providing [0]:
    //         3
    //    1      \
    // [0]  (2)   4
    //
    // proving (2), providing [0, 5, 9]:
    //                   7
    //         3                  x
    //     1       [5]      [9]      \
    // [0]  (2)   4   6    8   10    12
    //
    // proving (26), providing [7, 19, 24]
    //                               15
    //              [7]
    //       3               11             [19]
    //   1       5       9       13      17      21      25
    // 0   2   4   6   8  10   12  14  16  18  20  22 [24](26)

    #[async_std::test]
    async fn creation() {
        let (_, log) = init().await;
        assert_eq!(log.head_id(), TreeID::from(0));
        assert_eq!(log.size(), 1);
        assert_eq!(log.head(), log.root());
    }

    #[async_std::test]
    async fn prove_and_verify() {
        let (mut store, mut log) = init().await;
        let proof = log.prove(0, log.head(), &store).await.unwrap();
        assert!(log.verify(0, log.head(), &proof));

        for idx in 1..=64u64 {
            let entry = format!("hello world x{}", idx);
            let head = log.append(&entry, &mut store).await.unwrap();
            assert_eq!(log.size(), idx + 1);
            assert_eq!(log.head(), &head);

            let proof = log.prove(idx, &head, &store).await.unwrap();
            assert!(
                log.verify(idx, &head, &proof),
                "failed verification for log of length {}",
                idx + 1
            );
        }
    }

    #[async_std::test]
    async fn prove_and_verify_prefix() {
        let (mut store, mut log) = init().await;
        let initial_log = log.clone();

        for idx in 1..=64u64 {
            let entry = format!("hello world x{}", idx);
            let head = log.append(&entry, &mut store).await.unwrap();
            assert_eq!(log.size(), idx + 1);
            assert_eq!(log.head(), &head);

            let (prefix_proof, mut head_proof) =
                log.prove_prefix(&initial_log, &store).await.unwrap();
            assert!(
                log.verify_prefix(&mut head_proof, &initial_log, &prefix_proof),
                "failed prefix verification for log of length {}",
                idx + 1
            );
        }
    }

    async fn init() -> (MemoryStore, Log) {
        let mut store = MemoryStore::default();
        let log = Log::new(&INITIAL_ENTRY, &mut store).await.unwrap();
        (store, log)
    }
}
