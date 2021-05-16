use crate::{Error, Node};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Represents access to immutable merkle tree nodes.
pub trait Store<N: Node = [u8; 32]> {
    /// Gets an intermediate [`Node`] by its [`TreeID`].
    ///
    /// [`Node`]: crate::Node
    /// [`TreeID`]: crate::TreeID
    fn get_node(&self, id: &TreeID) -> Result<N, Error>;

    /// Stores an intermediate [`Node`] by its [`TreeID`].
    ///
    /// [`Node`]: crate::Node
    /// [`TreeID`]: crate::TreeID
    fn set_node(&mut self, id: TreeID, node: N) -> Result<(), Error>;

    /// Gets a leaf [`Node`] by its [`TreeID`].
    ///
    /// [`Node`]: crate::Node
    /// [`TreeID`]: crate::TreeID
    fn get_leaf(&self, id: &TreeID) -> Result<N, Error>;

    /// Stores a leaf [`Node`] by its [`TreeID`].
    ///
    /// [`Node`]: crate::Node
    /// [`TreeID`]: crate::TreeID
    fn set_leaf(&mut self, id: TreeID, leaf: N) -> Result<(), Error>;

    /// Gets a [`Node`] by its [`TreeID`].
    ///
    /// [`Node`]: crate::Node
    /// [`TreeID`]: crate::TreeID
    fn get(&self, id: &TreeID) -> Result<N, Error> {
        if id.is_leaf() {
            self.get_leaf(id)
        } else {
            self.get_node(id)
        }
    }

    /// Stores a [`Node`] by its [`TreeID`].
    ///
    /// [`Node`]: crate::Node
    /// [`TreeID`]: crate::TreeID
    fn set(&mut self, id: TreeID, node: N) -> Result<(), Error> {
        if id.is_leaf() {
            self.set_leaf(id, node)
        } else {
            self.set_node(id, node)
        }
    }

    /// Gets many [`Node`]s from an [`Iterator`] of [`TreeID`]s.
    ///
    /// [`Node`]: crate::Node
    /// [`TreeID`]: crate::TreeID
    fn get_many<'a, I: Iterator<Item = &'a TreeID>>(
        &self,
        ids: I,
    ) -> Result<HashMap<TreeID, N>, Error> {
        let mut nodes = HashMap::new();
        for id in ids {
            nodes.insert(*id, self.get(id)?);
        }
        Ok(nodes)
    }

    /// Sets many [`Node`]s from an [`Iterator`] of [`TreeID`]s and [`Node`]s.
    ///
    /// [`Node`]: crate::Node
    /// [`TreeID`]: crate::TreeID
    fn set_many<I: Iterator<Item = (TreeID, N)>>(&mut self, nodes: I) -> Result<(), Error> {
        for (id, node) in nodes {
            self.set(id, node)?
        }
        Ok(())
    }
}

/// An in-memory store for the intermediate nodes of a [`MerkleLog`].
///
/// [`MerkleLog`]: crate::MerkleLog
pub type MemoryStore<N = [u8; 32]> = HashMap<TreeID, N>;

impl<N: Node> Store<N> for HashMap<TreeID, N> {
    /// Delegates to [`HashMap::get`].
    ///
    /// [`Node`]: crate::Node
    /// [`HashMap::get`]: std::collections::HashMap::get
    #[inline]
    fn get_node(&self, id: &TreeID) -> Result<N, Error> {
        let node = self.get(id).ok_or(Error::MissingNode(*id))?;
        Ok(*node)
    }

    /// Delegates to [`HashMap::insert`].
    ///
    /// [`HashMap::insert`]: std::collections::HashMap::insert
    #[inline]
    fn set_node(&mut self, id: TreeID, node: N) -> Result<(), Error> {
        self.insert(id, node);
        Ok(())
    }

    /// Delegates to [`HashMap::get`].
    ///
    /// [`Node`]: crate::Node
    /// [`HashMap::get`]: std::collections::HashMap::get
    #[inline]
    fn get_leaf(&self, id: &TreeID) -> Result<N, Error> {
        let leaf = self.get(id).ok_or(Error::MissingNode(*id))?;
        Ok(*leaf)
    }

    /// Delegates to [`HashMap::insert`].
    ///
    /// [`HashMap::insert`]: std::collections::HashMap::insert
    #[inline]
    fn set_leaf(&mut self, id: TreeID, leaf: N) -> Result<(), Error> {
        self.insert(id, leaf);
        Ok(())
    }
}

impl<N: Node> Store<N> for BTreeMap<TreeID, N> {
    /// Delegates to [`BTreeMap::get`].
    ///
    /// [`Node`]: crate::Node
    /// [`BTreeMap::get`]: std::collections::BTreeMap::get
    #[inline]
    fn get_node(&self, id: &TreeID) -> Result<N, Error> {
        let node = self.get(id).ok_or(Error::MissingNode(*id))?;
        Ok(*node)
    }

    /// Delegates to [`BTreeMap::insert`].
    ///
    /// [`BTreeMap::insert`]: std::collections::BTreeMap::insert
    #[inline]
    fn set_node(&mut self, id: TreeID, node: N) -> Result<(), Error> {
        self.insert(id, node);
        Ok(())
    }

    /// Delegates to [`BTreeMap::get`].
    ///
    /// [`Node`]: crate::Node
    /// [`BTreeMap::get`]: std::collections::BTreeMap::get
    #[inline]
    fn get_leaf(&self, id: &TreeID) -> Result<N, Error> {
        let leaf = self.get(id).ok_or(Error::MissingNode(*id))?;
        Ok(*leaf)
    }

    /// Delegates to [`BTreeMap::insert`].
    ///
    /// [`BTreeMap::insert`]: std::collections::BTreeMap::insert
    #[inline]
    fn set_leaf(&mut self, id: TreeID, leaf: N) -> Result<(), Error> {
        self.insert(id, leaf);
        Ok(())
    }
}

/// Unique identifiers for binary tree nodes. Reproduced from [flat-tree].
///
/// [flat-tree]: https://docs.rs/flat-tree
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TreeID(u64);

impl TreeID {
    /// Returns a node's unique id within the tree, given its depth and index.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::new(0, 0), TreeID::from(0));
    /// assert_eq!(TreeID::new(0, 1), TreeID::from(2));
    /// assert_eq!(TreeID::new(0, 2), TreeID::from(4));
    /// assert_eq!(TreeID::new(1, 0), TreeID::from(1));
    /// assert_eq!(TreeID::new(1, 1), TreeID::from(5));
    /// assert_eq!(TreeID::new(1, 2), TreeID::from(9));
    /// assert_eq!(TreeID::new(1, 3), TreeID::from(13));
    /// assert_eq!(TreeID::new(2, 0), TreeID::from(3));
    /// assert_eq!(TreeID::new(2, 1), TreeID::from(11));
    /// assert_eq!(TreeID::new(2, 2), TreeID::from(19));
    /// assert_eq!(TreeID::new(3, 0), TreeID::from(7));
    /// assert_eq!(TreeID::new(3, 1), TreeID::from(23));
    /// ```
    #[inline]
    pub const fn new(depth: u8, index: u64) -> Self {
        Self((index << (depth + 1)) | ((1 << depth) - 1))
    }

    /// Determines if the id represents a leaf node.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).is_leaf(), true);
    /// assert_eq!(TreeID::from(1).is_leaf(), false);
    /// assert_eq!(TreeID::from(2).is_leaf(), true);
    /// assert_eq!(TreeID::from(3).is_leaf(), false);
    /// ```
    #[inline]
    pub const fn is_leaf(&self) -> bool {
        (self.0 & 1) == 0
    }

    /// Returns a node's index among nodes of the same depth.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).index(), 0);
    /// assert_eq!(TreeID::from(1).index(), 0);
    /// assert_eq!(TreeID::from(2).index(), 1);
    /// assert_eq!(TreeID::from(3).index(), 0);
    /// assert_eq!(TreeID::from(4).index(), 2);
    /// ```
    #[inline]
    pub const fn index(&self) -> u64 {
        if self.is_leaf() {
            self.0 >> 1
        } else {
            self.0 >> (self.depth() + 1)
        }
    }

    /// Returns a node's depth in the tree.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).depth(), 0);
    /// assert_eq!(TreeID::from(1).depth(), 1);
    /// assert_eq!(TreeID::from(2).depth(), 0);
    /// assert_eq!(TreeID::from(3).depth(), 2);
    /// assert_eq!(TreeID::from(4).depth(), 0);
    /// ```
    #[inline]
    pub const fn depth(&self) -> u8 {
        (!self.0).trailing_zeros() as u8
    }

    /// Returns the parent id of a node.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).parent(), TreeID::from(1));
    /// assert_eq!(TreeID::from(1).parent(), TreeID::from(3));
    /// assert_eq!(TreeID::from(2).parent(), TreeID::from(1));
    /// assert_eq!(TreeID::from(3).parent(), TreeID::from(7));
    /// assert_eq!(TreeID::from(4).parent(), TreeID::from(5));
    /// assert_eq!(TreeID::from(5).parent(), TreeID::from(3));
    /// assert_eq!(TreeID::from(6).parent(), TreeID::from(5));
    /// assert_eq!(TreeID::from(7).parent(), TreeID::from(15));
    /// assert_eq!(TreeID::from(8).parent(), TreeID::from(9));
    /// ```
    #[inline]
    pub const fn parent(&self) -> Self {
        TreeID::new(self.depth() + 1, self.index() >> 1)
    }

    /// Returns the sibling id of a node.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).sibling(), TreeID::from(2));
    /// assert_eq!(TreeID::from(2).sibling(), TreeID::from(0));
    /// assert_eq!(TreeID::from(1).sibling(), TreeID::from(5));
    /// assert_eq!(TreeID::from(5).sibling(), TreeID::from(1));
    /// ```
    #[inline]
    pub const fn sibling(&self) -> Self {
        TreeID::new(self.depth(), self.index() ^ 1)
    }

    /// Given a node, returns its parent's sibling's id.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).uncle(), TreeID::from(5));
    /// assert_eq!(TreeID::from(2).uncle(), TreeID::from(5));
    /// assert_eq!(TreeID::from(1).uncle(), TreeID::from(11));
    /// assert_eq!(TreeID::from(5).uncle(), TreeID::from(11));
    /// assert_eq!(TreeID::from(9).uncle(), TreeID::from(3));
    /// ```
    #[inline]
    pub const fn uncle(&self) -> Self {
        TreeID::new(self.depth() + 1, self.parent().index() ^ 1)
    }

    /// Returns the id of the node's left child.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).left(), None);
    /// assert_eq!(TreeID::from(1).left(), Some(TreeID::from(0)));
    /// assert_eq!(TreeID::from(3).left(), Some(TreeID::from(1)));
    /// ```
    #[inline]
    pub const fn left(&self) -> Option<Self> {
        let depth = self.depth();
        if self.is_leaf() {
            None
        } else if depth == 0 {
            Some(*self)
        } else {
            Some(Self::new(depth - 1, self.index() << 1))
        }
    }

    /// Returns the id of the node's right child.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).right(), None);
    /// assert_eq!(TreeID::from(1).right(), Some(TreeID::from(2)));
    /// assert_eq!(TreeID::from(3).right(), Some(TreeID::from(5)));
    /// ```
    #[inline]
    pub const fn right(&self) -> Option<Self> {
        let depth = self.depth();
        if self.is_leaf() {
            None
        } else if depth == 0 {
            Some(*self)
        } else {
            Some(Self::new(depth - 1, (self.index() << 1) + 1))
        }
    }

    /// Returns the left- and right-most node ids in the tree the node spans.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).span(), (TreeID::from(0), TreeID::from(0)));
    /// assert_eq!(TreeID::from(1).span(), (TreeID::from(0), TreeID::from(2)));
    /// assert_eq!(TreeID::from(3).span(), (TreeID::from(0), TreeID::from(6)));
    /// assert_eq!(TreeID::from(23).span(), (TreeID::from(16), TreeID::from(30)));
    /// assert_eq!(TreeID::from(27).span(), (TreeID::from(24), TreeID::from(30)));
    /// ```
    #[inline]
    pub const fn span(&self) -> (Self, Self) {
        let depth = self.depth();
        if depth == 0 {
            (*self, *self)
        } else {
            let idx = self.index();
            let distance = 2u64 << depth;
            (Self(idx * distance), Self((idx + 1) * distance - 2))
        }
    }

    /// Determines if the id's tree spans (i.e. contains) another id.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).spans(&TreeID::from(0)), true);
    /// assert_eq!(TreeID::from(0).spans(&TreeID::from(1)), false);
    /// assert_eq!(TreeID::from(1).spans(&TreeID::from(0)), true);
    /// assert_eq!(TreeID::from(1).spans(&TreeID::from(1)), true);
    /// assert_eq!(TreeID::from(1).spans(&TreeID::from(2)), true);
    /// assert_eq!(TreeID::from(3).spans(&TreeID::from(1)), true);
    /// assert_eq!(TreeID::from(3).spans(&TreeID::from(5)), true);
    /// assert_eq!(TreeID::from(3).spans(&TreeID::from(7)), false);
    /// ```
    #[inline]
    pub fn spans(&self, other: &Self) -> bool {
        let (ref left, ref right) = self.span();
        left <= other && other <= right
    }

    /// The root ids of the highest complete subtrees within a log of a given
    /// `size`, sorted left to right.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::subroots(0), None);
    /// assert_eq!(TreeID::subroots(1).unwrap(), &[TreeID::from(0)]);
    /// assert_eq!(TreeID::subroots(2).unwrap(), &[TreeID::from(1)]);
    /// assert_eq!(TreeID::subroots(3).unwrap(), &[TreeID::from(1), TreeID::from(4)]);
    /// assert_eq!(TreeID::subroots(4).unwrap(), &[TreeID::from(3)]);
    /// assert_eq!(TreeID::subroots(5).unwrap(), &[TreeID::from(3), TreeID::from(8)]);
    /// assert_eq!(TreeID::subroots(6).unwrap(), &[TreeID::from(3), TreeID::from(9)]);
    /// assert_eq!(TreeID::subroots(7).unwrap(), &[TreeID::from(3), TreeID::from(9), TreeID::from(12)]);
    /// assert_eq!(TreeID::subroots(8).unwrap(), &[TreeID::from(7)]);
    /// assert_eq!(TreeID::subroots(9).unwrap(), &[TreeID::from(7), TreeID::from(16)]);
    /// assert_eq!(TreeID::subroots(10).unwrap(), &[TreeID::from(7), TreeID::from(17)]);
    /// ```
    pub fn subroots(size: u64) -> Option<Vec<Self>> {
        // a log larger than this wouldn't have a valid TreeID
        const MAX_SIZE: u64 = u64::max_value() >> 2;

        let mut subroot_ids = Vec::<Self>::new();
        if size == 0 || size > MAX_SIZE {
            return None;
        }

        // write size as sum of decreasing powers of two
        // push each subtree root id whose length is a power of two
        let mut sum = 0u64;
        while sum < size {
            let subtree_size = prev_power_of_two(size - sum);
            let depth = subtree_size.trailing_zeros() as u8;

            sum += subtree_size;
            subroot_ids.push(match subroot_ids.last() {
                None => Self::new(depth, 0),
                Some(_) if depth == 0 => Self::new(0, size - 1),
                Some(prev_id) => {
                    let index = ((prev_id.index() + 1) << (prev_id.depth() - depth)) as u64;
                    Self::new(depth, index)
                }
            });
        }

        Some(subroot_ids)
    }

    /// Given the id of a node in a balanced tree, produce the ids of nodes
    /// required for a merkle tree proof, excluding the root.
    ///
    /// ## Examples
    /// ```rust
    /// use std::collections::HashSet;
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).proving_ids(0, None), HashSet::<TreeID>::new());
    /// assert_eq!(TreeID::from(0).proving_ids(1, None), [TreeID::from(2)].iter().copied().collect());
    /// assert_eq!(TreeID::from(0).proving_ids(2, None), [TreeID::from(2), TreeID::from(5)].iter().copied().collect());
    /// ```
    #[inline]
    pub fn proving_ids(&self, root_depth: u8, tree_ids: Option<HashSet<Self>>) -> HashSet<Self> {
        let mut tree_ids =
            tree_ids.unwrap_or_else(|| HashSet::with_capacity(root_depth as usize + 1usize));
        let mut current_id = *self;
        for _ in 0..root_depth {
            tree_ids.insert(current_id.sibling());
            current_id = current_id.parent();
        }
        tree_ids
    }

    /// The ids whose values are required to append the next entry to the log,
    /// sorted left to right.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::appending_ids(0), None);
    /// assert_eq!(TreeID::appending_ids(1).unwrap(), Vec::<TreeID>::new());
    /// assert_eq!(TreeID::appending_ids(2).unwrap(), &[TreeID::from(0)]);
    /// assert_eq!(TreeID::appending_ids(3).unwrap(), &[TreeID::from(1)]);
    /// assert_eq!(TreeID::appending_ids(4).unwrap(), &[TreeID::from(1), TreeID::from(4)]);
    /// assert_eq!(TreeID::appending_ids(5).unwrap(), &[TreeID::from(3)]);
    /// assert_eq!(TreeID::appending_ids(6).unwrap(), &[TreeID::from(3), TreeID::from(8)]);
    /// assert_eq!(TreeID::appending_ids(7).unwrap(), &[TreeID::from(3), TreeID::from(9)]);
    /// assert_eq!(TreeID::appending_ids(8).unwrap(), &[TreeID::from(3), TreeID::from(9), TreeID::from(12)]);
    /// assert_eq!(TreeID::appending_ids(9).unwrap(), &[TreeID::from(7)]);
    /// assert_eq!(TreeID::appending_ids(10).unwrap(), &[TreeID::from(7), TreeID::from(16)]);
    /// ```
    #[inline]
    pub fn appending_ids(new_size: u64) -> Option<Vec<Self>> {
        match new_size {
            0 => None,
            1 => Some(Vec::default()),
            _ => Self::subroots(new_size - 1),
        }
    }

    #[inline]
    pub(crate) const fn root_depth(size: u64) -> u8 {
        size.next_power_of_two().trailing_zeros() as u8
    }

    #[inline]
    pub(crate) const fn root_id(size: u64) -> Self {
        Self::new(Self::root_depth(size), 0)
    }
}

const fn prev_power_of_two(n: u64) -> u64 {
    let n = n >> 1;
    if n.is_power_of_two() {
        (n << 1).next_power_of_two()
    } else {
        n.next_power_of_two()
    }
}

impl From<u64> for TreeID {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

macro_rules! derive_eq {
    ($type:ty) => {
        impl PartialEq<$type> for TreeID {
            fn eq(&self, other: &$type) -> bool {
                self.0 == *other as u64
            }
        }
    };
}

derive_eq!(usize);
derive_eq!(u8);
derive_eq!(u16);
derive_eq!(u32);
derive_eq!(u64);
