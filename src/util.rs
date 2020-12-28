use crate::{Error, Node};
use std::collections::{BTreeMap, HashMap};

/// Represents access to immutable merkle tree nodes.
#[async_trait::async_trait]
pub trait Store {
    /// Gets an intermediate node by its [`TreeID`].
    ///
    /// [`TreeID`]: crate::TreeID
    async fn get(&self, id: &TreeID) -> Result<Node, Error>;

    /// Stores an intermediate node by its [`TreeID`].
    ///
    /// [`TreeID`]: crate::TreeID
    async fn set(&mut self, id: TreeID, node: &Node) -> Result<(), Error>;
}

/// An in-memory store for the intermediate nodes of a [`MerkleLog`].
///
/// [`MerkleLog`]: crate::MerkleLog
pub type MemoryStore = BTreeMap<TreeID, Node>;

#[async_trait::async_trait]
impl Store for MemoryStore {
    /// # Panics
    ///
    /// Panics if there is no node stored at the given depth and offset.
    async fn get(&self, id: &TreeID) -> Result<Node, Error> {
        self.get(id).copied().ok_or(Error::MissingNode(*id))
    }

    async fn set(&mut self, id: TreeID, node: &Node) -> Result<(), Error> {
        self.insert(id, *node);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Store for HashMap<TreeID, Node> {
    /// # Panics
    ///
    /// Panics if there is no node stored at the given depth and offset.
    async fn get(&self, id: &TreeID) -> Result<Node, Error> {
        self.get(id).copied().ok_or(Error::MissingNode(*id))
    }

    async fn set(&mut self, id: TreeID, node: &Node) -> Result<(), Error> {
        self.insert(id, *node);
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
    /// assert_eq!(TreeID::new(0, 0), 0usize);
    /// assert_eq!(TreeID::new(0, 1), 2usize);
    /// assert_eq!(TreeID::new(0, 2), 4usize);
    /// assert_eq!(TreeID::new(1, 2), 9usize);
    /// assert_eq!(TreeID::new(1, 3), 13usize);
    /// assert_eq!(TreeID::new(2, 1), 11usize);
    /// assert_eq!(TreeID::new(2, 2), 19usize);
    /// assert_eq!(TreeID::new(3, 0), 7usize);
    /// assert_eq!(TreeID::new(3, 1), 23usize);
    /// ```
    #[inline]
    pub const fn new(depth: u8, index: u64) -> Self {
        Self((index << (depth + 1)) | ((1 << depth) - 1))
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
        if self.is_even() {
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
    /// assert_eq!(TreeID::from(0).parent(), 1usize);
    /// assert_eq!(TreeID::from(1).parent(), 3usize);
    /// assert_eq!(TreeID::from(2).parent(), 1usize);
    /// assert_eq!(TreeID::from(3).parent(), 7usize);
    /// assert_eq!(TreeID::from(4).parent(), 5usize);
    /// assert_eq!(TreeID::from(5).parent(), 3usize);
    /// assert_eq!(TreeID::from(6).parent(), 5usize);
    /// assert_eq!(TreeID::from(7).parent(), 15usize);
    /// assert_eq!(TreeID::from(8).parent(), 9usize);
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
    /// assert_eq!(TreeID::from(0).sibling(), 2usize);
    /// assert_eq!(TreeID::from(2).sibling(), 0usize);
    /// assert_eq!(TreeID::from(1).sibling(), 5usize);
    /// assert_eq!(TreeID::from(5).sibling(), 1usize);
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
    /// assert_eq!(TreeID::from(0).uncle(), 5usize);
    /// assert_eq!(TreeID::from(2).uncle(), 5usize);
    /// assert_eq!(TreeID::from(1).uncle(), 11usize);
    /// assert_eq!(TreeID::from(5).uncle(), 11usize);
    /// assert_eq!(TreeID::from(9).uncle(), 3usize);
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
        if self.is_even() {
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
        if self.is_even() {
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
    /// `length`.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::subroots(0), Vec::<TreeID>::new());
    /// assert_eq!(TreeID::subroots(1), &[TreeID::from(0)]);
    /// assert_eq!(TreeID::subroots(2), &[TreeID::from(1)]);
    /// assert_eq!(TreeID::subroots(3), &[TreeID::from(1), TreeID::from(4)]);
    /// assert_eq!(TreeID::subroots(4), &[TreeID::from(3)]);
    /// assert_eq!(TreeID::subroots(5), &[TreeID::from(3), TreeID::from(8)]);
    /// assert_eq!(TreeID::subroots(6), &[TreeID::from(3), TreeID::from(9)]);
    /// assert_eq!(
    ///     TreeID::subroots(7),
    ///     &[TreeID::from(3), TreeID::from(9), TreeID::from(12)]
    /// );
    /// assert_eq!(TreeID::subroots(8), &[TreeID::from(7)]);
    /// assert_eq!(TreeID::subroots(9), &[TreeID::from(7), TreeID::from(16)]);
    /// assert_eq!(TreeID::subroots(10), &[TreeID::from(7), TreeID::from(17)]);
    /// ```
    pub fn subroots(size: u64) -> Vec<Self> {
        let mut subroot_ids = Vec::new();
        if size == 0 {
            return subroot_ids;
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

        subroot_ids
    }

    #[inline]
    pub(crate) fn root_height(size: u64) -> u8 {
        size.next_power_of_two().trailing_zeros() as u8
    }

    const fn is_even(&self) -> bool {
        (self.0 & 1) == 0
    }
}

impl From<u64> for TreeID {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

fn prev_power_of_two(n: u64) -> u64 {
    let n = n >> 1;
    if n.is_power_of_two() {
        (n << 1).next_power_of_two()
    } else {
        n.next_power_of_two()
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
