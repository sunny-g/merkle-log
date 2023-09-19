use crate::{maybestd::iter, util::Either};

/// Unique identifiers for binary tree nodes. Reproduced from [flat-tree].
///
/// [flat-tree]: https://docs.rs/flat-tree
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TreeID(u64);

impl TreeID {
    ///
    /// a log longer than this wouldn't have a valid TreeID
    #[doc(hidden)]
    pub const MAX_LEN: u64 = Self::MAX_LEAF_INDEX + 1;

    /// The maximum index of a leaf's [`TreeID`].
    #[doc(hidden)]
    pub const MAX_LEAF_INDEX: u64 = u64::MAX >> 1;

    /// The maximum sort index of a [`TreeID`].
    #[doc(hidden)]
    pub const MAX_SORT_INDEX: u64 = u64::MAX - 1;

    /// The maximum height of a [`TreeID`].
    ///
    /// we need 1 more bit than the id's size to represent all ids, so cap
    /// the height to one less bit
    #[doc(hidden)]
    pub const MAX_HEIGHT: u8 = (u64::BITS - 1) as u8;

    /// The highest root [`TreeID`] of a full [`MerkleLog`].
    pub const ROOT: Self = Self(Self::MAX_LEAF_INDEX);

    /// The [`TreeID`] of the very first leaf.
    pub const MIN_LEAF: Self = Self::leaf(0);

    /// The [`TreeID`] of the very last leaf.
    pub const MAX_LEAF: Self = Self::leaf(Self::MAX_LEAF_INDEX);

    /// Returns a node's unique id within the tree, given its height and index.
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
    pub const fn new(height: u8, index: u64) -> Self {
        debug_assert!(height <= Self::MAX_HEIGHT);
        debug_assert!(index <= (Self::MAX_LEAF_INDEX >> height));
        if height == Self::MAX_HEIGHT {
            Self::ROOT
        } else {
            Self((index << (height + 1)) | ((1 << height) - 1))
        }
    }

    /// Returns the first node's unique id at a given height.
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::first(0), TreeID::from(0));
    /// assert_eq!(TreeID::first(1), TreeID::from(1));
    /// assert_eq!(TreeID::first(2), TreeID::from(3));
    /// // test roots
    /// assert_eq!(TreeID::first(62), TreeID::ROOT.left().unwrap());
    /// assert_eq!(TreeID::first(TreeID::MAX_HEIGHT), TreeID::ROOT);
    /// ```
    #[inline]
    pub const fn first(height: u8) -> Self {
        Self::new(height, 0)
    }

    /// Returns the last node's unique id at a given height.
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::last(0), TreeID::MAX_LEAF);
    /// assert_eq!(TreeID::last(1), TreeID::MAX_LEAF.parent());
    /// assert_eq!(TreeID::last(2), TreeID::MAX_LEAF.parent().parent());
    /// // test roots
    /// assert_eq!(TreeID::last(62), TreeID::ROOT.right().unwrap());
    /// assert_eq!(TreeID::last(TreeID::MAX_HEIGHT), TreeID::ROOT);
    /// ```
    #[inline]
    pub const fn last(height: u8) -> Self {
        Self::new(height, Self::MAX_LEAF_INDEX >> height)
    }

    /// Returns a leaf node's unique id at a given index.
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::leaf(0), TreeID::from(0));
    /// assert_eq!(TreeID::leaf(1), TreeID::from(2));
    /// assert_eq!(TreeID::leaf(2), TreeID::from(4));
    /// assert_eq!(TreeID::leaf(3), TreeID::from(6));
    /// ```
    #[inline]
    pub const fn leaf(index: u64) -> Self {
        Self::new(0, index)
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

    /// Determines if the id represents a left node of its parent.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).is_left(), true);
    /// assert_eq!(TreeID::from(1).is_left(), true);
    /// assert_eq!(TreeID::from(2).is_left(), false);
    /// assert_eq!(TreeID::from(3).is_left(), true);
    /// assert_eq!(TreeID::from(4).is_left(), true);
    /// assert_eq!(TreeID::from(5).is_left(), false);
    /// assert_eq!(TreeID::from(6).is_left(), false);
    /// // test root
    /// assert_eq!(TreeID::ROOT.is_left(), true);
    /// ```
    #[inline]
    pub const fn is_left(&self) -> bool {
        (self.index() & 1) == 0
    }

    /// Determines if the id represents a right node of its parent.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).is_right(), false);
    /// assert_eq!(TreeID::from(1).is_right(), false);
    /// assert_eq!(TreeID::from(2).is_right(), true);
    /// assert_eq!(TreeID::from(3).is_right(), false);
    /// assert_eq!(TreeID::from(4).is_right(), false);
    /// assert_eq!(TreeID::from(5).is_right(), true);
    /// assert_eq!(TreeID::from(6).is_right(), true);
    /// // test root
    /// assert_eq!(TreeID::ROOT.is_right(), false);
    /// ```
    #[inline]
    pub const fn is_right(&self) -> bool {
        !self.is_left()
    }

    /// Determines if the id represents a left node of its parent.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).is_left_of(&TreeID::from(0)), false);
    /// assert_eq!(TreeID::from(0).is_left_of(&TreeID::from(1)), true);
    /// assert_eq!(TreeID::from(2).is_left_of(&TreeID::from(1)), false);
    /// assert_eq!(TreeID::from(1).is_left_of(&TreeID::from(2)), true);
    /// ```
    #[inline]
    pub const fn is_left_of(&self, other: &Self) -> bool {
        self.lt(other)
    }

    /// Determines if the id represents a right node of its parent.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).is_right_of(&TreeID::from(0)), false);
    /// assert_eq!(TreeID::from(0).is_right_of(&TreeID::from(1)), false);
    /// assert_eq!(TreeID::from(2).is_right_of(&TreeID::from(1)), true);
    /// assert_eq!(TreeID::from(1).is_right_of(&TreeID::from(2)), false);
    /// ```
    #[inline]
    pub const fn is_right_of(&self, other: &Self) -> bool {
        other.lt(self)
    }

    /// Determines if the id is the first among nodes of the same height.
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).is_first(), true);
    /// assert_eq!(TreeID::from(1).is_first(), true);
    /// assert_eq!(TreeID::from(2).is_first(), false);
    /// assert_eq!(TreeID::from(3).is_first(), true);
    /// assert_eq!(TreeID::from(4).is_first(), false);
    /// assert_eq!(TreeID::from(5).is_first(), false);
    /// assert_eq!(TreeID::from(6).is_first(), false);
    /// assert_eq!(TreeID::from(7).is_first(), true);
    /// // test root
    /// assert_eq!(TreeID::ROOT.is_first(), true);
    /// ```
    #[inline]
    pub const fn is_first(self) -> bool {
        self.index() == 0
    }

    /// Determines if the id is the last among nodes of the same height.
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::MAX_LEAF.is_last(), true);
    /// assert_eq!(TreeID::MAX_LEAF.parent().is_last(), true);
    /// assert_eq!(TreeID::MAX_LEAF.sibling().is_last(), false);
    /// assert_eq!(TreeID::MAX_LEAF.parent().sibling().is_last(), false);
    /// // test root
    /// assert_eq!(TreeID::ROOT.is_last(), true);
    /// ```
    #[inline]
    pub const fn is_last(self) -> bool {
        self.index() == (Self::MAX_LEAF_INDEX >> self.height())
    }

    /// Returns a node's index among nodes of the same height.
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
    /// assert_eq!(TreeID::from(5).index(), 1);
    /// assert_eq!(TreeID::from(6).index(), 3);
    /// assert_eq!(TreeID::from(7).index(), 0);
    /// assert_eq!(TreeID::from(8).index(), 4);
    /// assert_eq!(TreeID::from(9).index(), 2);
    /// assert_eq!(TreeID::from(10).index(), 5);
    /// // test root
    /// assert_eq!(TreeID::ROOT.index(), 0);
    /// ```
    #[inline]
    pub const fn index(&self) -> u64 {
        if self.is_root() {
            0
        } else {
            self.0 >> (self.height() + 1)
        }
    }

    /// Returns a node's height in the tree.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).height(), 0);
    /// assert_eq!(TreeID::from(1).height(), 1);
    /// assert_eq!(TreeID::from(2).height(), 0);
    /// assert_eq!(TreeID::from(3).height(), 2);
    /// assert_eq!(TreeID::from(4).height(), 0);
    /// // test root
    /// assert_eq!(TreeID::ROOT.height(), TreeID::MAX_HEIGHT);
    /// ```
    #[inline]
    pub const fn height(&self) -> u8 {
        (!self.0).trailing_zeros() as u8
    }

    /// Returns the total number of nodes the node spans.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).size(), 1);
    /// assert_eq!(TreeID::from(2).size(), 1);
    /// assert_eq!(TreeID::from(1).size(), 3);
    /// assert_eq!(TreeID::from(3).size(), 7);
    /// assert_eq!(TreeID::from(7).size(), 15);
    /// // test root
    /// assert_eq!(TreeID::ROOT.size(), u64::MAX);
    /// ```
    #[inline]
    pub const fn size(&self) -> u64 {
        !((u64::MAX - 1) << self.height())
    }

    /// Returns the number of leaf nodes the node spans.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).num_leaves(), 0);
    /// assert_eq!(TreeID::from(2).num_leaves(), 0);
    /// assert_eq!(TreeID::from(1).num_leaves(), 2);
    /// assert_eq!(TreeID::from(5).num_leaves(), 2);
    /// assert_eq!(TreeID::from(3).num_leaves(), 4);
    /// assert_eq!(TreeID::from(7).num_leaves(), 8);
    /// // test root
    /// assert_eq!(TreeID::ROOT.num_leaves(), TreeID::MAX_LEAF.index() + 1);
    /// ```
    #[inline]
    pub const fn num_leaves(&self) -> u64 {
        if self.is_leaf() {
            0
        } else {
            2u64 << (self.height() - 1)
        }
    }

    /// Returns the left- and right-most node ids in the tree the node spans.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).span(), (TreeID::from(0), TreeID::from(0)));
    /// assert_eq!(TreeID::from(2).span(), (TreeID::from(2), TreeID::from(2)));
    /// assert_eq!(TreeID::from(1).span(), (TreeID::from(0), TreeID::from(2)));
    /// assert_eq!(TreeID::from(3).span(), (TreeID::from(0), TreeID::from(6)));
    /// assert_eq!(TreeID::from(23).span(), (TreeID::from(16), TreeID::from(30)));
    /// assert_eq!(TreeID::from(27).span(), (TreeID::from(24), TreeID::from(30)));
    /// // test root
    /// assert_eq!(TreeID::ROOT.span(), (TreeID::MIN_LEAF, TreeID::MAX_LEAF));
    /// ```
    #[inline]
    pub const fn span(&self) -> (Self, Self) {
        if self.is_leaf() {
            (*self, *self)
        } else {
            let idx = self.index();
            let num_leaves = self.num_leaves();
            (
                Self::leaf(idx * num_leaves),
                Self::leaf((idx + 1) * num_leaves - 1),
            )
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
    /// assert_eq!(TreeID::from(0).spans(&TreeID::from(2)), false);
    /// assert_eq!(TreeID::from(1).spans(&TreeID::from(0)), true);
    /// assert_eq!(TreeID::from(1).spans(&TreeID::from(1)), true);
    /// assert_eq!(TreeID::from(1).spans(&TreeID::from(2)), true);
    /// assert_eq!(TreeID::from(3).spans(&TreeID::from(1)), true);
    /// assert_eq!(TreeID::from(3).spans(&TreeID::from(5)), true);
    /// assert_eq!(TreeID::from(3).spans(&TreeID::from(7)), false);
    /// // test root
    /// assert_eq!(TreeID::ROOT.spans(&TreeID::MIN_LEAF), true);
    /// assert_eq!(TreeID::ROOT.spans(&TreeID::MAX_LEAF), true);
    /// ```
    #[inline]
    pub const fn spans(&self, other: &Self) -> bool {
        let (ref left, ref right) = self.span();
        left.lte(other) && other.lte(right)
    }

    /// Returns the lowest root id of a [`MerkleLog`] that contains this node.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).root_id(), TreeID::from(0));
    /// assert_eq!(TreeID::from(1).root_id(), TreeID::from(1));
    /// assert_eq!(TreeID::from(2).root_id(), TreeID::from(1));
    /// assert_eq!(TreeID::from(3).root_id(), TreeID::from(3));
    /// assert_eq!(TreeID::from(4).root_id(), TreeID::from(3));
    /// assert_eq!(TreeID::from(5).root_id(), TreeID::from(3));
    /// assert_eq!(TreeID::from(6).root_id(), TreeID::from(3));
    /// assert_eq!(TreeID::from(7).root_id(), TreeID::from(7));
    /// assert_eq!(TreeID::from(8).root_id(), TreeID::from(7));
    /// assert_eq!(TreeID::from(9).root_id(), TreeID::from(7));
    /// // test root
    /// assert_eq!(TreeID::ROOT.root_id(), TreeID::ROOT);
    /// ```
    #[inline]
    pub const fn root_id(&self) -> Self {
        let (_, right) = self.span();
        Self::first(Self::root_height(right.index() + 1))
    }

    /// Returns a node's sort index, i.e. the index in a list sorted by when the
    /// node completes a subtree and becomes immutable.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::TreeID;
    ///
    /// assert_eq!(TreeID::from(0).sort_index(), 0);
    /// assert_eq!(TreeID::from(2).sort_index(), 1);
    /// assert_eq!(TreeID::from(1).sort_index(), 2);
    /// assert_eq!(TreeID::from(4).sort_index(), 3);
    /// assert_eq!(TreeID::from(6).sort_index(), 4);
    /// assert_eq!(TreeID::from(5).sort_index(), 5);
    /// assert_eq!(TreeID::from(3).sort_index(), 6);
    /// assert_eq!(TreeID::from(8).sort_index(), 7);
    /// assert_eq!(TreeID::from(10).sort_index(), 8);
    /// assert_eq!(TreeID::from(9).sort_index(), 9);
    /// assert_eq!(TreeID::from(12).sort_index(), 10);
    /// assert_eq!(TreeID::from(14).sort_index(), 11);
    /// assert_eq!(TreeID::from(13).sort_index(), 12);
    /// assert_eq!(TreeID::from(11).sort_index(), 13);
    /// assert_eq!(TreeID::from(7).sort_index(), 14);
    /// // check final nodes
    /// assert_eq!(TreeID::MAX_LEAF.sort_index(), TreeID::MAX_SORT_INDEX - TreeID::MAX_HEIGHT as u64);
    /// assert_eq!(TreeID::ROOT.sort_index(), TreeID::MAX_SORT_INDEX);
    /// ```
    #[inline]
    pub const fn sort_index(&self) -> u64 {
        if self.is_min_leaf() {
            return 0;
        } else if self.is_a_root() {
            return self.size() - 1;
        }

        match (self.is_leaf(), self.is_left()) {
            (true, true) => self.subroots_size() - 1,
            (true, false) => 1 + self.sibling().sort_index(),
            _ => {
                let (_, right) = self.span();
                self.height() as u64 + right.sort_index()
            }
        }
    }

    // /// Returns a node's sort index, i.e. the index in a list sorted by when the
    // /// node completes a subtree and becomes immutable.
    // ///
    // /// ## Examples
    // /// ```rust
    // /// use merkle_log::TreeID;
    // ///
    // /// assert_eq!(TreeID::from_sort_index(0), TreeID::from(0));
    // /// assert_eq!(TreeID::from_sort_index(1), TreeID::from(2));
    // /// assert_eq!(TreeID::from_sort_index(2), TreeID::from(1));
    // /// assert_eq!(TreeID::from_sort_index(3), TreeID::from(4));
    // /// assert_eq!(TreeID::from_sort_index(4), TreeID::from(6));
    // /// assert_eq!(TreeID::from_sort_index(5), TreeID::from(5));
    // /// assert_eq!(TreeID::from_sort_index(6), TreeID::from(3));
    // /// assert_eq!(TreeID::from_sort_index(7), TreeID::from(8));
    // /// assert_eq!(TreeID::from_sort_index(8), TreeID::from(10));
    // /// assert_eq!(TreeID::from_sort_index(9), TreeID::from(9));
    // /// assert_eq!(TreeID::from_sort_index(10), TreeID::from(12));
    // /// assert_eq!(TreeID::from_sort_index(11), TreeID::from(14));
    // /// assert_eq!(TreeID::from_sort_index(12), TreeID::from(13));
    // /// assert_eq!(TreeID::from_sort_index(13), TreeID::from(11));
    // /// assert_eq!(TreeID::from_sort_index(14), TreeID::from(7));
    // /// // check last leaf
    // /// // assert_eq!(TreeID::MAX_LEAF.sort_index(), u64::MAX);
    // /// ```
    // #[inline]
    // pub const fn from_sort_index(index: u64) -> Self {
    //     if index == 0 {
    //         return Self::MIN_LEAF;
    //     } else if (index + 2).is_power_of_two() {
    //         return Self::first(Self::num_balanced_leaves(index).trailing_zeros() as u8);
    //     }
    //
    //     let len = index + 1;
    //     //
    //     unimplemented!()
    // }
    //
    // #[inline]
    // pub fn sort_iter() -> impl Iterator<Item = Self> {
    //     (0..u64::MAX).map(TreeID::from_sort_index)
    // }

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
    /// // test root
    /// // assert_eq!(TreeID::ROOT.sibling(), TreeID::ROOT);
    /// ```
    #[inline]
    pub const fn sibling(&self) -> Self {
        Self::new(self.height(), self.index() ^ 1)
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
    /// // test root
    /// // assert_eq!(TreeID::ROOT.sibling(), TreeID::ROOT);
    /// ```
    #[inline]
    pub const fn parent(&self) -> Self {
        Self::new(self.height() + 1, self.index() >> 1)
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
    /// // test root
    /// // assert_eq!(TreeID::ROOT.sibling(), TreeID::ROOT);
    /// ```
    #[inline]
    pub const fn uncle(&self) -> Self {
        Self::new(self.height() + 1, self.parent().index() ^ 1)
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
        if self.is_leaf() {
            None
        } else {
            Some(Self::new(self.height() - 1, self.index() << 1))
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
        if self.is_leaf() {
            None
        } else {
            Some(Self::new(self.height() - 1, (self.index() << 1) + 1))
        }
    }

    /// Given the id of a node in a balanced tree, produce the ids of nodes
    /// required for a traditional merkle tree proof, excluding the (sub)root.
    ///
    /// ## Examples
    /// ```rust
    /// use std::collections::BTreeSet;
    /// use merkle_log::*;
    ///
    /// assert_eq!(TreeID::from(0).proving_ids(0).collect::<TreeIDs>(), &[]);
    /// assert_eq!(TreeID::from(0).proving_ids(1).collect::<TreeIDs>(), &[TreeID::from(2)]);
    /// assert_eq!(TreeID::from(0).proving_ids(2).collect::<TreeIDs>(), &[TreeID::from(2), TreeID::from(5)]);
    /// ```
    #[inline]
    pub fn proving_ids(&self, to_height: u8) -> impl Iterator<Item = Self> {
        debug_assert!(to_height <= Self::MAX_HEIGHT);
        (0..(to_height - self.height())).scan(*self, |current_id, _| {
            let sibling = current_id.sibling();
            *current_id = current_id.parent();
            Some(sibling)
        })
    }

    /// The ids whose values are required to append the next entry to the log,
    /// sorted left to right.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::*;
    ///
    /// assert_eq!(TreeID::appending_ids(1).collect::<TreeIDs>(), &[]);
    /// assert_eq!(TreeID::appending_ids(2).collect::<TreeIDs>(), &[TreeID::from(0)]);
    /// assert_eq!(TreeID::appending_ids(3).collect::<TreeIDs>(), &[TreeID::from(1)]);
    /// assert_eq!(TreeID::appending_ids(4).collect::<TreeIDs>(), &[TreeID::from(1), TreeID::from(4)]);
    /// assert_eq!(TreeID::appending_ids(5).collect::<TreeIDs>(), &[TreeID::from(3)]);
    /// assert_eq!(TreeID::appending_ids(6).collect::<TreeIDs>(), &[TreeID::from(3), TreeID::from(8)]);
    /// assert_eq!(TreeID::appending_ids(7).collect::<TreeIDs>(), &[TreeID::from(3), TreeID::from(9)]);
    /// assert_eq!(TreeID::appending_ids(8).collect::<TreeIDs>(), &[TreeID::from(3), TreeID::from(9), TreeID::from(12)]);
    /// assert_eq!(TreeID::appending_ids(9).collect::<TreeIDs>(), &[TreeID::from(7)]);
    /// assert_eq!(TreeID::appending_ids(10).collect::<TreeIDs>(), &[TreeID::from(7), TreeID::from(16)]);
    /// ```
    #[inline]
    pub fn appending_ids(new_len: u64) -> impl Iterator<Item = Self> {
        Self::subroot_ids(new_len - 1)
    }

    /// The root ids of the highest complete subtrees within a log whose length
    /// is `len`, sorted left to right.
    ///
    /// ## Examples
    /// ```rust
    /// use merkle_log::*;
    ///
    /// assert_eq!(TreeID::subroot_ids(0).collect::<TreeIDs>(), &[]);
    /// assert_eq!(TreeID::subroot_ids(1).collect::<TreeIDs>(), &[TreeID::from(0)]);
    /// assert_eq!(TreeID::subroot_ids(2).collect::<TreeIDs>(), &[TreeID::from(1)]);
    /// assert_eq!(TreeID::subroot_ids(3).collect::<TreeIDs>(), &[TreeID::from(1), TreeID::from(4)]);
    /// assert_eq!(TreeID::subroot_ids(4).collect::<TreeIDs>(), &[TreeID::from(3)]);
    /// assert_eq!(TreeID::subroot_ids(5).collect::<TreeIDs>(), &[TreeID::from(3), TreeID::from(8)]);
    /// assert_eq!(TreeID::subroot_ids(6).collect::<TreeIDs>(), &[TreeID::from(3), TreeID::from(9)]);
    /// assert_eq!(TreeID::subroot_ids(7).collect::<TreeIDs>(), &[TreeID::from(3), TreeID::from(9), TreeID::from(12)]);
    /// assert_eq!(TreeID::subroot_ids(8).collect::<TreeIDs>(), &[TreeID::from(7)]);
    /// assert_eq!(TreeID::subroot_ids(9).collect::<TreeIDs>(), &[TreeID::from(7), TreeID::from(16)]);
    /// assert_eq!(TreeID::subroot_ids(10).collect::<TreeIDs>(), &[TreeID::from(7), TreeID::from(17)]);
    /// // test root
    /// // assert_eq!(TreeID::subroot_ids(TreeID::MAX_LEN).count() as u64, 0u64);
    /// ```
    #[inline]
    pub fn subroot_ids(len: u64) -> impl Iterator<Item = Self> {
        debug_assert!(
            len <= Self::MAX_LEN,
            "cannot obtain subroots for logs greater than {}",
            Self::MAX_LEN
        );

        if len == 0 {
            return Either::Left(Either::Left(iter::empty()));
        } else if len.is_power_of_two() {
            let root = Self::first(Self::root_height(len));
            return Either::Left(Either::Right(iter::once(root)));
        }

        Either::Right(
            iter::successors(Some(Self::num_balanced_leaves(len)), move |num_leaves| {
                (num_leaves < &len)
                    .then(|| num_leaves + Self::num_balanced_leaves(len - num_leaves))
            })
            .scan(None, move |prev_id: &mut Option<TreeID>, num_leaves| {
                let height = num_leaves.trailing_zeros() as u8;
                let next_id = match prev_id {
                    None => Self::first(height),
                    Some(_) if height == 0 => Self::leaf(len - 1),
                    Some(prev_id) => {
                        let index = ((prev_id.index() + 1) << (prev_id.height() - height)) as u64;
                        Self::new(height, index)
                    }
                };
                prev_id.replace(next_id);
                Some(next_id)
            }),
        )
    }

    #[inline]
    pub(crate) const fn root_height(len: u64) -> u8 {
        len.next_power_of_two().trailing_zeros() as u8
    }

    #[inline]
    const fn num_balanced_leaves(len: u64) -> u64 {
        prev_power_of_two(len)
    }

    #[inline]
    const fn subroots_size(&self) -> u64 {
        debug_assert!(self.is_leaf());
        let len = self.index() + 1;

        let mut num_leaves = 0u64;
        let mut size = 0u64;
        while num_leaves < len {
            let subtree_len = Self::num_balanced_leaves(len - num_leaves);
            num_leaves += subtree_len;
            size += (subtree_len << 1) - 1;
        }
        size
    }
}

impl TreeID {
    #[inline]
    const fn is_min_leaf(&self) -> bool {
        self.is(&Self::MIN_LEAF)
    }

    #[inline]
    const fn is_root(&self) -> bool {
        self.is(&Self::ROOT)
    }

    #[inline(always)]
    const fn is_a_root(&self) -> bool {
        self.is_first()
    }

    #[inline(always)]
    const fn is(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    #[inline]
    const fn lte(&self, other: &Self) -> bool {
        other.0.checked_sub(self.0).is_some()
    }

    #[inline]
    const fn lt(&self, other: &Self) -> bool {
        match other.0.checked_sub(self.0) {
            None | Some(0) => false,
            _ => true,
        }
    }
}

#[inline]
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

// macro_rules! derive_eq {
//     ($type:ty) => {
//         impl PartialEq<$type> for TreeID {
//             fn eq(&self, other: &$type) -> bool {
//                 self.0 == *other as u64
//             }
//         }
//     };
// }

// derive_eq!(usize);
// derive_eq!(u8);
// derive_eq!(u16);
// derive_eq!(u32);
// derive_eq!(u64);
