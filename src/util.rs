use crate::{maybestd::*, Error, Node, TreeID};

/// Represents access to immutable merkle tree nodes.
pub trait Store<N: Node> {
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
    fn get_many<'a, I: Iterator<Item = TreeID>>(
        &self,
        ids: I,
    ) -> Result<BTreeMap<TreeID, N>, Error> {
        let mut nodes = BTreeMap::new();
        for id in ids {
            nodes.insert(id, self.get(&id)?);
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
pub type MemoryStore<N> = BTreeMap<TreeID, N>;

impl<N: Node> Store<N> for BTreeMap<TreeID, N> {
    /// Delegates to [`BTreeMap::get`].
    ///
    /// [`BTreeMap::get`]: crate::maybestd::BTreeMap::get
    #[inline]
    fn get_node(&self, id: &TreeID) -> Result<N, Error> {
        let node = self.get(id).ok_or(Error::MissingNode(*id))?;
        Ok(*node)
    }

    /// Delegates to [`BTreeMap::insert`].
    ///
    /// [`BTreeMap::insert`]: crate::maybestd::BTreeMap::insert
    #[inline]
    fn set_node(&mut self, id: TreeID, node: N) -> Result<(), Error> {
        self.insert(id, node);
        Ok(())
    }

    /// Delegates to [`BTreeMap::get`].
    ///
    /// [`BTreeMap::get`]: crate::maybestd::BTreeMap::get
    #[inline]
    fn get_leaf(&self, id: &TreeID) -> Result<N, Error> {
        let leaf = self.get(id).ok_or(Error::MissingNode(*id))?;
        Ok(*leaf)
    }

    /// Delegates to [`BTreeMap::insert`].
    ///
    /// [`BTreeMap::insert`]: crate::maybestd::BTreeMap::insert
    #[inline]
    fn set_leaf(&mut self, id: TreeID, leaf: N) -> Result<(), Error> {
        self.insert(id, leaf);
        Ok(())
    }
}

///
pub trait Digest<N: Node>: Default {
    ///
    fn leaf_digest<R: BufRead>(entry: R) -> N;

    ///
    fn node_digest(left: (TreeID, &N), right: (TreeID, &N)) -> N;

    // ///
    // fn root_digest(leaf_id: TreeID, leaf_node: &N, height: u8)
}

#[cfg(feature = "digest")]
mod _digest {
    use super::*;
    use digest::Output;

    impl<D, N> Digest<N> for D
    where
        D: digest::Digest + Default,
        N: Node + From<Output<D>>,
    {
        fn leaf_digest<R: BufRead>(mut entry: R) -> N {
            let mut hasher = Self::default();
            loop {
                let bytes = entry
                    .fill_buf()
                    .expect("should not fail to fill BufReader from an io::Read");
                match bytes.len() {
                    0 => break,
                    len => {
                        hasher.update(bytes);
                        entry.consume(len);
                    }
                }
            }
            hasher.finalize().into()
        }

        fn node_digest(left: (TreeID, &N), right: (TreeID, &N)) -> N {
            let mut hasher = Self::default();
            hasher.update(left.1.as_ref());
            hasher.update(right.1.as_ref());
            hasher.finalize().into()
        }
    }
}

pub(crate) enum Either<I1, I2> {
    Left(I1),
    Right(I2),
}

impl<I1, I2> Iterator for Either<I1, I2>
where
    I1: Iterator<Item = TreeID>,
    I2: Iterator<Item = TreeID>,
{
    type Item = TreeID;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Left(i) => i.next(),
            Self::Right(i) => i.next(),
        }
    }
}
