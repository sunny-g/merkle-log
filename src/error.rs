use crate::{maybestd::io::Error as IoError, TreeID};

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(feature = "std", error("Out of bounds"))]
    OutOfBounds,

    #[cfg_attr(feature = "std", error("Overflow error"))]
    Overflow,

    #[cfg_attr(feature = "std", error("I/O error: {0}"))]
    IO(#[cfg_attr(feature = "std", from)] IoError),

    #[cfg_attr(feature = "std", error("missing node: {0:?}"))]
    MissingNode(TreeID),

    #[cfg_attr(feature = "std", error("unable to provide/verify proof: {0}"))]
    ProofError(&'static str),
}
