use crate::{maybestd::io::Error as IoError, TreeID};
use onlyerror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Out of bounds")]
    OutOfBounds,

    #[error("Overflow error")]
    Overflow,

    #[error("I/O error: {0}")]
    IO(#[from] IoError),

    #[error("missing node: {0:?}")]
    MissingNode(TreeID),

    #[error("unable to provide/verify proof: {0}")]
    ProofError(&'static str),
}
