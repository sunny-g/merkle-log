use crate::TreeID;
use std::io::Error as IoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    IO(#[from] IoError),

    #[error("missing node: {0:?}")]
    MissingNode(TreeID),

    #[error("unable to provide/verify proof: {0}")]
    ProofError(&'static str),
}
