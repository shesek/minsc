use std::fmt;
use lalrpop_util::ParseError;

use crate::Ident;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Assigned variable name already exists: {0}")]
    AssignedVariableExists(Ident),

    #[error("Missing function: {0}")]
    FnNotFound(Ident),

    #[error("Not a function: {0}")]
    NotFn(Ident),

    #[error("Invalid probability: {0}")]
    InvalidProb(String),

    #[error("Function {0} expected {1} arguments, not {2}")]
    ArgumentMismatch(Ident, usize, usize),

    #[error("Value cannot be represented as Miniscript policy")]
    NotMiniscriptRepresentable,

    #[error("Parser error: {0}")]
    ParseError(String),
}

impl<L, T, E> From<ParseError<L, T, E>> for Error
where
    L: fmt::Display,
    T: fmt::Display,
    E: fmt::Display,
{
    fn from(err: ParseError<L, T, E>) -> Self {
        Error::ParseError(err.to_string())
    }
}
