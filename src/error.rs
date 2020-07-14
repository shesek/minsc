use std::fmt;
use lalrpop_util::ParseError;

use crate::Ident;
use crate::runtime::Value;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Assigned variable name already exists: {0}")]
    AssignedVariableExists(Ident),

    #[error("Missing function: {0}")]
    FnNotFound(Ident),

    #[error("Not a function: {0}")]
    NotFn(Ident),

    #[error("Not an array: {0:?}")]
    NotArray(Value),

    #[error("Invalid probability: {0}")]
    InvalidProb(String),

    #[error("Invalid array index, not a number")]
    InvalidArrayIndex,

    #[error("Array index out of range")]
    ArrayIndexOutOfRange,

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
