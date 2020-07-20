use lalrpop_util::ParseError;
use std::fmt;

use crate::ast::Ident;
use crate::miniscript;
use crate::runtime::Value;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Assigned variable name already exists: {0}")]
    AssignedVariableExists(Ident),

    #[error("Undefined function: {0}")]
    FnNotFound(Ident),

    #[error("Undefined variable: {0}")]
    VarNotFound(Ident),

    #[error("Not a function: {0:?}")]
    NotFn(Value),

    #[error("Not an array: {0:?}")]
    NotArray(Value),

    #[error("Not a number: {0:?}")]
    NotNumber(Value),

    #[error("Invalid probability: {0}")]
    InvalidProb(String),

    #[error("Invalid array index, not a number")]
    InvalidArrayIndex,

    #[error("Array index out of range")]
    ArrayIndexOutOfRange,

    #[error("Function {0} expected {1} arguments, not {2}")]
    ArgumentMismatch(Ident, usize, usize),

    #[error("Cannot represent as a Miniscript policy: {0:?}")]
    NotMiniscriptRepresentable(Value),

    #[error("Parser error: {0}")]
    ParseError(String),

    #[error("Invalid miniscript: {0}")]
    InvalidMiniscript(miniscript::Error),

    #[error("IO error: {0:?}")]
    Io(std::io::Error),
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

impl_from_variant!(miniscript::Error, Error, InvalidMiniscript);
impl_from_variant!(std::io::Error, Error, Io);
