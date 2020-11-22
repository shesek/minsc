use lalrpop_util::ParseError;
use std::fmt;

use ::miniscript::bitcoin::hashes;
use ::miniscript::descriptor::DescriptorKeyParseError;

use crate::ast::Ident;
use crate::miniscript;
use crate::runtime::Value;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Assigned variable name already exists: {0}")]
    AssignedVariableExists(Ident),

    #[error("Missing expected return value, set a final expression or a main() function")]
    NoReturnValue,

    #[error("Invalid main expression, expecting a policy fragment")]
    InvalidTopLevel,

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

    #[error("Not a pubkey: {0:?}")]
    NotPubKey(Value),

    #[error("Not an hash: {0:?}")]
    NotHash(Value),

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

    #[error("Invalid datetime string: {0}")]
    InvalidDateTime(chrono::ParseError),

    #[error("Absolute by-blocktime timelock out of range, supported up to 2106")]
    InvalidDateTimeOutOfRange,

    #[error("Heightwise duration must be divisible by 10 minutes")]
    InvalidDurationHeightwise,

    #[error("Relative by-blockheight timelocks are only supported for up to 65535 blocks (roughly 455 days)")]
    InvalidDurationBlocksOutOfRange,

    #[error("Relative by-blocktime timelocks are only supported for up to 33553920 seconds (roughly 1 year)")]
    InvalidDurationTimeOutOfRange,

    #[error("Parser error: {0}")]
    ParseError(String),

    #[error("Miniscript error: {0}")]
    MiniscriptError(miniscript::Error),

    #[error("Descriptor key parse error: {0}")]
    DescriptorKeyParseError(DescriptorKeyParseError),

    #[error("Hash error: {0}")]
    HashError(hashes::Error),

    #[error("Invalid hex: {0}")]
    HexError(hashes::hex::Error),

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

impl_from_variant!(miniscript::Error, Error, MiniscriptError);
impl_from_variant!(DescriptorKeyParseError, Error);
impl_from_variant!(hashes::Error, Error, HashError);
impl_from_variant!(hashes::hex::Error, Error, HexError);
impl_from_variant!(chrono::ParseError, Error, InvalidDateTime);
impl_from_variant!(std::io::Error, Error, Io);
