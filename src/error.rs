use lalrpop_util::ParseError;
use std::fmt;

use miniscript::bitcoin::hashes;
use miniscript::descriptor::DescriptorKeyParseError;
use miniscript::policy::compiler::CompilerError;

use crate::ast::Ident;
use crate::runtime::Value;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Assigned variable name already exists: {0}")]
    AssignedVariableExists(Ident),

    #[error("Missing expected return value, set a final expression or a main() function")]
    NoReturnValue,

    #[error("Undefined function: {0}")]
    FnNotFound(Ident),

    #[error("Undefined variable: {0}")]
    VarNotFound(Ident),

    #[error("Expected a function, not {0:?}")]
    NotFn(Value),

    #[error("Expected an array, not {0:?}")]
    NotArray(Value),

    #[error("Expected a number, not {0:?}")]
    NotNumber(Value),

    #[error("Expected a pubkey, not {0:?}")]
    NotPubKey(Value),

    #[error("Expected an hash, not {0:?}")]
    NotHash(Value),

    #[error("Expected a network type, not {0:?}")]
    NotNetwork(Value),

    #[error("Expected a policy or array of policies, not {0:?}")]
    NotPolicyLike(Value),

    #[error("Expected a miniscript or policy, not {0:?}")]
    NotMiniscriptLike(Value),

    #[error("Expected a descriptor, policy or miniscript, not {0:?}")]
    NotDescriptorLike(Value),

    #[error("Expected value castable to Script, not {0:?}")]
    NotScriptLike(Value),

    #[error("Array index out of range")]
    ArrayIndexOutOfRange,

    #[error("Function {0} expected {1} arguments, not {2}")]
    ArgumentMismatch(Ident, usize, usize),

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

    #[error("Invalid arguments")]
    InvalidArguments,

    #[error("Descriptors can only be derived with a single child code and without '/*'")]
    InvalidDescriptorDerivation,

    #[error("Standalone single keys cannot be derived")]
    InvalidSingleDerivation,

    #[error("sh() can only wrap wsh() or wpkh()")]
    InvalidShUse,

    #[error("in {0}(): {1}")]
    CallError(Ident, Box<Error>),

    #[error("Descriptor key parse error: {0}")]
    DescriptorKeyParseError(DescriptorKeyParseError),

    #[error("Miniscript compiler error: {0}")]
    MiniscriptCompilerError(CompilerError),

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

impl_from_variant!(DescriptorKeyParseError, Error);
impl_from_variant!(CompilerError, Error, MiniscriptCompilerError);
impl_from_variant!(hashes::Error, Error, HashError);
impl_from_variant!(hashes::hex::Error, Error, HexError);
impl_from_variant!(chrono::ParseError, Error, InvalidDateTime);
impl_from_variant!(std::io::Error, Error, Io);
