use lalrpop_util::ParseError;
use std::fmt;

use miniscript::bitcoin::{self, hashes};
use miniscript::descriptor;
use miniscript::policy::compiler::CompilerError;

use crate::ast::{Ident, InfixOp};
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

    #[error("Expected a boolean, not {0:?}")]
    NotBool(Value),

    #[error("Expected a pubkey, not {0:?}")]
    NotPubKey(Value),

    #[error("Expected hash bytes, not {0:?}")]
    NotHashLike(Value),

    #[error("Expected a network type, not {0:?}")]
    NotNetwork(Value),

    #[error("Expected bytes, not {0:?}")]
    NotBytes(Value),

    #[error("Expected a policy or array of policies, not {0:?}")]
    NotPolicyLike(Value),

    #[error("Expected a miniscript or policy, not {0:?}")]
    NotMiniscriptLike(Value),

    #[error("Expected a descriptor, policy or miniscript, not {0:?}")]
    NotDescriptorLike(Value),

    #[error("Expected a value coercible into Script, not {0:?}")]
    NotScriptLike(Value),

    #[error("Invalid script fragment {0:?}")]
    InvalidScriptFrag(Value),

    #[error("Array index out of range")]
    ArrayIndexOutOfRange,

    #[error("Function {0} expected {1} arguments, not {2}")]
    ArgumentMismatch(Ident, usize, usize),

    #[error("Invalid datetime string: {0}")]
    InvalidDateTime(chrono::ParseError),

    #[error("Absolute by-blocktime timelock out of range, supported up to 2106")]
    InvalidDateTimeOutOfRange,

    #[error("Heightwise duration must be divisible by the block interval (typically 10 minutes)")]
    InvalidDurationHeightwise,

    #[error("Relative by-blockheight timelocks are only supported for up to 65535 blocks (roughly 455 days)")]
    InvalidDurationBlocksOutOfRange,

    #[error("Relative by-blocktime timelocks are only supported for up to 33553920 seconds (roughly 1 year)")]
    InvalidDurationTimeOutOfRange,

    #[error("Parser error: {0}")]
    ParseError(String),

    #[error("Invalid arguments")]
    InvalidArguments,

    #[error("Cannot derive policy/miniscript/descriptor without inner wildcard keys")]
    NonDeriveableNoWildcard,

    #[error("Data type cannot be derived")]
    NonDeriveableType,

    #[error("Standalone keys cannot be derived")]
    NonDeriveableSingle,

    #[error("sh() can only wrap wsh() or wpkh()")]
    InvalidShUse,

    #[error("Script cannot be represented as an address: {0}")]
    NotAddressable(bitcoin::Script),

    #[error("Number operation overflowed")]
    Overflow,

    #[error("in {0}(): {1}")]
    CallError(Ident, Box<Error>),

    #[error("in {0:?}: {1}")]
    OpError(InfixOp, Box<Error>),

    #[error("Descriptor key parse error: {0}")]
    DescriptorKeyParse(descriptor::DescriptorKeyParseError),

    #[error("Descriptor conversion error: {0}")]
    DescriptorConversion(descriptor::ConversionError),

    #[error("Miniscript error: {0}")]
    MiniscriptError(miniscript::Error),

    #[error("Miniscript compiler error: {0}")]
    MiniscriptCompilerError(CompilerError),

    #[error("Taproot error: {0}")]
    TaprootError(bitcoin::util::taproot::TaprootError),

    #[error("Taproot builder error: {0}")]
    TaprootBuilderError(bitcoin::util::taproot::TaprootBuilderError),

    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(bitcoin::secp256k1::Error),

    #[error("Hash error: {0}")]
    HashError(hashes::Error),

    #[error("Invalid hex: {0}")]
    HexError(hashes::hex::Error),

    #[error("IO error: {0:?}")]
    Io(std::io::Error),

    #[error("Bitcoin key error: {0}")]
    BitcoinKey(bitcoin::util::key::Error),

    #[error("BIP 32 error: {0}")]
    Bip32(bitcoin::util::bip32::Error),

    #[error("number type conversion failed (likely an unexpected negative number)")]
    TryFromInt(std::num::TryFromIntError),

    #[error("Invalid pubkey key length: {0} (expected 32 or 33)")]
    InvalidPubKeyLen(usize),

    #[error("Invalid merkle root hash length: {0} (expected 32)")]
    InvalidMerkleLen(usize),

    #[error("Invalid taproot script tree, nested arrays are expected to have exactly 2 elements")]
    TaprootInvalidNestedTree,

    #[error("UTF-8 error: {0}")]
    Utf8Error(std::string::FromUtf8Error),
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

impl_from_variant!(descriptor::ConversionError, Error, DescriptorConversion);
impl_from_variant!(miniscript::Error, Error, MiniscriptError);
impl_from_variant!(CompilerError, Error, MiniscriptCompilerError);
impl_from_variant!(hashes::Error, Error, HashError);
impl_from_variant!(hashes::hex::Error, Error, HexError);
impl_from_variant!(chrono::ParseError, Error, InvalidDateTime);
impl_from_variant!(std::io::Error, Error, Io);
impl_from_variant!(bitcoin::util::key::Error, Error, BitcoinKey);
impl_from_variant!(bitcoin::util::bip32::Error, Error, Bip32);
impl_from_variant!(bitcoin::util::taproot::TaprootError, Error, TaprootError);
impl_from_variant!(
    bitcoin::util::taproot::TaprootBuilderError,
    Error,
    TaprootBuilderError
);
impl_from_variant!(bitcoin::secp256k1::Error, Error, Secp256k1Error);
impl_from_variant!(std::num::TryFromIntError, Error, TryFromInt);
impl_from_variant!(
    descriptor::DescriptorKeyParseError,
    Error,
    DescriptorKeyParse
);

impl_from_variant!(std::string::FromUtf8Error, Error, Utf8Error);
