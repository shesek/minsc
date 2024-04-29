use lalrpop_util::ParseError;
use std::fmt;

use miniscript::bitcoin::{
    self, amount, bip32, hashes, hex, key, network, script, taproot, witness_program,
};
use miniscript::policy::compiler::CompilerError;
use miniscript::{descriptor, TranslateErr};

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

    #[error("Expected an integer or a float that can be converted to an integer, not {0:?}")]
    NotIntLike(f64),

    #[error("Expected a boolean, not {0:?}")]
    NotBool(Value),

    #[error("Expected a pubkey, not {0:?}")]
    NotPubKey(Value),

    #[error("Expected hash bytes, not {0:?}")]
    NotHashLike(Value),

    #[error("Expected a network type, not {0:?}")]
    NotNetwork(Value),

    #[error("Cannot be converted to Bytes: {0:?}")]
    NotBytesLike(Value),

    #[error("Expected a string, not {0:?}")]
    NotString(Value),

    #[error("Expected TapInfo or tr() Descriptor, not {0:?}")]
    NotTapInfoLike(Value),

    #[error("Expected a policy or pubkey, not {0:?}")]
    NotPolicyLike(Value),

    #[error("Expected a descriptor or pubkey, not {0:?}")]
    NotDescriptorLike(Value),

    #[error("Expected Script, not {0:?}")]
    NotScript(Value),

    #[error("Cannot represent as a scriptPubKey: {0:?}")]
    NotSpkLike(Value),

    #[error("Invalid script fragment: {0:?}")]
    InvalidScriptFrag(Value),

    #[error("Only integers can be interpolated as script fragments, received a float: {0:?}")]
    InvalidScriptFragIntOnly(f64),

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

    #[error("Invalid derivation child code index. Only numbers and SHA256 hashes are supported.")]
    InvalidDerivationCode,

    #[error("Invalid tr() use. Valid invocations are tr(policy) or tr(internal_key, policy)")]
    InvalidTrUse,

    #[error("Invalid Taproot unspendable key: {0}")]
    InvalidTrUnspendable(Value),

    #[error("No viable internal key found (TR_UNSPENDABLE was unset)")]
    TaprootNoViableKey,

    #[error("sh() can only wrap wsh() or wpkh()")]
    InvalidShUse,

    #[error("Script cannot be represented as an address: {0}")]
    NotAddressable(bitcoin::ScriptBuf),

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
    TaprootError(taproot::TaprootError),

    #[error("Taproot builder error: {0}")]
    TaprootBuilderError(taproot::TaprootBuilderError),

    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(bitcoin::secp256k1::Error),

    #[error("Hash error: {0}")]
    HashError(hashes::FromSliceError),

    #[error("Invalid hex: {0}")]
    HexError(hex::HexToBytesError),

    #[error("IO error: {0:?}")]
    Io(std::io::Error),

    #[error("Bitcoin key error: {0}")]
    BitcoinKey(key::Error),

    #[error("BIP 32 error: {0}")]
    Bip32(bip32::Error),

    #[error("Bitcoin amount parse error: {0}")]
    ParseAmountError(amount::ParseAmountError),

    #[error("number type conversion failed (likely an unexpected negative number)")]
    TryFromInt(std::num::TryFromIntError),

    #[error("Invalid pubkey key length: {0} (expected 32 or 33)")]
    InvalidPubKeyLen(usize),

    #[error("Invalid merkle root hash length: {0} (expected 32)")]
    InvalidMerkleLen(usize),

    #[error("Invalid taproot binary script tree structure. Expecting a nested array where elements are leaf nodes (with no weights) or a tuple of nodes.")]
    TaprootInvalidScriptBinaryTree,

    #[error("Invalid taproot script. expecting Policy/Script or an array of them, an empty array, or the merkle root hash")]
    TaprootInvalidScript,

    #[error("UTF-8 error: {0}")]
    Utf8Error(std::string::FromUtf8Error),

    // needed so that Infallible conversions can be used with `?`
    #[error("Infallible (can never be constructed)")]
    Infallible(std::convert::Infallible),

    #[error("Witness program error: {0}")]
    WitnessProgError(witness_program::Error),

    #[error("Push bytes error: {0}")]
    PushBytesError(script::PushBytesError),

    #[error("Key translation error: {0:?}")]
    TranslateError(Box<miniscript::TranslateErr<Error>>),

    #[error("Parse network error: {0}")]
    ParseNetworkError(network::ParseNetworkError),
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
impl_from_variant!(hashes::FromSliceError, Error, HashError);
impl_from_variant!(hex::HexToBytesError, Error, HexError);
impl_from_variant!(chrono::ParseError, Error, InvalidDateTime);
impl_from_variant!(std::io::Error, Error, Io);
impl_from_variant!(key::Error, Error, BitcoinKey);
impl_from_variant!(bip32::Error, Error, Bip32);
impl_from_variant!(taproot::TaprootError, Error, TaprootError);
impl_from_variant!(taproot::TaprootBuilderError, Error, TaprootBuilderError);
impl_from_variant!(bitcoin::secp256k1::Error, Error, Secp256k1Error);
impl_from_variant!(std::num::TryFromIntError, Error, TryFromInt);
impl_from_variant!(
    descriptor::DescriptorKeyParseError,
    Error,
    DescriptorKeyParse
);

impl_from_variant!(std::string::FromUtf8Error, Error, Utf8Error);
impl_from_variant!(std::convert::Infallible, Error, Infallible);
impl_from_variant!(amount::ParseAmountError, Error, ParseAmountError);
impl_from_variant!(witness_program::Error, Error, WitnessProgError);
impl_from_variant!(script::PushBytesError, Error, PushBytesError);
impl_from_variant!(Box<TranslateErr<Error>>, Error, TranslateError);
impl_from_variant!(network::ParseNetworkError, Error, ParseNetworkError);

impl From<TranslateErr<Error>> for Error {
    fn from(e: TranslateErr<Error>) -> Self {
        Box::new(e).into()
    }
}
