use miniscript::bitcoin::{
    self, amount, bip32, hashes, hex, key, network, script, taproot, witness_program,
};
use miniscript::policy::compiler::CompilerError;
use miniscript::{descriptor, TranslateErr};

use crate::parser::ast::{Ident, InfixOp};
use crate::runtime::Value;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Parse error: {0}")]
    Parse(ParseError),

    #[error("Runtime error: {0}")]
    Runtime(RuntimeError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl<T: Into<RuntimeError>> From<T> for Error {
    fn from(err: T) -> Error {
        Error::Runtime(err.into())
    }
}
impl_from_variant!(ParseError, Error, Parse);

#[derive(thiserror::Error, Debug)]
pub enum RuntimeError {
    #[error("Assigned variable name already exists: {0}")]
    AssignedVariableExists(Ident),

    #[error("Missing expected return value, set a final expression or a main() function")]
    NoReturnValue,

    #[error("Undefined function: {0}")]
    FnNotFound(Ident),

    #[error("Undefined variable: {0}")]
    VarNotFound(Ident),

    #[error("Expected a function, not {0:?}")]
    NotFn(Box<Value>),

    #[error("Expected an array, not {0:?}")]
    NotArray(Box<Value>),

    #[error(
        "Accessing by index is possible on Array, Bytes and multi-path Descriptors, not {0:?}"
    )]
    NoArrayAccess(Box<Value>),

    #[error("Expected a number, not {0:?}")]
    NotNumber(Box<Value>),

    #[error("Expected an integer, not {0:?}")]
    NotInt(f64),

    #[error("Expected a boolean, not {0:?}")]
    NotBool(Box<Value>),

    #[error("Expected a pubkey, not {0:?}")]
    NotPubKey(Box<Value>),

    #[error("Expected an address, not {0:?}")]
    NotAddress(Box<Value>),

    #[error("Expected hash bytes, not {0:?}")]
    NotHashLike(Box<Value>),

    #[error("Expected a network type, not {0:?}")]
    NotNetwork(Box<Value>),

    #[error("Cannot be converted to Bytes: {0:?}")]
    NotBytesLike(Box<Value>),

    #[error("Expected a string, not {0:?}")]
    NotString(Box<Value>),

    #[error("Expected TapInfo or tr() Descriptor, not {0:?}")]
    NotTapInfoLike(Box<Value>),

    #[error("Expected a policy or pubkey, not {0:?}")]
    NotPolicyLike(Box<Value>),

    #[error("Expected a descriptor or pubkey, not {0:?}")]
    NotDescriptorLike(Box<Value>),

    #[error("Expected Script, not {0:?}")]
    NotScript(Box<Value>),

    #[error("Expected a transaction as object, raw bytes or tagged list, not {0:?}")]
    NotTxLike(Box<Value>),

    #[error("Expected raw Script or Bytes, not {0:?}. Perhaps you meant to use explicitScript()/scriptPubKey()?")]
    InvalidScriptConstructor(Box<Value>),

    #[error("Cannot represent as a scriptPubKey: {0:?}")]
    NoSpkRepr(Box<Value>),

    #[error("Invalid script fragment: {0:?}")]
    InvalidScriptFrag(Box<Value>),

    #[error("Only integers can be interpolated as script fragments, received a float: {0:?}")]
    InvalidScriptFragIntOnly(f64),

    #[error("Array index out of range")]
    ArrayIndexOutOfRange,

    #[error("Required value missing")]
    MissingValue,

    #[error("Invalid value: {0:?}")]
    InvalidValue(Box<Value>),

    #[error("Expected length {1}, not {0}")]
    InvalidLength(usize, usize), // (actual, expected)

    #[error("Expected length {1} to {2}, not {0}")]
    InvalidVarLength(usize, usize, usize), // (actual, min, max)

    #[error("Invalid arguments: {0}")]
    InvalidArgumentsError(#[source] Box<RuntimeError>),

    #[error("Expected {1} arguments, not {0}")]
    ArgumentMismatch(usize, usize),

    #[error("Heightwise duration must be divisible by the block interval (typically 10 minutes)")]
    InvalidDurationHeightwise,

    #[error("Relative by-blockheight timelocks are only supported for up to 65535 blocks (roughly 455 days)")]
    InvalidDurationBlocksOutOfRange,

    #[error("Relative by-blocktime timelocks are only supported for up to 33553920 seconds (roughly 388 days)")]
    InvalidDurationTimeOutOfRange,

    #[error("Invalid arguments")]
    InvalidArguments,

    #[error("Cannot derive policy/miniscript/descriptor without inner wildcard keys")]
    NonDeriveableNoWildcard,

    #[error("Data type cannot be derived")]
    NonDeriveableType,

    #[error("Standalone keys cannot be derived")]
    NonDeriveableSingle,

    #[error(
        "Invalid derivation index. Only child numbers, hashes and multi-path arrays are supported."
    )]
    InvalidDerivationCode,

    #[error("Policy probabilities are only supported for OR with 2 branches")]
    InvalidPolicyProb,

    #[error("Script probabilities are not supported in explicit tree structure")]
    InvalidScriptProb,

    #[error("sh() can only wrap wsh() or wpkh()")]
    InvalidShUse,

    #[error("Script cannot be represented as an address: {0}")]
    NotAddressable(bitcoin::ScriptBuf),

    #[error("Number operation overflowed")]
    Overflow,

    #[error("in {}(): {1}", .0.as_ref().unwrap_or(&"<anonymous>".into()))]
    CallError(Option<Ident>, #[source] Box<RuntimeError>),

    #[error("in {0}: {1}")]
    ContextStr(&'static str, #[source] Box<RuntimeError>),

    // Error message with information about the originated argument/element index
    #[error("#{0}: {1}")]
    NthContext(usize, #[source] Box<RuntimeError>), // usize is 1-indexed

    #[error("{0:?} operator error: {1}")]
    InfixOpError(InfixOp, #[source] Box<RuntimeError>),

    #[error("Invalid operands: ({0}, {1})")]
    InfixOpArgs(Box<Value>, Box<Value>),

    #[error("cannot mix number types ({0} and {1}). convert with explicit int()/float()")]
    InfixOpMixedNum(Box<Value>, Box<Value>),

    #[error("Invalid merkle root hash: {0}")]
    InvalidMerkleRoot(#[source] hashes::FromSliceError),

    #[error("Invalid pubkey key length: {0} (expected 32 or 33)")]
    InvalidPubKeyLen(usize),

    #[error("Invalid tr() use. Valid invocations are tr(PubKey), tr(Policy|Array<Policy>), tr(PubKey, Policy|Array<Policy>), tr(PubKey, Script|Array<Script>) or tr(PubKey, Hash)")]
    TaprootInvalidTrUse,

    #[error("Invalid Taproot unspendable key: {0}")]
    InvalidTrUnspendable(Box<Value>),

    #[error("No viable taproot internal key found, provide one explicitly")]
    TaprootNoViableKey,

    #[error("Invalid taproot binary script tree structure. Expecting a nested array where elements are leaf nodes (with no weights) or a tuple of nodes.")]
    TaprootInvalidScriptBinaryTree,

    #[error("Invalid taproot script, expecting Policy/Script or an array of them")]
    TaprootInvalidScript,

    #[error("Expected a tuple array of 2 elements, not {0:?}")]
    InvalidTuple(Box<Value>),

    #[error("Invalid tagged array structure: {0}")]
    InvalidTaggedList(#[source] Box<RuntimeError>),

    #[error("\"{0}\" tag: {1}")]
    TagError(String, #[source] Box<RuntimeError>),

    #[error("Duplicated tag")]
    TagDuplicated,

    #[error("Unknown tag")]
    TagUnknown,

    // Generic error raised from user-land Minsc code
    #[error("Exception: {0}")]
    ScriptException(String),

    //
    // Wrapped errors
    //
    #[error("Descriptor conversion error: {0}")]
    DescriptorConversion(#[from] descriptor::ConversionError),

    #[error("Miniscript error: {0}")]
    MiniscriptError(#[from] miniscript::Error),

    #[error("Miniscript compiler error: {0}")]
    MiniscriptCompilerError(#[from] CompilerError),

    #[error("Taproot error: {0}")]
    TaprootError(#[from] taproot::TaprootError),

    #[error("Taproot builder error: {0}")]
    TaprootBuilderError(#[from] taproot::TaprootBuilderError),

    #[error("Secp256k1 error: {0}")]
    Secp256k1Error(#[from] bitcoin::secp256k1::Error),

    #[error("Hash error: {0}")]
    HashError(#[from] hashes::FromSliceError),

    #[error("IO error: {0:?}")]
    Io(#[from] std::io::Error),

    #[error("Bitcoin key error: {0}")]
    BitcoinKey(#[from] key::Error),

    #[error("BIP 32 error: {0}")]
    Bip32(#[from] bip32::Error),

    #[error("Bitcoin amount parse error: {0}")]
    ParseAmountError(#[from] amount::ParseAmountError),

    #[error("Number conversion failed: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("Bytes conversion failed: {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    // needed so that Infallible conversions can be used with `?`
    #[error("Infallible (can never be constructed)")]
    Infallible(#[from] std::convert::Infallible),

    #[error("Witness program error: {0}")]
    WitnessProgError(#[from] witness_program::Error),

    #[error("Push bytes error: {0}")]
    PushBytesError(#[from] script::PushBytesError),

    #[error("Parse network error: {0}")]
    ParseNetworkError(#[from] network::ParseNetworkError),

    #[error("Key translation error: {0:?}")]
    TranslateError(Box<miniscript::TranslateErr<RuntimeError>>),

    #[error("Invalid address: {0}")]
    AddressError(#[from] bitcoin::address::ParseError),

    #[error("Encoding error: {0}")]
    EncodeError(#[from] bitcoin::consensus::encode::Error),

    #[error("Script error: {0}")]
    ScriptError(#[from] bitcoin::script::Error),
}

impl From<TranslateErr<RuntimeError>> for RuntimeError {
    fn from(e: TranslateErr<RuntimeError>) -> Self {
        RuntimeError::TranslateError(Box::new(e))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("ParseFloatError: {0}")]
    ParseFloatError(#[from] std::num::ParseFloatError),

    #[error("ParseIntError: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Invalid hex: {0}")]
    HexError(#[from] hex::HexToBytesError),

    #[error("Invalid address: {0}")]
    AddressError(#[from] bitcoin::address::ParseError),

    #[error("Descriptor key parse error: {0}")]
    DescKeyParse(#[from] descriptor::DescriptorKeyParseError),

    #[error("Invalid datetime string: {0}")]
    InvalidDateTime(#[from] chrono::ParseError),

    #[error("Absolute by-blocktime timelock out of range, supported up to 2106")]
    InvalidDateTimeOutOfRange,

    #[error("{0}")]
    LalrError(String),
}

pub type LalrParseError<'a> =
    lalrpop_util::ParseError<usize, lalrpop_util::lexer::Token<'a>, ParseError>;

impl<'a> From<LalrParseError<'a>> for ParseError {
    fn from(e: LalrParseError<'a>) -> Self {
        ParseError::LalrError(e.to_string())
    }
}
