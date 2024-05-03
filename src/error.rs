use miniscript::bitcoin::{
    self, amount, bip32, hashes, hex, key, network, script, taproot, witness_program,
};
use miniscript::policy::compiler::CompilerError;
use miniscript::{descriptor, TranslateErr};

use crate::ast::{Ident, InfixOp};
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
    NotFn(Value),

    #[error("Expected an array, not {0:?}")]
    NotArray(Value),

    #[error("Accessing by index is possible on Array/Bytes, not {0:?}")]
    NoArrayAccess(Value),

    #[error("Expected a number, not {0:?}")]
    NotNumber(Value),

    #[error("Expected an integer, not {0:?}")]
    NotInt(f64),

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

    #[error("Expected raw Script or Bytes, not {0:?}. Perhaps you meant to use explicitScript()/scriptPubKey()?")]
    InvalidScriptConstructor(Value),

    #[error("Cannot represent as a scriptPubKey: {0:?}")]
    NoSpkRepr(Value),

    #[error("Invalid script fragment: {0:?}")]
    InvalidScriptFrag(Value),

    #[error("Only integers can be interpolated as script fragments, received a float: {0:?}")]
    InvalidScriptFragIntOnly(f64),

    #[error("Array index out of range")]
    ArrayIndexOutOfRange,

    #[error("Missing required value")]
    MissingValue,

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

    #[error("sh() can only wrap wsh() or wpkh()")]
    InvalidShUse,

    #[error("Script cannot be represented as an address: {0}")]
    NotAddressable(bitcoin::ScriptBuf),

    #[error("Number operation overflowed")]
    Overflow,

    #[error("in {0}(): {1}")]
    CallError(Ident, Box<RuntimeError>),

    #[error("{0:?} error: {1}")]
    InfixOpError(InfixOp, Box<RuntimeError>),

    #[error("Invalid arguments: ({0}, {1})")]
    InfixOpArgs(Value, Value),

    #[error("cannot mix number types ({0} and {1}). convert with explicit int()/float()")]
    InfixOpMixedNum(Value, Value),

    #[error("Invalid merkle root hash: {0}")]
    InvalidMerkleRoot(hashes::FromSliceError),

    #[error("Invalid pubkey key length: {0} (expected 32 or 33)")]
    InvalidPubKeyLen(usize),

    #[error("Invalid tr() use. Valid invocations are tr(PubKey), tr(Policy|Array<Policy>), tr(PubKey, Policy|Array<Policy>), tr(PubKey, Script|Array<Script>) or tr(PubKey, Hash)")]
    TaprootInvalidTrUse,

    #[error("Invalid Taproot unspendable key: {0}")]
    InvalidTrUnspendable(Value),

    #[error("No viable taproot internal key found, provide one explicitly")]
    TaprootNoViableKey,

    #[error("Invalid taproot binary script tree structure. Expecting a nested array where elements are leaf nodes (with no weights) or a tuple of nodes.")]
    TaprootInvalidScriptBinaryTree,

    #[error("Invalid taproot script, expecting Policy/Script or an array of them")]
    TaprootInvalidScript,

    #[error("Expected a tuple array of 2 elements, not {0:?}")]
    InvalidTuple(Value),

    #[error("Invalid tagged array structure: {0}")]
    InvalidTaggedList(Box<RuntimeError>),

    #[error("\"{0}\" tag error: {1}")]
    TagError(String, Box<RuntimeError>),

    #[error("Duplicated tag")]
    TagDuplicated,

    #[error("Unknown tag")]
    TagUnknown,

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

    #[error("Number type conversion failed (unexpected negative number?)")]
    TryFromInt(#[from] std::num::TryFromIntError),

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

    #[error("Descriptor key parse error: {0}")]
    DescKeyParse(#[from] descriptor::DescriptorKeyParseError),

    #[error("Invalid datetime string: {0}")]
    InvalidDateTime(#[from] chrono::ParseError),

    #[error("Absolute by-blocktime timelock out of range, supported up to 2106")]
    InvalidDateTimeOutOfRange,

    #[error("Parser error: {0}")]
    LalrError(String),
}

pub type LalrParseError<'a> =
    lalrpop_util::ParseError<usize, lalrpop_util::lexer::Token<'a>, ParseError>;

impl<'a> From<LalrParseError<'a>> for ParseError {
    fn from(e: LalrParseError<'a>) -> Self {
        ParseError::LalrError(e.to_string())
    }
}
