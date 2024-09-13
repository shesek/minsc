use std::result::Result as StdResult;

use bitcoin::{self, amount, bip32, hashes, hex, key, network, script, taproot, witness_program};
use miniscript::policy::compiler::CompilerError;
use miniscript::{descriptor, TranslateErr};

use crate::parser::ast::{Ident, InfixOp};
use crate::runtime::Value;
use crate::stdlib;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Parse error: {0}")]
    Parse(ParseError),

    #[error("Runtime error: {0}")]
    Runtime(RuntimeError),
}

pub type Result<T> = StdResult<T, Error>;

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

    #[error("Expected a secret key, not {0:?}")]
    NotSecKey(Box<Value>),

    #[error("Cannot be converted to Bytes: {0:?}")]
    NotBytesLike(Box<Value>),

    #[error("Expected a string, not {0:?}")]
    NotString(Box<Value>),

    #[error("Expected a single Xpub, not {0}")]
    NotSingleXpub(Box<miniscript::descriptor::DescriptorPublicKey>),

    #[error("Expected a single Xpriv, not {0}")]
    NotSingleXpriv(Box<miniscript::descriptor::DescriptorSecretKey>),

    #[error("Expected TapInfo or tr() Descriptor, not {0:?}")]
    NotTapInfoLike(Box<Value>),

    #[error("Expected a Policy (or a coercible PubKey/SecKey), not {0:?}")]
    NotPolicyLike(Box<Value>),

    #[error("Expected a descriptor or pubkey, not {0:?}")]
    NotDescriptorLike(Box<Value>),

    #[error("Expected Script, not {0:?}")]
    NotScript(Box<Value>),

    #[error("Expected a transaction as object, raw bytes or tagged list, not {0:?}")]
    NotTxLike(Box<Value>),

    #[error("Expected txid bytes or tx, not {0:?}")]
    NotTxidLike(Box<Value>),

    #[error(
        "Expected a 4 bytes BIP32 fingerprint or a key to compute the fingerprint for, not {0:?}"
    )]
    NotFingerprintLike(Box<Value>),

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

    #[error("No inner wildcard xpubs to derive")]
    NonDeriveableNoWildcard,

    #[error("Data type cannot be derived")]
    NonDeriveableType,

    #[error("Standalone keys cannot be derived")]
    NonDeriveableSingle,

    #[error(
        "Invalid derivation index. Only child numbers, hashes and multi-path arrays are supported."
    )]
    InvalidDerivationCode,

    #[error("Unexpected multi-path Xpriv, only single-path Xprivs or single keys are accepted")]
    InvalidMultiXprv,

    #[error("Unexpected multi-path Xpub, only single-path Xpubs or single keys are accepted")]
    InvalidMultiXpub,

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

    #[error("BIP32 derivation error: {0}")]
    SlashBip32Derive(#[source] Box<RuntimeError>),

    #[error("Number division cannot be used with BIP32 modifiers (', h and *)")]
    SlashUnexpectedBip32Mod,

    #[error("Invalid merkle root hash: {0}")]
    InvalidMerkleRoot(#[source] hashes::FromSliceError),

    #[error(
        "Invalid public key length {0} (expected 33 for single key, 32 for x-only or 78 for xpub"
    )]
    InvalidPubKeyLen(usize),

    #[error("Invalid secret key length {0} (expected 32 for single key or 78 for xpub)")]
    InvalidSecKeyLen(usize),

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

    // PSBT
    #[error("Cannot construct PSBT from {0:?}")]
    NotPsbtLike(Box<Value>),

    #[error("Expected PSBT sighash as number/string, not {0:?}")]
    PsbtInvalidSighashType(Box<Value>),

    #[error("PSBT tagged array construction must begin with the \"tx\"/\"unsigned_tx\" field")]
    PsbtFirstTagNotTx,

    #[error("Invalid PSBT source tx: {0}")]
    PsbtInvalidTx(#[source] Box<RuntimeError>),

    #[error("PSBT input #{0} does not exists")]
    PsbtInputNotFound(usize),

    #[error("PSBT output #{0} does not exists")]
    PsbtOutputNotFound(usize),

    #[error("PSBT finalization error(s): {}", .0.into_iter().map(ToString::to_string).collect::<Vec<_>>().join(" · "))]
    PsbtFinalize(Vec<miniscript::psbt::Error>),

    #[error("PSBT signing error(s): {}", .0.into_iter().map(|(i, e)| format!("input #{}: {}", i, e)).collect::<Vec<_>>().join(" · "))]
    PsbtSigning(bitcoin::psbt::SigningErrors),

    #[error("Missing fields to construct PSBT transaction input (prevout is required)")]
    PsbtTxInMissingFields,

    #[error("Missing fields to construct PSBT transaction output (amount and scriptPubKey/descriptor are required)")]
    PsbtTxOutMissingFields,

    #[error("Invalid PSBT signing keys. Expected an Xpriv, array of Xprivs, or a tagged array mapping from single PubKeys to single SecKeys")]
    PsbtInvalidSignKeys,

    // Generic error raised from user-land Minsc code
    #[error("Exception: {0}")]
    ScriptException(String),

    //
    // Wrapped errors
    //
    #[error(transparent)]
    ScriptMarker(#[from] stdlib::script_marker::MarkerError),

    #[error("Descriptor conversion error: {0}")]
    DescriptorConversion(#[from] descriptor::ConversionError),

    #[error("Descriptor key parse error: {0}")]
    DescriptorKeyParseError(#[from] descriptor::DescriptorKeyParseError),

    #[error("Miniscript error: {0}")]
    MiniscriptError(#[from] miniscript::Error),

    #[error("Miniscript compiler error: {0}")]
    MiniscriptCompilerError(#[from] CompilerError),

    #[error("Miniscript threshold error: {0}")]
    MiniscriptThreshold(#[from] miniscript::ThresholdError),

    #[error("Relative locktime error: {0}")]
    MiniscriptRelLockTime(#[from] miniscript::RelLockTimeError),

    #[error("Absolute locktime error: {0}")]
    MiniscriptAbsLockTime(#[from] miniscript::AbsLockTimeError),

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
    BitcoinKey(#[from] key::FromSliceError),

    #[error("BIP 32 error: {0}")]
    Bip32(#[from] bip32::Error),

    #[error("Bitcoin amount parse error: {0}")]
    ParseAmountError(#[from] amount::ParseAmountError),

    #[error("Number conversion failed: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("Bytes conversion failed: {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error("Parse int error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("Parse float error: {0}")]
    ParseFloat(#[from] std::num::ParseFloatError),

    #[error("fmt Error: {0}")]
    Fmt(#[from] std::fmt::Error),

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

    #[error("Invalid Script: {0}")]
    InvalidScript(#[from] bitcoin::script::Error),

    #[error("ECDSA error: {0}")]
    Ecdsa(#[from] bitcoin::ecdsa::Error),

    #[error("Failed extracting PSBT tx: {0}")]
    PsbtExtractTx(#[from] bitcoin::psbt::ExtractTxError),

    #[error("Invalid sighash: {0}")]
    SighashTypeParse(#[from] bitcoin::sighash::SighashTypeParseError),

    #[error("Failed parsing taproot signature: {0}")]
    SigFromSlice(#[from] bitcoin::taproot::SigFromSliceError),

    #[error("PSBT error: {0}")]
    Psbt(#[from] bitcoin::psbt::Error),

    #[error("Miniscript PSBT error: {0}")]
    MiniscriptPsbt(#[from] miniscript::psbt::Error),

    #[error("PSBT SigHash error: {0}")]
    PsbtSigHash(#[from] miniscript::psbt::SighashError),

    #[error("PSBT update error: {0}")]
    PsbtUtxoUpdate(#[from] miniscript::psbt::UtxoUpdateError),
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

pub trait ResultExt<T, E> {
    /// Like map_err(), but boxes the error. Can be used directly with the boxed enum variant,
    /// for example `result.box_ctx(Error::Foo)` with `enum Error { Foo(Box<Error>) }`
    fn box_err<O>(self, op: impl FnOnce(Box<E>) -> O) -> StdResult<T, O>;
}

impl<T, E> ResultExt<T, E> for StdResult<T, E> {
    fn box_err<O>(self, op: impl FnOnce(Box<E>) -> O) -> StdResult<T, O> {
        self.map_err(|e| op(Box::new(e)))
    }
}
