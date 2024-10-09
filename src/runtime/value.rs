use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

use miniscript::{bitcoin, descriptor};

use bitcoin::{
    hex::DisplayHex, taproot::TaprootSpendInfo, Address, Network, Psbt, ScriptBuf, Transaction,
};
use descriptor::{DescriptorPublicKey, DescriptorSecretKey};

use crate::parser::Expr;
use crate::util::{fmt_quoted_str, PrettyDisplay, EC};
use crate::{error, DescriptorDpk as Descriptor, PolicyDpk as Policy};

use crate::runtime::{Array, Error, Evaluate, Function, Result, Scope};

/// A runtime value. This is what gets passed around as function arguments, returned from functions,
/// and assigned to variables.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Number(Number),
    String(String),
    Bytes(Vec<u8>),
    Array(Array),
    Function(Function),

    // Bitcoin stuff
    Script(ScriptBuf),
    Address(Address),
    Transaction(Transaction),
    Network(Network),
    PubKey(DescriptorPublicKey),
    SecKey(DescriptorSecretKey),
    Policy(Policy),
    Descriptor(Descriptor),
    TapInfo(TaprootSpendInfo),
    Psbt(Psbt),
    WithProb(usize, Box<Value>), // Policy/Script with an associated execution probability (the `@` operator)

    // A unique Symbol
    Symbol(Symbol),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Number {
    Int(i64),
    Float(f64),
}
impl_from_variant!(i64, Number, Int);
impl_from_variant!(f64, Number, Float);

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Symbol {
    id: usize,
    name: Option<String>,
}

//
// Value conversions
//

// From primitive numbers to Value
impl From<i64> for Value {
    fn from(n: i64) -> Value {
        Number::Int(n).into()
    }
}
impl From<f64> for Value {
    fn from(n: f64) -> Value {
        Number::Float(n).into()
    }
}
impl From<u8> for Value {
    fn from(num: u8) -> Value {
        Number::Int(num.into()).into()
    }
}
impl From<usize> for Value {
    fn from(num: usize) -> Value {
        // TODO this should use TryFrom
        Number::Int(num.try_into().unwrap()).into()
    }
}
impl TryFrom<u64> for Value {
    type Error = Error;
    fn try_from(num: u64) -> Result<Self> {
        Ok(Value::Number(Number::Int(num.try_into()?)))
    }
}

// From NativeFunction/UserFunction to Value
impl<T: Into<Function>> From<T> for Value {
    fn from(f: T) -> Self {
        Value::Function(f.into())
    }
}

// From the underlying enum inner type to Value
impl_from_variant!(bool, Value, Bool);
impl_from_variant!(Number, Value);
impl_from_variant!(String, Value);
impl_from_variant!(Vec<u8>, Value, Bytes);
impl_from_variant!(Array, Value);
impl_from_variant!(Symbol, Value);
impl_from_variant!(Policy, Value);
impl_from_variant!(Descriptor, Value);
impl_from_variant!(DescriptorPublicKey, Value, PubKey);
impl_from_variant!(DescriptorSecretKey, Value, SecKey);
impl_from_variant!(ScriptBuf, Value, Script);
impl_from_variant!(Address, Value);
impl_from_variant!(Network, Value);
impl_from_variant!(Transaction, Value);
impl_from_variant!(TaprootSpendInfo, Value, TapInfo);
impl_from_variant!(Psbt, Value);

impl From<Vec<Value>> for Value {
    fn from(vec: Vec<Value>) -> Value {
        Value::Array(Array(vec))
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}

// From Value to the underlying enum inner type
// Simple extraction of the enum variant, with no specialized type coercion logic
impl_simple_into_variant!(bool, Bool, into_bool, NotBool);
impl_simple_into_variant!(Number, Number, into_number, NotNumber);
impl_simple_into_variant!(Array, Array, into_array, NotArray);
impl_simple_into_variant!(Function, Function, into_fn, NotFn);
impl_simple_into_variant!(String, String, into_string, NotString);

// From Value to f64 primitive, with auto-coercion for integers
impl TryFrom<Value> for f64 {
    type Error = Error;
    fn try_from(value: Value) -> Result<f64> {
        value.into_number()?.try_into()
    }
}
impl TryFrom<Number> for f64 {
    type Error = Error;
    fn try_from(value: Number) -> Result<f64> {
        Ok(match value {
            Number::Float(f) => f,
            Number::Int(n) => {
                let f = n as f64;
                ensure!(f as i64 == n, Error::Overflow); // ensure it is within the representable f64 range (-2^53 to 2^53)
                f
            }
        })
    }
}

// From Value to primitive integer types, with no auto-coercion for floats
macro_rules! impl_int_num_conv {
    ($type:ident, $fn_name:ident) => {
        impl TryFrom<Number> for $type {
            type Error = Error;
            fn try_from(number: Number) -> Result<Self> {
                Ok(match number {
                    Number::Int(n) => n.try_into()?,
                    Number::Float(f) => bail!(Error::NotInt(f)),
                })
            }
        }
        impl TryFrom<Value> for $type {
            type Error = Error;
            fn try_from(value: Value) -> Result<Self> {
                // Extract the Value::Number, then delegate to TryFrom<Number> above
                value.into_number()?.try_into()
            }
        }
        impl Number {
            pub fn $fn_name(self) -> Result<$type> {
                self.try_into()
            }
        }
        impl Value {
            pub fn $fn_name(self) -> Result<$type> {
                self.try_into()
            }
        }
    };
}
impl_int_num_conv!(u32, into_u32);
impl_int_num_conv!(u64, into_u64);
impl_int_num_conv!(usize, into_usize);
impl_int_num_conv!(i32, into_i32);
impl_int_num_conv!(i64, into_i64);
impl_int_num_conv!(isize, into_isize);

// From Value to Vec<u8>
impl TryFrom<Value> for Vec<u8> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        use descriptor::SinglePubKey::{FullKey as Full, XOnly};
        use descriptor::{DescriptorPublicKey as Dpk, DescriptorSecretKey as Dsk, SinglePub};
        Ok(match value {
            Value::Bytes(bytes) => bytes,
            Value::String(string) => string.into_bytes(),
            Value::Script(script) => script.into_bytes(),
            Value::Transaction(tx) => bitcoin::consensus::serialize(&tx),
            // XXX PubKey/SecKey not fully round-trip-able - only the key is encoded, without the bip32 `origin` field associated with it
            Value::PubKey(dpk) => match dpk {
                Dpk::XPub(xpub) => xpub
                    .xkey
                    .derive_pub(&EC, &xpub.derivation_path)?
                    .encode()
                    .to_vec(),
                Dpk::Single(SinglePub { key: Full(pk), .. }) => pk.to_bytes(),
                Dpk::Single(SinglePub { key: XOnly(pk), .. }) => pk.serialize().to_vec(),
                Dpk::MultiXPub(_) => bail!(Error::InvalidMultiXpub),
            },
            Value::SecKey(dsk) => match dsk {
                Dsk::XPrv(xprv) => xprv
                    .xkey
                    .derive_priv(&EC, &xprv.derivation_path)?
                    .encode()
                    .to_vec(),
                // XXX not fully round-trip-able - bitcoin::PrivateKey::to_bytes() does not preserve the compressed/uncompressed flag
                Dsk::Single(sk) => sk.key.to_bytes(),
                Dsk::MultiXPrv(_) => bail!(Error::InvalidMultiXprv),
            },
            Value::Psbt(psbt) => psbt.serialize(),
            v => bail!(Error::NotBytesLike(v.into())),
        })
    }
}

/// Generic conversion from a Value/Option<Value> into T/Option<T> of any TryFrom<Value> type.
///
/// Used to support types that can be either required or optional (for example by into_tagged()).
/// Must use a new trait because TryFrom<Option<Value>> would violate the orphan rule.
/// This is blanket-implemented for types that implement TryFrom<Value>, which should be preferred
/// over using FromValue directly unless necessary.
pub trait FromValue: Sized {
    const IS_REQUIRED: bool;

    fn from_value(value: Value) -> Result<Self>;
    fn from_opt_value(value: Option<Value>) -> Result<Self>;
}

impl<T> FromValue for T
where
    T: TryFrom<Value> + FromValueMarker,
    Error: From<T::Error>,
{
    const IS_REQUIRED: bool = true;

    fn from_value(value: Value) -> Result<T> {
        Ok(value.try_into()?)
    }
    fn from_opt_value(value: Option<Value>) -> Result<T> {
        // Convert from Option<Value> to a T, erroring if there's no Value
        Ok(value.ok_or(Error::MissingValue)?.try_into()?)
    }
}

impl<T> FromValue for Option<T>
where
    T: TryFrom<Value> + FromValueMarker,
    Error: From<T::Error>,
{
    const IS_REQUIRED: bool = false;

    fn from_value(value: Value) -> Result<Option<T>> {
        Ok(Some(value.try_into()?))
    }
    fn from_opt_value(value: Option<Value>) -> Result<Option<T>> {
        // Convert from Option<Value> to an Option<T>, keeping `None`s
        Ok(value.map(Value::try_into).transpose()?)
    }
}

// The above FromValue impls cannot be implemented for any TryFrom<Value> because they would conflict with each-other
// (due to a blanket trait implementations in the stdlib?). The FromValueMarker trait restricts the supported types
// to our own types, which are identified by virtue of using our runtime::Error for their TryFrom conversion.
pub trait FromValueMarker {}
impl<T: TryFrom<Value, Error = Error>> FromValueMarker for T {}
impl FromValueMarker for Value {}

// Generic conversion from a Value containing an Array into a Vec, HashSet, HashMap, BTreeSet,
// BTreeMap or 1/2/3-tuples of any FromValue type. Delegated to the inner Array's TryFrom.
macro_rules! impl_delegate_array_conv {
    ($type:ty, $($param:tt)*) => {
        impl<$($param)*> TryFrom<Value> for $type {
            type Error = Error;
            fn try_from(val: Value) -> Result<$type> {
                val.into_array()?.try_into()
            }
        }
    };
}
impl_delegate_array_conv!(Vec<T>, T: FromValue);
impl_delegate_array_conv!(HashSet<T>, T: FromValue + std::hash::Hash + Eq);
impl_delegate_array_conv!(BTreeSet<T>, T: FromValue + Eq + Ord);
impl_delegate_array_conv!(BTreeMap<K, V>, K: FromValue + Ord, V: FromValue);
impl_delegate_array_conv!(HashMap<K, V>, K: FromValue + std::hash::Hash + Eq, V: FromValue);
impl_delegate_array_conv!((A, ), A: FromValue);
impl_delegate_array_conv!((A, B), A: FromValue, B: FromValue);
impl_delegate_array_conv!((A, B, C), A: FromValue, B: FromValue, C: FromValue);

//
// Value impl
//

impl Value {
    pub fn type_of(&self) -> &'static str {
        match self {
            Value::PubKey(_) => "pubkey",
            Value::SecKey(_) => "seckey",
            Value::Bool(_) => "bool",
            Value::Bytes(_) => "bytes",
            Value::String(_) => "string",
            Value::Policy(_) => "policy",
            Value::WithProb(_, _) => "withprob",
            Value::Descriptor(_) => "descriptor",
            Value::Address(_) => "address",
            Value::Script(_) => "script",
            Value::Transaction(_) => "transaction",
            Value::Function(_) => "function",
            Value::Network(_) => "network",
            Value::TapInfo(_) => "tapinfo",
            Value::Psbt(_) => "psbt",
            Value::Array(_) => "array",
            Value::Symbol(_) => "symbol",
            Value::Number(Number::Int(_)) => "int",
            Value::Number(Number::Float(_)) => "float",
        }
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }
    pub fn is_number(&self) -> bool {
        matches!(self, Value::Number(_))
    }
    pub fn is_string(&self) -> bool {
        matches!(self, Value::String(_))
    }
    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }
    pub fn is_bytes(&self) -> bool {
        matches!(self, Value::Bytes(_))
    }
    pub fn is_empty_array(&self) -> bool {
        matches!(self, Value::Array(arr) if arr.is_empty())
    }

    pub fn into_u8(self) -> Result<u8> {
        // Cannot be implemented as TryFrom because the Vec<u8> and Vec<T> conversions would conflict
        Ok(self.into_u32()?.try_into()?)
    }

    pub fn into_f64(self) -> Result<f64> {
        self.try_into()
    }

    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.try_into()
    }

    pub fn map_array<T, F: Fn(Value) -> Result<T>>(self, f: F) -> Result<Vec<T>> {
        self.into_array()?.into_iter().map(f).collect()
    }

    pub fn into_vec(self) -> Result<Vec<Value>> {
        Ok(self.into_array()?.0)
    }

    /// Transform Array elements into a Vec<T> of any FromValue type
    pub fn into_vec_of<T: FromValue>(self) -> Result<Vec<T>> {
        self.try_into()
    }

    /// Transform an Array of 2 elements into a typed 2-tuple of FromValue types
    pub fn into_tuple<A: FromValue, B: FromValue>(self) -> Result<(A, B)> {
        self.try_into()
    }

    pub fn is_tagged_with(&self, tag: &str) -> bool {
        matches!(self, Value::Array(arr) if arr.is_tagged_with(tag))
    }

    pub fn array(elements: Vec<Value>) -> Self {
        Value::Array(Array(elements))
    }
    pub fn array_of(array: impl Into<Array>) -> Self {
        Value::Array(array.into())
    }
}

// Parse & evaluate the string code in the default global scope to produce a Value
impl FromStr for Value {
    type Err = error::Error;
    fn from_str(s: &str) -> error::Result<Self> {
        Ok(Expr::from_str(s)?.eval(&Scope::root())?)
    }
}

// Display

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Mostly round-trip-able, see ReprExpr for a string representation that always is
        match self {
            Value::Number(x) => write!(f, "{}", x),
            Value::Bool(x) => write!(f, "{}", x),
            Value::Bytes(x) => write!(f, "0x{}", x.as_hex()),
            Value::String(x) => fmt_quoted_str(f, x),
            Value::Policy(x) => write!(f, "{}", x),
            Value::WithProb(p, x) => write!(f, "{}@{}", p, x),
            Value::Descriptor(x) => write!(f, "{:#}", x), // not round-trip-able (ExprRepr is)
            Value::Address(x) => write!(f, "{}", x),
            Value::Function(x) => write!(f, "{}", x), // not round-trip-able (cannot be)
            Value::Network(x) => write!(f, "{}", x),
            Value::Symbol(x) => write!(f, "{}", x),
            Value::Psbt(x) => write!(f, "{}", x.pretty(None)),
            Value::SecKey(x) => write!(f, "{}", x.pretty(None)),
            Value::PubKey(x) => write!(f, "{}", x.pretty(None)),
            Value::Array(x) => write!(f, "{}", x.pretty(None)),
            Value::Transaction(x) => write!(f, "{}", x.pretty(None)),
            Value::Script(x) => write!(f, "{}", x.pretty(None)),
            Value::TapInfo(x) => write!(f, "{}", x.pretty(None)),
        }
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Number::Int(x) => write!(f, "{}", x),
            Number::Float(x) => write!(f, "{:?}", x),
        }
    }
}
impl PrettyDisplay for Value {
    const AUTOFMT_ENABLED: bool = true;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        match self {
            Value::PubKey(x) => write!(f, "{}", x.pretty(indent)),
            Value::SecKey(x) => write!(f, "{}", x.pretty(indent)),
            Value::Array(x) => write!(f, "{}", x.pretty(indent)),
            Value::Script(x) => write!(f, "{}", x.pretty(indent)),
            Value::Transaction(x) => write!(f, "{}", x.pretty(indent)),
            Value::TapInfo(x) => write!(f, "{}", x.pretty(indent)),
            Value::Psbt(x) => write!(f, "{}", x.pretty(indent)),

            // Use Display for other types that don't implement PrettyDisplay
            other => write!(f, "{}", other),
        }
    }
}

/// Round-trip-able string encoding as a Minsc expression that can be evaluated to reproduce the original Value.
/// Used as the encoding format to pass around Values between the Minsc runtime and other runtimes (currently WASM/JS).
pub trait ExprRepr {
    fn repr_fmt<W: fmt::Write>(&self, f: &mut W) -> fmt::Result;

    fn repr_str(&self) -> String {
        let mut s = String::new();
        self.repr_fmt(&mut s).unwrap();
        s
    }
}

impl ExprRepr for Value {
    fn repr_fmt<W: fmt::Write>(&self, f: &mut W) -> fmt::Result {
        use Value::*;
        match self {
            // For most types we can delegate to Display, which already is round-trip-able
            // (Symbols are encoded as their name, which is expected to be made round-trip-able)
            Number(_) | Bool(_) | Bytes(_) | String(_) | Network(_) | Address(_) | Symbol(_)
            | SecKey(_) | PubKey(_) | Policy(_) => write!(f, "{}", self),

            // These also have round-trip-able Display, but can be expressed more compactly/precisely for ExprRepr
            Transaction(tx) => write!(f, "tx(0x{})", bitcoin::consensus::serialize(tx).as_hex()),
            Script(script) => write!(f, "script(0x{})", script.as_bytes().as_hex()),
            Psbt(psbt) => write!(f, "psbt(0x{})", psbt.serialize().as_hex()),
            TapInfo(tapinfo) => tapinfo.repr_fmt(f),

            // Descriptors require special handling when they have script paths (i.e. not (W)Pkh or script-less Tr)
            Descriptor(desc) => desc.repr_fmt(f),

            // Functions cannot be round tripped, as they depend on their lexical scope.
            // Write null instead of erroring so that arrays containing them may otherwise be ExprRepr-serialized.
            Function(func) => write!(f, "/**{}*/null", func),

            // Use ExprRepr to encode inner values
            Array(arr) => {
                write!(f, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    item.repr_fmt(f)?;
                }
                write!(f, "]")
            }
            WithProb(p, x) => {
                write!(f, "{}@", p)?;
                x.repr_fmt(f)
            }
        }
    }
}

// Symbol
//
// A Value type guaranteed to be unique. Symbols don't have any special meaning on the Rust side, but are used in
// Minsc code for various purposes (like `null` and `default`). Symbols can be created at runtime using Symbol().

use std::sync::atomic::{AtomicUsize, Ordering};
static SYMBOL_COUNTER: AtomicUsize = AtomicUsize::new(1);

impl Symbol {
    pub fn new(name: Option<String>) -> Self {
        let id = SYMBOL_COUNTER.fetch_add(1, Ordering::Relaxed);
        Symbol { id, name }
    }
}
impl fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(f, "symbol({}, \"{}\")", self.id, name),
            None => write!(f, "symbol({})", self.id),
        }
    }
}
impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(name) => write!(f, "{}", name),
            None => write!(f, "symbol()"),
        }
    }
}
