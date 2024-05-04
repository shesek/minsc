use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpub};
use bitcoin::hashes::{self, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::key::TweakedPublicKey;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{
    Address, Network, PublicKey, ScriptBuf, WitnessProgram, WitnessVersion, XOnlyPublicKey,
};
use miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, SinglePub, SinglePubKey};
use miniscript::{bitcoin, descriptor, ScriptContext};

use crate::parser::Expr;
use crate::util::DescriptorExt;
use crate::{error, DescriptorDpk as Descriptor, MiniscriptDpk as Miniscript, PolicyDpk as Policy};

use crate::runtime::{Array, Error, Evaluate, Function, Result, Scope};

/// A runtime value. This is what gets passed around as function arguments, returned from functions,
/// and assigned to variables.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    PubKey(DescriptorPublicKey),
    Bytes(Vec<u8>),
    String(String),
    Number(Number),
    Bool(bool),
    Network(Network),

    Policy(Policy),
    WithProb(usize, Box<Value>),

    Descriptor(Descriptor),
    Script(ScriptBuf),
    Address(Address),
    TapInfo(TaprootSpendInfo),

    Array(Array),
    Function(Function),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Number {
    Int(i64),
    Float(f64),
}
impl_from_variant!(i64, Number, Int);
impl_from_variant!(f64, Number, Float);

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
impl From<usize> for Value {
    fn from(num: usize) -> Value {
        // TODO this should use TryFrom
        Number::Int(num.try_into().unwrap()).into()
    }
}

// From NativeFunction/UserFunction to Value
impl<T: Into<Function>> From<T> for Value {
    fn from(f: T) -> Self {
        Value::Function(f.into())
    }
}

// From the underlying enum inner type to Value
impl_from_variant!(Policy, Value);
impl_from_variant!(Descriptor, Value);
impl_from_variant!(DescriptorPublicKey, Value, PubKey);
impl_from_variant!(ScriptBuf, Value, Script);
impl_from_variant!(Address, Value);
impl_from_variant!(Vec<u8>, Value, Bytes);
impl_from_variant!(String, Value);
impl_from_variant!(Network, Value);
impl_from_variant!(TaprootSpendInfo, Value, TapInfo);
impl_from_variant!(Number, Value);
impl_from_variant!(bool, Value, Bool);
impl_from_variant!(Array, Value, Array);
impl From<Vec<Value>> for Value {
    fn from(vec: Vec<Value>) -> Value {
        Value::Array(Array(vec))
    }
}

// From Value to the underlying enum inner type
// Simple extraction of the enum variant, with no specialized type coercion logic
macro_rules! impl_simple_into_variant_conv {
    ($type:path, $variant:ident, $into_fn_name:ident, $error:ident) => {
        impl TryFrom<Value> for $type {
            type Error = Error;
            fn try_from(value: Value) -> Result<Self> {
                match value {
                    Value::$variant(x) => Ok(x),
                    v => Err(Error::$error(v)),
                }
            }
        }
        impl Value {
            pub fn $into_fn_name(self) -> Result<$type> {
                self.try_into()
            }
        }
    };
}
impl_simple_into_variant_conv!(bool, Bool, into_bool, NotBool);
impl_simple_into_variant_conv!(Number, Number, into_number, NotNumber);
impl_simple_into_variant_conv!(Array, Array, into_array, NotArray);
impl_simple_into_variant_conv!(Network, Network, into_network, NotNetwork);
impl_simple_into_variant_conv!(Function, Function, into_fn, NotFn);
impl_simple_into_variant_conv!(ScriptBuf, Script, into_script, NotScript);
impl_simple_into_variant_conv!(String, String, into_string, NotString);

// From Value to f64 primitive, with auto-coercion for integers
impl TryInto<f64> for Value {
    type Error = Error;
    fn try_into(self) -> Result<f64> {
        Ok(match self.into_number()? {
            Number::Float(n) => n,
            Number::Int(n) => n as f64,
        })
    }
}

// From Value to primitive integer types (no coercion)
macro_rules! impl_int_num_conv {
    ($type:ident, $fn_name:ident) => {
        impl TryFrom<Number> for $type {
            type Error = Error;
            fn try_from(number: Number) -> Result<Self> {
                Ok(match number {
                    Number::Int(n) => n.try_into()?,
                    Number::Float(n) => bail!(Error::NotInt(n)),
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
impl_int_num_conv!(i64, into_i64);
impl_int_num_conv!(usize, into_usize);
impl_int_num_conv!(u32, into_u32);
impl_int_num_conv!(u64, into_u64);
impl_int_num_conv!(i32, into_i32);

// From Value to Bitcoin/Miniscript types
impl TryFrom<Value> for Policy {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Policy(policy) => Ok(policy),
            // Pubkeys are coerced into a pk() policy
            Value::PubKey(pubkey) => Ok(Policy::Key(pubkey)),
            v => Err(Error::NotPolicyLike(v)),
        }
    }
}
impl TryFrom<Value> for DescriptorPublicKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::PubKey(x) => Ok(x),
            // Bytes are coerced into a PubKey when they are 33 or 32 bytes long
            Value::Bytes(bytes) => {
                let key = match bytes.len() {
                    33 => SinglePubKey::FullKey(PublicKey::from_slice(&bytes)?),
                    32 => SinglePubKey::XOnly(XOnlyPublicKey::from_slice(&bytes)?),
                    // uncompressed keys are currently unsupported
                    len => bail!(Error::InvalidPubKeyLen(len)),
                };
                Ok(DescriptorPublicKey::Single(SinglePub { key, origin: None }))
            }
            v => Err(Error::NotPubKey(v)),
        }
    }
}
impl TryFrom<Value> for Descriptor {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Descriptor(x) => Ok(x),
            // PubKeys are coerced into a wpkh() descriptor
            Value::PubKey(x) => Ok(Descriptor::new_wpkh(x)?),
            v => Err(Error::NotDescriptorLike(v)),
        }
    }
}
impl<Ctx: ScriptContext> TryFrom<Value> for Miniscript<Ctx> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(value.into_policy()?.compile()?)
    }
}
impl TryFrom<Value> for TaprootSpendInfo {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::TapInfo(tapinfo) => tapinfo,
            Value::Descriptor(desc) => match desc.at_derivation_index(0)? {
                miniscript::Descriptor::Tr(tr_desc) => (*tr_desc.spend_info()).clone(),
                _ => bail!(Error::NotTapInfoLike(Value::Descriptor(desc))),
            },
            v => bail!(Error::NotTapInfoLike(v)),
        })
    }
}

// From Bitcoin/Miniscript types to Value
impl From<XOnlyPublicKey> for Value {
    fn from(key: XOnlyPublicKey) -> Self {
        Value::PubKey(DescriptorPublicKey::Single(SinglePub {
            key: SinglePubKey::XOnly(key),
            origin: None,
        }))
    }
}
impl From<TweakedPublicKey> for Value {
    fn from(key: TweakedPublicKey) -> Self {
        key.to_inner().into()
    }
}
impl From<Xpub> for Value {
    fn from(xpub: Xpub) -> Self {
        Value::PubKey(DescriptorPublicKey::XPub(DescriptorXKey {
            xkey: xpub,
            derivation_path: DerivationPath::master(),
            wildcard: descriptor::Wildcard::Unhardened,
            origin: if xpub.depth > 0 {
                Some((xpub.parent_fingerprint, [xpub.child_number][..].into()))
            } else {
                None
            },
        }))
    }
}

// From Value to Vec<u8>
impl TryFrom<Value> for Vec<u8> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Bytes(bytes) => bytes,
            Value::String(string) => string.into_bytes(),
            Value::Script(script) => script.into_bytes(),
            v => bail!(Error::NotBytesLike(v)),
        })
    }
}

// From Value to Hash types +
// From Hash types to Value
macro_rules! impl_hash_conv {
    ($name:path) => {
        impl TryFrom<Value> for $name {
            type Error = Error;
            fn try_from(value: Value) -> Result<Self> {
                match value {
                    Value::Bytes(b) => Ok(Self::from_slice(&b)?),
                    v => Err(Error::NotHashLike(v)),
                }
            }
        }
        impl From<$name> for Value {
            fn from(hash: $name) -> Self {
                Value::Bytes(hash.to_byte_array().to_vec())
            }
        }
    };
}
impl_hash_conv!(hashes::sha256::Hash);
impl_hash_conv!(hashes::sha256d::Hash);
impl_hash_conv!(hashes::ripemd160::Hash);
impl_hash_conv!(hashes::hash160::Hash);
impl_hash_conv!(miniscript::hash256::Hash);

// Generic conversion from Value::Array into a Vec of any convertible type
impl<T: FromValue> TryFrom<Value> for Vec<T> {
    type Error = Error;
    fn try_from(val: Value) -> Result<Vec<T>> {
        val.into_array()?.try_into()
    }
}

// Generic conversion from Value::Array into a 2-tuple of any convertible type
impl<A: FromValue, B: FromValue> TryFrom<Value> for (A, B) {
    type Error = Error;
    fn try_from(val: Value) -> Result<(A, B)> {
        val.into_array()?.try_into()
    }
}

// Generic conversion from a Value/Option<Value> into T/Option<T>
// Used to support types that can be either required or optional (for example by into_tagged())
// Must use a new trait because TryFrom<Option<Value>> would violate the orphan rule.
pub trait FromValue: Sized {
    fn from_value(value: Value) -> Result<Self>;
    fn from_opt_value(value: Option<Value>) -> Result<Self>;
    fn is_optional() -> bool;
    fn is_required() -> bool {
        !Self::is_optional()
    }
}

impl<T> FromValue for T
where
    T: TryFrom<Value> + FromValueMarker,
    Error: From<T::Error>,
{
    fn from_value(value: Value) -> Result<T> {
        Ok(value.try_into()?)
    }
    fn from_opt_value(value: Option<Value>) -> Result<T> {
        // Convert from Option<Value> to a T, erroring if there's no Value
        Ok(value.ok_or(Error::MissingValue)?.try_into()?)
    }
    fn is_optional() -> bool {
        false
    }
}

impl<T> FromValue for Option<T>
where
    T: TryFrom<Value> + FromValueMarker,
    Error: From<T::Error>,
{
    fn from_value(value: Value) -> Result<Option<T>> {
        Ok(Some(value.try_into()?))
    }
    fn from_opt_value(value: Option<Value>) -> Result<Option<T>> {
        // Convert from Option<Value> to an Option<T>, keeping `None`s
        Ok(value.map(Value::try_into).transpose()?)
    }
    fn is_optional() -> bool {
        true
    }
}

// The above FromValue impls cannot be implemented for any TryFrom<Value> because they would conflict with each-other
// (due to a blanket trait implementations in the stdlib?). The FromValueMarker trait restricts the supported types
// to our own types, which are identified by virtue of using our runtime::Error for their TryFrom conversion.
pub trait FromValueMarker {}
impl<T: TryFrom<Value, Error = Error>> FromValueMarker for T {}
impl FromValueMarker for Value {}

//
// Value methods
//

impl Value {
    /// Get the scriptPubKey representation of this Value
    pub fn into_spk(self) -> Result<ScriptBuf> {
        Ok(match self {
            // Raw scripts are returned as-is
            Value::Script(script) => script,
            // Descriptors (or values coercible into them) are converted into their scriptPubKey
            v @ Value::Descriptor(_) | v @ Value::PubKey(_) => v.into_desc()?.to_script_pubkey()?,
            // TapInfo returns the output V1 witness program of the output key
            Value::TapInfo(tapinfo) => ScriptBuf::new_witness_program(&WitnessProgram::new(
                WitnessVersion::V1,
                &tapinfo.output_key().serialize(),
            )?),
            Value::Address(addr) => addr.script_pubkey(),
            v => bail!(Error::NoSpkRepr(v)),
        })
    }

    /// Extract Array elements as plain Vec<Value>
    pub fn into_array_elements(self) -> Result<Vec<Value>> {
        Ok(self.into_array()?.inner())
    }

    /// Transform Array elements into a Vec<T> of any convertible type
    pub fn into_vec_of<T: FromValue>(self) -> Result<Vec<T>> {
        self.try_into()
    }

    /// Transform an Array of 2 elements into a typed 2-tuple
    pub fn into_tuple<A: FromValue, B: FromValue>(self) -> Result<(A, B)> {
        self.try_into()
    }

    pub fn type_of(&self) -> &'static str {
        match self {
            Value::PubKey(_) => "pubkey",
            Value::Number(_) => "number",
            Value::Bool(_) => "bool",
            Value::Bytes(_) => "bytes",
            Value::String(_) => "string",
            Value::Policy(_) => "policy",
            Value::WithProb(_, _) => "withprob",
            Value::Descriptor(_) => "descriptor",
            Value::Address(_) => "address",
            Value::Script(_) => "script",
            Value::Function(_) => "function",
            Value::Network(_) => "network",
            Value::TapInfo(_) => "tapinfo",
            Value::Array(_) => "array",
        }
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }
    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }
    pub fn is_bytes(&self) -> bool {
        matches!(self, Value::Bytes(_))
    }
    pub fn is_policy(&self) -> bool {
        matches!(self, Value::Policy(_))
    }
    pub fn is_desc(&self) -> bool {
        matches!(self, Value::Descriptor(_))
    }
    pub fn is_script(&self) -> bool {
        matches!(self, Value::Script(_))
    }
    pub fn is_empty_array(&self) -> bool {
        matches!(self, Value::Array(arr) if arr.is_empty())
    }

    pub fn array(elements: Vec<Value>) -> Self {
        Value::Array(Array(elements))
    }

    pub fn into_f64(self) -> Result<f64> {
        self.try_into()
    }
    pub fn into_policy(self) -> Result<Policy> {
        self.try_into()
    }
    pub fn into_key(self) -> Result<DescriptorPublicKey> {
        self.try_into()
    }
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.try_into()
    }
    pub fn into_desc(self) -> Result<Descriptor> {
        self.try_into()
    }
    pub fn into_miniscript<Ctx: ScriptContext>(self) -> Result<Miniscript<Ctx>> {
        self.try_into()
    }
    pub fn into_tapinfo(self) -> Result<TaprootSpendInfo> {
        self.try_into()
    }
}

// Parse & evaluate the string code in the default global scope to produce a Value
impl FromStr for Value {
    type Err = error::Error;
    fn from_str(s: &str) -> error::Result<Self> {
        Ok(Expr::from_str(s)?.eval(&Scope::root())?)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Value::PubKey(x) => write!(f, "{}", x),
            Value::Number(x) => write!(f, "{}", x),
            Value::Bool(x) => write!(f, "{}", x),
            Value::Bytes(x) => write!(f, "0x{}", x.to_lower_hex_string()),
            Value::String(x) => write!(f, "\"{}\"", escape_str(x)),
            Value::Array(x) => write!(f, "{}", x),
            Value::Policy(x) => write!(f, "{}", x),
            Value::WithProb(p, x) => write!(f, "{}@{}", p, x),
            Value::Descriptor(x) => write!(f, "{}", x),
            Value::Address(x) => write!(f, "{}", x),
            Value::Script(x) => write!(f, "{:?}", x),
            Value::Function(x) => write!(f, "{:?}", x),
            Value::Network(x) => write!(f, "{}", x),
            Value::TapInfo(x) => write!(f, "{:?}", x),
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

fn escape_str(str: &str) -> String {
    str.bytes()
        .into_iter()
        .flat_map(core::ascii::escape_default)
        .map(char::from)
        .collect()
}
