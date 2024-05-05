use ::miniscript::bitcoin::{self, Address, Network, ScriptBuf};
use bitcoin::hashes::{sha256, Hash};

use crate::runtime::{Array, Error, Execute, Number, Result, Scope, Value};
use crate::{parser, time};

pub mod ctv;
pub mod miniscript;
pub mod tagged;
pub mod taproot;

lazy_static! {
    static ref MINSC_STDLIB: parser::Library = include_str!("stdlib.minsc").parse().unwrap();
    static ref ELEMENTS_STDLIB: parser::Library = include_str!("elements.minsc").parse().unwrap();
}

/// Attach built-in functions and variables to the Minsc runtime environment
pub fn attach_stdlib(scope: &mut Scope) {
    // Boolean types
    scope.set("true", true).unwrap();
    scope.set("false", false).unwrap();

    // Network types
    scope.set("signet", Network::Signet).unwrap();
    scope.set("testnet", Network::Testnet).unwrap();
    scope.set("regtest", Network::Regtest).unwrap();
    scope
        .set("_$$_RECKLESSLY_RISK_MY_BITCOINS_$$_", Network::Bitcoin)
        .unwrap();

    // Functions
    scope.set_fn("typeof", fns::r#typeof).unwrap();
    scope.set_fn("len", fns::len).unwrap();
    scope.set_fn("reduce", fns::reduce).unwrap();
    scope.set_fn("repeat", fns::repeat).unwrap();

    scope.set_fn("int", fns::int).unwrap();
    scope.set_fn("float", fns::float).unwrap();
    scope.set_fn("bytes", fns::bytes).unwrap();

    scope.set_fn("address", fns::address).unwrap();
    scope.set_fn("script", fns::script).unwrap();
    scope.set_fn("scriptPubKey", fns::scriptPubKey).unwrap();

    scope.set_fn("le64", fns::le64).unwrap();
    scope.set_fn("SHA256", fns::SHA256).unwrap();

    // Constants
    scope.set("BLOCK_INTERVAL", time::BLOCK_INTERVAL).unwrap();
    scope.set("MAX_NUMBER", i64::MAX).unwrap();
    scope.set("MIN_NUMBER", i64::MIN).unwrap();

    // Miniscript related functions
    self::miniscript::attach_stdlib(scope);

    // Taproot related functions
    self::taproot::attach_stdlib(scope);

    // CTV
    self::ctv::attach_stdlib(scope);

    // Standard library implemented in Minsc
    MINSC_STDLIB.exec(scope).unwrap();
    ELEMENTS_STDLIB.exec(scope).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;
    use crate::runtime::{Call, Function};

    /// Get the argument type as a string
    /// One of: pubkey, number, bool, bytes, policy, withprob, descriptor, address, script, function, network, tapinfo, array
    /// typeof(Value) -> String
    pub fn r#typeof(args: Array, _: &Scope) -> Result<Value> {
        let type_of = args.arg_into::<Value>()?.type_of();
        Ok(type_of.to_string().into())
    }

    /// len(Array|Bytes|Script|String) -> Number
    pub fn len(args: Array, _: &Scope) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Array(array) => array.len(),
            Value::Bytes(bytes) => bytes.len(),
            Value::String(string) => string.len(),
            Value::Script(script) => script.into_bytes().len(),
            _ => bail!(Error::InvalidArguments),
        }
        .into())
    }

    /// reduce(Array, Value, Function) -> Value
    pub fn reduce(args: Array, scope: &Scope) -> Result<Value> {
        let (array, mut current_val, callback): (Array, Value, Function) = args.args_into()?;

        for element in array.into_iter() {
            current_val = callback.call(vec![current_val, element], scope)?;
        }
        Ok(current_val)
    }

    /// repeat(Number, Value) -> Array<Value>
    /// Return an array of the specified size filled with Values
    ///
    /// repeat(Number, Function) -> Array<Value>
    /// Return an array of the specified size, using the callback function to produce values
    pub fn repeat(args: Array, scope: &Scope) -> Result<Value> {
        let (num, producer): (usize, Value) = args.args_into()?;
        Ok(Value::array(
            (0..num)
                .map(|n| match &producer {
                    // The callback is called with the iteration index as an argument
                    Value::Function(callback) => callback.call(vec![n.into()], scope),
                    other => Ok(other.clone()),
                })
                .collect::<Result<_>>()?,
        ))
    }

    pub fn int(args: Array, _: &Scope) -> Result<Value> {
        let num = match args.arg_into()? {
            Number::Int(n) => n,
            Number::Float(n) if n.is_finite() && n >= i64::MIN as f64 && n <= i64::MAX as f64 => {
                // rounded down
                n as i64
            }
            Number::Float(_) => bail!(Error::Overflow),
        };

        Ok(num.into())
    }

    pub fn float(args: Array, _: &Scope) -> Result<Value> {
        let num_float: f64 = args.arg_into()?;
        //let num_val: Value = args.arg_into()?;
        //let num_float: f64 = num_val.try_into()?;
        Ok(num_float.into())

    }
    /// Convert the argument into Bytes
    /// Scripts are serialized, Strings are converted to Bytes, Bytes are returned as-is
    /// bytes(Script|Bytes|String) -> Bytes
    pub fn bytes(args: Array, _: &Scope) -> Result<Value> {
        let bytes: Vec<u8> = args.arg_into()?;
        Ok(bytes.into())
    }

    /// Generate an address
    /// address(Script|Descriptor|PubKey|TapInfo|String|Address) -> Address
    pub fn address(args: Array, _: &Scope) -> Result<Value> {
        let (spk, network): (Value, Option<Network>) = args.args_into()?;
        let spk = spk.into_spk()?;
        let network = network.unwrap_or(Network::Signet);

        Ok(Address::from_script(&spk, network)
            .map_err(|_| Error::NotAddressable(spk))?
            .into())
    }

    /// script(Script|Bytes) -> Script
    pub fn script(args: Array, _: &Scope) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Script(script) => script.into(),
            Value::Bytes(bytes) => ScriptBuf::from(bytes).into(),
            other => bail!(Error::InvalidScriptConstructor(other)),
        })
    }

    /// scriptPubKey(Descriptor|TapInfo|PubKey|Address|Script) -> Script
    ///
    /// Descriptors are compiled into their scriptPubKey
    /// TapInfo are returned as their V1 witness program
    /// PubKeys are converted into a wpkh() scripts
    /// Scripts are returned as-is
    pub fn scriptPubKey(args: Array, _: &Scope) -> Result<Value> {
        let spk = args.arg_into::<Value>()?.into_spk()?;
        Ok(spk.into())
    }

    /// le64(Number) -> Bytes
    /// Encode 64-bit signed integers as little-endian bytes
    /// Matches the format used by Elements Script
    pub fn le64(args: Array, _: &Scope) -> Result<Value> {
        let num: i64 = args.arg_into()?;
        Ok(num.to_le_bytes().to_vec().into())
    }

    #[allow(non_snake_case)]
    /// SHA256(Bytes preimage) -> Bytes hash
    /// Hash some data with SHA256
    /// Named in upper-case to avoid a conflict with the Miniscript sha256(Bytes) policy function
    /// (Yes, this is awfully confusing and requires a better solution. :<)
    pub fn SHA256(args: Array, _: &Scope) -> Result<Value> {
        let bytes: Vec<u8> = args.arg_into()?;
        let hash = sha256::Hash::hash(&bytes);
        Ok(hash.into())
    }
}
