use ::miniscript::bitcoin::hashes::{sha256, Hash};

use crate::runtime::{Array, Error, Execute, Number, Result, Scope, Value};
use crate::{parser, time, Ident};

pub mod btc;
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

    // Functions
    scope.set_fn("typeof", fns::r#typeof).unwrap();
    scope.set_fn("len", fns::len).unwrap();
    scope.set_fn("reduce", fns::reduce).unwrap();
    scope.set_fn("repeat", fns::repeat).unwrap();

    scope.set_fn("int", fns::int).unwrap();
    scope.set_fn("float", fns::float).unwrap();
    scope.set_fn("str", fns::r#str).unwrap();
    scope.set_fn("bytes", fns::bytes).unwrap();

    scope.set_fn("le64", fns::le64).unwrap();
    scope.set_fn("SHA256", fns::SHA256).unwrap();

    scope.set_fn("env", fns::env).unwrap();
    scope.set_fn("locals", fns::locals).unwrap();

    // Constants
    scope.set("BLOCK_INTERVAL", time::BLOCK_INTERVAL).unwrap();
    scope.set("MAX_NUMBER", i64::MAX).unwrap();
    scope.set("MIN_NUMBER", i64::MIN).unwrap();

    // Bitcoin related functions
    self::btc::attach_stdlib(scope);

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
        let num: f64 = args.arg_into()?;
        Ok(num.into())
    }

    pub fn r#str(args: Array, _: &Scope) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::String(string) => string,
            other => other.to_string(),
        }
        .into())
    }

    /// Convert the argument into Bytes
    /// Scripts are serialized, Strings are converted to Bytes, Bytes are returned as-is
    /// bytes(Script|Bytes|String) -> Bytes
    pub fn bytes(args: Array, _: &Scope) -> Result<Value> {
        let bytes: Vec<u8> = args.arg_into()?;
        Ok(bytes.into())
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

    /// Get variables from the local scope
    /// locals() -> Array<(String, Value)>
    pub fn locals(args: Array, scope: &Scope) -> Result<Value> {
        args.no_args()?;
        Ok(Array(scope.locals().into_iter().map(format_var).collect()).into())
    }

    /// Get the entire env from the local and parent scopes
    /// env() -> Array<(String, Value)>
    pub fn env(args: Array, scope: &Scope) -> Result<Value> {
        args.no_args()?;
        Ok(Array(scope.env().into_iter().map(format_var).collect()).into())
    }

    fn format_var((ident, val): (&Ident, &Value)) -> Value {
        vec![Value::String(ident.0.clone()), val.clone()].into()
    }
}
