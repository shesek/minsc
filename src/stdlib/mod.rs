use std::convert::TryInto;

use crate::runtime::scope::{Mutable, ScopeRef};
use crate::runtime::{array, value, Array, Error, Execute, Result, Symbol, Value};
use crate::stdlib;
use crate::util::DescriptorSecretKeyExt;
use crate::Library;

#[cfg(feature = "bip39")]
pub mod bip39;
pub mod btc;
pub mod crypto;
pub mod ctv;
pub mod descriptors;
pub mod keys;
pub mod policy;
pub mod psbt;
pub mod script_marker;
#[cfg(feature = "scriptexec")]
pub mod scriptexec;
pub mod tagged;
pub mod taproot;

lazy_static! {
    static ref MINSC_STDLIB: Library = include_str!("stdlib.minsc").parse().unwrap();
    static ref ELEMENTS_STDLIB: Library = include_str!("elements.minsc").parse().unwrap();
}

/// Attach built-in functions and variables to the Minsc runtime environment
pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    {
        let mut scope = scope.borrow_mut();

        // Boolean types
        scope.set("true", true).unwrap();
        scope.set("false", false).unwrap();

        // Functions
        scope.set_fn("typeof", fns::r#typeof).unwrap();
        scope.set_fn("len", fns::len).unwrap();
        scope.set_fn("fold", fns::fold).unwrap();
        scope.set_fn("foldUntil", fns::foldUntil).unwrap();
        scope.set_fn("fillArray", fns::fillArray).unwrap();

        scope.set_fn("int", fns::int).unwrap();
        scope.set_fn("float", fns::float).unwrap();
        scope.set_fn("str", fns::r#str).unwrap();
        scope.set_fn("bytes", fns::bytes).unwrap();
        scope.set_fn("symbol", fns::symbol).unwrap();

        scope.set_fn("le64", fns::le64).unwrap();
        scope.set_fn("hex", fns::hex).unwrap();
        scope.set_fn("base64", fns::base64).unwrap();

        // Logging & Exceptions
        // These are the only functions in Minsc that produce side-effects.
        scope.set_fn("throw", fns::throw).unwrap();
        scope.set_fn("print", fns::print).unwrap();
        scope.set_fn("log", fns::log).unwrap();
        scope.set_fn("warn", fns::warn).unwrap();

        // Development utilities
        scope.set_fn("debug", fns::debug).unwrap();
        scope.set_fn("pretty", fns::pretty).unwrap();
        scope.set_fn("repr", fns::repr).unwrap();
        scope.set_fn("env", fns::env).unwrap();

        // Constants
        scope.set("MAX_INTEGER", i64::MAX).unwrap();
        scope.set("MIN_INTEGER", i64::MIN).unwrap();
        scope.set("MAX_FLOAT", f64::MAX).unwrap();
        scope.set("MIN_FLOAT", f64::MIN).unwrap();
        scope.set("inf", f64::INFINITY).unwrap();
        scope.set("NaN", f64::NAN).unwrap();

        // Built-in Symbols
        scope
            .set("MULTIVAL_TAG", array::SYM_MULTIVAL.clone())
            .unwrap();
    }

    // Standard library functions implemented in Minsc
    MINSC_STDLIB.exec(scope).unwrap();

    // Submodules
    self::crypto::attach_stdlib(scope);
    self::keys::attach_stdlib(scope);
    self::btc::attach_stdlib(scope); // requires the 'keys' stdlib
    self::descriptors::attach_stdlib(scope);
    self::policy::attach_stdlib(scope);
    self::psbt::attach_stdlib(scope);
    self::taproot::attach_stdlib(scope);
    self::ctv::attach_stdlib(scope); // requires the 'btc' stdlib
    ELEMENTS_STDLIB.exec(scope).unwrap(); // requires the 'btc' stdlib
    #[cfg(feature = "scriptexec")]
    self::scriptexec::attach_stdlib(scope);
    #[cfg(feature = "bip39")]
    self::bip39::attach_stdlib(scope);
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;
    use crate::runtime::{Call, Function};
    use crate::{ExprRepr, PrettyDisplay};

    /// Get the argument type as a string
    /// One of: pubkey, seckey, int, float, bool, bytes, string, policy, withprob, descriptor,
    /// address, script, transaction, function, network, tapinfo, wshinfo, psbt, array, symbol
    /// typeof(Value) -> String
    pub fn r#typeof(args: Array, _: &ScopeRef) -> Result<Value> {
        let type_of = args.arg_into::<Value>()?.type_of();
        Ok(type_of.into())
    }

    /// len(Array|Bytes|Script|String) -> Int
    pub fn len(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Array(array) => array.len(),
            Value::Bytes(bytes) => bytes.len(),
            Value::String(string) => string.len(),
            Value::Script(script) => script.into_bytes().len(),
            Value::Descriptor(desc) if desc.is_multipath() => desc.into_single_descriptors()?.len(),
            Value::PubKey(pk) if pk.is_multipath() => pk.full_derivation_paths().len(),
            Value::SecKey(sk) if sk.is_multipath() => sk.full_derivation_paths().len(),
            _ => bail!(Error::InvalidArguments),
        }
        .into())
    }

    /// fold(Array, Value, Function) -> Value
    /// Fold each element in the Array through the Function, starting with Value as the initial value
    pub fn fold(args: Array, scope: &ScopeRef) -> Result<Value> {
        let (array, init_val, callback): (Array, Value, Function) = args.args_into()?;

        let mut accumlator = init_val;
        for element in array {
            accumlator = callback.call(vec![accumlator, element], scope)?;
        }
        Ok(accumlator)
    }

    /// foldUntil(Array, Value, Function) -> Value
    /// Like fold(), with support for early termination. The callback can return a `false:$new_val` tuple
    /// to update the accumulated value and continue, or `true:$new_val` to return `$new_val` immediately.
    pub fn foldUntil(args: Array, scope: &ScopeRef) -> Result<Value> {
        let (array, init_val, callback): (Array, Value, Function) = args.args_into()?;

        let mut accumlator = init_val;
        for element in array {
            let callback_ret = callback.call(vec![accumlator, element], scope)?;
            let (found, new_val): (bool, _) = callback_ret.try_into()?;
            accumlator = new_val;
            if found {
                break;
            }
        }
        Ok(accumlator)
    }

    /// fillArray(Int, Value) -> Array
    /// Return an array of the specified size filled with copies of Value
    ///
    /// fillArray(Int, Function) -> Array
    /// Return an array of the specified size, using the callback function to produce values
    pub fn fillArray(args: Array, scope: &ScopeRef) -> Result<Value> {
        let (num, producer): (usize, Value) = args.args_into()?;
        Ok(match producer {
            Value::Function(callback) => Value::array(
                (0..num)
                    .map(|n| callback.call(vec![n.into()], scope))
                    .collect::<Result<_>>()?,
            ),
            other => vec![other; num].into(),
        })
    }

    pub fn int(args: Array, _: &ScopeRef) -> Result<Value> {
        let num = match args.arg_into()? {
            Value::Int(n) => n,
            Value::Float(f) => value::safe_f64_to_i64(f)?, // rounded down
            Value::String(str) => str.parse()?,
            Value::Bytes(bytes) => stdlib::btc::scriptnum_decode(&bytes)?,
            _ => bail!(Error::InvalidArguments),
        };
        Ok(num.into())
    }

    pub fn float(args: Array, _: &ScopeRef) -> Result<Value> {
        let num: f64 = match args.arg_into()? {
            Value::Float(f) => f,
            Value::Int(i) => value::safe_i64_to_f64(i)?,
            Value::String(s) => s.parse()?,
            _ => bail!(Error::InvalidArguments),
        };
        Ok(num.into())
    }

    /// str(Value) -> String
    ///
    /// Strings are returned as-is, other values are converted to a string representation that is mostly
    /// pretty (but single-line; see pretty() for multi-line) and mostly round-trip-able (see repr())
    pub fn r#str(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::String(string) => string, // no quoting/escaping
            other => other.to_string(),      // Display internally uses single-line PrettyDisplay
        }
        .into())
    }

    /// Create a new unique Symbol
    /// symbol(String=None) -> Symbol
    pub fn symbol(args: Array, _: &ScopeRef) -> Result<Value> {
        let name = args.arg_into()?;
        Ok(Symbol::new(name).into())
    }

    /// Convert the argument into Bytes
    /// bytes(Transaction|Psbt|Script|PubKey|SecKey|String|Bytes) -> Bytes
    pub fn bytes(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::Bytes(args.arg_into()?))
    }

    /// le64(Int) -> Bytes
    /// Encode 64-bit signed integers as little-endian bytes
    /// Matches the format used by Elements Script
    pub fn le64(args: Array, _: &ScopeRef) -> Result<Value> {
        let num: i64 = args.arg_into()?;
        Ok(num.to_le_bytes().to_vec().into())
    }

    /// debug(Value, Bool single_line=false) -> String
    /// Get the Debug representation of the Value (rust's std::fmt::Debug)
    pub fn debug(args: Array, _: &ScopeRef) -> Result<Value> {
        let (val, single_line): (Value, Option<bool>) = args.args_into()?;
        let debug_str = if single_line.unwrap_or(false) {
            format!("{:?}", val)
        } else {
            // Indent with 2 spaces instead of 4
            format!("{:#?}", val).replace("    ", "  ")
        };
        Ok(debug_str.into())
    }

    /// repr(Value) -> String
    ///
    /// Get the ExprRepr representation of the Value, which can be round-tripped
    /// as a Minsc expression to reproduce the original Value.
    pub fn repr(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args.arg_into::<Value>()?.repr_str().into())
    }

    /// pretty(Value) -> String
    ///
    /// Get a pretty multi-line string representation of the Value.
    /// Similar to str(), except for using multi-line and that strings are quoted/escaped.
    pub fn pretty(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args.arg_into::<Value>()?.multiline_str().into())
    }

    /// hex(Bytes|Transaction|Psbt|Script|PubKey|SecKey|String) -> String
    pub fn hex(args: Array, _: &ScopeRef) -> Result<Value> {
        use bitcoin::hex::DisplayHex;
        let bytes = args.arg_into::<Vec<u8>>()?;
        Ok(format!("{}", bytes.as_hex()).into())
    }

    /// base64(Bytes|Transaction|Psbt|Script|PubKey|SecKey|String) -> String
    pub fn base64(args: Array, _: &ScopeRef) -> Result<Value> {
        use base64::prelude::{Engine, BASE64_STANDARD};
        let bytes = args.arg_into::<Vec<u8>>()?;
        Ok(BASE64_STANDARD.encode(bytes).into())
    }

    /// Get env vars from the local and parent scopes
    /// env(max_depth=1) -> Array<(String, Value)>
    pub fn env(args: Array, scope: &ScopeRef) -> Result<Value> {
        // Set to -1 by default, which will return everything but the root scope
        let max_depth = args.arg_into::<Option<isize>>()?.unwrap_or(-1);
        let tagged_vars = scope
            .borrow()
            .env(max_depth)
            .into_iter()
            .map(|(ident, val)| vec![Value::String(ident.0), val].into())
            .collect();
        Ok(Array(tagged_vars).into())
    }

    /// Throw a custom runtime script execution error
    pub fn throw(args: Array, _: &ScopeRef) -> Result<Value> {
        let msg = stringify_args(args)?;
        Err(Error::ScriptException(msg))
    }

    /// Print to STDOUT or console.log
    pub fn print(args: Array, _: &ScopeRef) -> Result<Value> {
        let msg = stringify_args(args)?;

        #[cfg(target_arch = "wasm32")]
        crate::wasm::console_log(&msg);
        #[cfg(not(target_arch = "wasm32"))]
        println!("{}", msg);

        Ok(true.into())
    }

    /// [LOG] to STDOUT or console.log
    pub fn log(mut args: Array, scope: &ScopeRef) -> Result<Value> {
        // XXX this and warn() should be implemented in Minsc once it has support for variadic functions
        args.insert(0, "[LOG]".into());
        fns::print(args, scope)
    }

    /// [WARN] to STDERR or console.error
    pub fn warn(args: Array, _: &ScopeRef) -> Result<Value> {
        let msg = stringify_args(args)?;

        #[cfg(target_arch = "wasm32")]
        crate::wasm::console_error(&format!("[WARN] {}", msg));
        #[cfg(not(target_arch = "wasm32"))]
        eprintln!("[WARN] {}", msg);

        Ok(true.into())
    }

    fn stringify_args(args: Array) -> Result<String> {
        let args_iter = args.check_varlen(1, usize::MAX)?.into_iter();
        let strs = args_iter.map(|arg| match arg {
            Value::String(str) => str,
            other => other.to_string(),
        });
        Ok(strs.collect::<Vec<_>>().join(" "))
    }
}
