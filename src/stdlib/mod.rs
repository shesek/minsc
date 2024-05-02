use std::convert::TryInto;

use ::miniscript::bitcoin::{self, Address, Network, ScriptBuf};
use bitcoin::hashes::{sha256, Hash};

use crate::runtime::{Error, Execute, Number, Result, Scope, Value};
use crate::{ast, parse_lib, time};

pub mod ctv;
pub mod miniscript;
pub mod tagged;
pub mod taproot;

lazy_static! {
    static ref MINSC_STDLIB: ast::Library = parse_lib(include_str!("stdlib.minsc")).unwrap();
    static ref ELEMENTS_STDLIB: ast::Library = parse_lib(include_str!("elements.minsc")).unwrap();
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
    scope.set_fn("len", fns::len).unwrap();
    scope.set_fn("typeof", fns::r#typeof).unwrap();
    scope.set_fn("int", fns::int).unwrap();
    scope.set_fn("float", fns::float).unwrap();
    scope.set_fn("bytes", fns::bytes).unwrap();
    scope.set_fn("rawscript", fns::rawscript).unwrap();
    scope.set_fn("address", fns::address).unwrap();
    scope.set_fn("scriptPubKey", fns::scriptPubKey).unwrap();
    scope.set_fn("repeat", fns::repeat).unwrap();
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
    use crate::function::Call;

    // len(Array|Bytes|Script|String) -> Number
    pub fn len(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(match args.remove(0) {
            Value::Array(elements) => elements.len(),
            Value::Bytes(bytes) => bytes.len(),
            Value::String(string) => string.len(),
            Value::Script(script) => script.into_bytes().len(),
            _ => bail!(Error::InvalidArguments),
        }
        .into())
    }

    /// Get the argument type as a string
    /// One of: pubkey, number, bool, bytes, policy, withprob, descriptor, address, script, function, network, tapinfo, array
    /// typeof(Value) -> String
    pub fn r#typeof(args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(args[0].type_of().to_string().into())
    }

    pub fn int(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);

        let num = match args.remove(0).into_number()? {
            Number::Int(n) => n,
            Number::Float(n) if n.is_finite() && n >= i64::MIN as f64 && n <= i64::MAX as f64 => {
                // non-whole floats are accepted and rounded down, unlike the implicit coercion in TryInto<i64>
                n as i64
            }
            Number::Float(_) => bail!(Error::Overflow),
        };

        Ok(num.into())
    }

    pub fn float(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(args.remove(0).into_f64()?.into())
    }

    // rawscript(Bytes) -> Script
    pub fn rawscript(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let bytes = args.remove(0).into_bytes()?;
        Ok(ScriptBuf::from(bytes).into())
    }

    /// Convert the argument into Bytes
    /// Scripts are serialized, Bytes are returned as-is
    /// bytes(Script|Bytes|String) -> Bytes
    pub fn bytes(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let bytes = args.remove(0).into_bytes()?;
        Ok(bytes.into())
    }

    /// Generate an address
    /// address(Script|Descriptor|Miniscript|Policy|PubKey) -> Address
    pub fn address(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1 || args.len() == 2, Error::InvalidArguments);

        let spk = args.remove(0).into_spk()?;
        let network = args.pop().map_or(Ok(Network::Signet), TryInto::try_into)?;

        Ok(Address::from_script(&spk, network)
            .map_err(|_| Error::NotAddressable(spk))?
            .into())
    }

    /// Descriptor|TapInfo|PubKey|Script -> Script
    ///
    /// TapInfo are returned as their V1 witness program
    /// PubKeys are converted into a wpkh() scripts
    /// Scripts are returned as-is
    pub fn scriptPubKey(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let script = args.remove(0).into_spk()?;
        Ok(script.into())
    }

    pub fn repeat(mut args: Vec<Value>, scope: &Scope) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidArguments);
        let num = args.remove(0).into_usize()?;
        let producer = args.remove(0);
        Ok(Value::Array(
            (0..num)
                .map(|n| match &producer {
                    Value::Function(callback) => callback.call(vec![n.into()], scope),
                    other => Ok(other.clone()),
                })
                .collect::<Result<_>>()?,
        ))
    }

    pub fn le64(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let num = args.remove(0).into_i64()?;
        Ok(num.to_le_bytes().to_vec().into())
    }

    #[allow(non_snake_case)]
    /// SHA256(Bytes preimage) -> Bytes hash
    /// Hash some data with SHA256
    /// Named in upper-case to avoid a conflict with the Miniscript sha256(Bytes) policy function
    /// (Yes, this is awfully confusing and requires a better solution. :<)
    pub fn SHA256(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let bytes = args.remove(0).into_bytes()?;
        let hash = sha256::Hash::hash(&bytes);
        Ok(hash.into())
    }
}
