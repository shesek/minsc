use std::convert::TryInto;

use ::miniscript::bitcoin::{Address, Network, Script};

use crate::runtime::{Execute, Value};
use crate::{ast, parse_lib, time, Result, Scope};

pub mod miniscript;

lazy_static! {
    static ref MINSC_STDLIB: ast::Library = parse_lib(include_str!("stdlib.minsc")).unwrap();
}

/// Attach built-in functions and variables to the Minsc runtime environment
pub fn attach_stdlib(scope: &mut Scope) {
    // Boolean types
    scope.set("true", true).unwrap();
    scope.set("false", false).unwrap();

    // Network types
    scope.set("testnet", Network::Testnet).unwrap();
    scope.set("regtest", Network::Regtest).unwrap();
    scope
        .set("_$$_RECKLESSLY_RISK_MY_BITCOINS_$$_", Network::Bitcoin)
        .unwrap();

    // Functions
    scope.set_fn("len", fns::len).unwrap();
    scope.set_fn("rawscript", fns::rawscript).unwrap();
    scope.set_fn("bytes", fns::bytes).unwrap();
    scope.set_fn("wsh", fns::wsh).unwrap();
    scope.set_fn("address", fns::address).unwrap();
    scope.set_fn("repeat", fns::repeat).unwrap();
    scope.set_fn("iif", fns::iif).unwrap();
    scope.set_fn("le64", fns::le64).unwrap();

    // Constants
    scope.set("BLOCK_INTERVAL", time::BLOCK_INTERVAL).unwrap();
    scope.set("MAX_NUMBER", i64::MAX).unwrap();
    scope.set("MIN_NUMBER", i64::MIN).unwrap();

    // Miniscript related functions
    self::miniscript::attach_stdlib(scope);

    // Standard library implemented in Minsc
    MINSC_STDLIB.exec(scope).unwrap();
}

pub mod fns {
    use super::*;
    use crate::function::Call;
    use crate::Error;

    // len(Array|Bytes) -> Number
    pub fn len(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(match args.remove(0) {
            Value::Array(elements) => elements.len(),
            Value::Bytes(bytes) => bytes.len(),
            _ => bail!(Error::InvalidArguments),
        }
        .into())
    }

    // rawscript(Bytes) -> Script
    pub fn rawscript(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let bytes = args.remove(0).into_bytes()?;
        Ok(Script::from(bytes).into())
    }

    // bytes(Script) -> Bytes
    pub fn bytes(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let bytes = args.remove(0).into_bytes()?;
        Ok(bytes.into())
    }

    // Can be used to wrap a Miniscript/Policy with a Wsh descriptor, or with raw scripts.
    // - wsh(Miniscript|Policy) -> Descriptor
    // - wsh(Script) -> Script
    pub fn wsh(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);

        let script_or_ms = args.remove(0);

        if let Value::Script(script) = script_or_ms {
            Ok(script.to_v0_p2wsh().into())
        } else if let Ok(ms) = script_or_ms.into_miniscript() {
            self::miniscript::fns::wsh_(ms)
        } else {
            Err(Error::InvalidArguments)
        }
    }

    /// Generate an address from the given script/miniscript
    /// address(Script|Descriptor|Miniscript|Policy) -> Address
    pub fn address(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1 || args.len() == 2, Error::InvalidArguments);

        let script_or_desc = args.remove(0);
        let network = args.pop().map_or(Ok(Network::Testnet), TryInto::try_into)?;

        if let Value::Script(script) = script_or_desc {
            Ok(Address::from_script(&script, network)
                .ok_or_else(|| Error::NotAddressable(script))?
                .into())
        } else if let Ok(desc) = script_or_desc.into_desc() {
            self::miniscript::fns::address_(&desc, network)
        } else {
            Err(Error::InvalidArguments)
        }
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

    pub fn iif(mut args: Vec<Value>, scope: &Scope) -> Result<Value> {
        ensure!(args.len() == 3, Error::InvalidArguments);
        let condition = args.remove(0).into_bool()?;
        let then_val = args.remove(0);
        let else_val = args.remove(0);
        let result = if condition { then_val } else { else_val };
        match result {
            // then_val/else_val may be provided as thunks to be lazily evaluated
            Value::Function(f) => f.call(vec![], scope),
            other => Ok(other),
        }
    }

    pub fn le64(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let num = args.remove(0).into_i64()?;
        Ok(num.to_le_bytes().to_vec().into())
    }
}
