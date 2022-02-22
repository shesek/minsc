use ::miniscript::bitcoin::{Network, Script};

use crate::runtime::Value;
use crate::{Result, Scope};

pub mod miniscript;

/// Attach built-in functions and variables to the Minsc runtime environment
pub fn attach_stdlib(scope: &mut Scope) {
    self::miniscript::attach_stdlib(scope);

    scope.set_fn("rawscript", fns::rawscript).unwrap();

    // Network types
    scope.set("testnet", Network::Testnet).unwrap();
    scope.set("regtest", Network::Regtest).unwrap();
    scope
        .set("_$$_RECKLESSLY_RISK_MY_BITCOINS_$$_", Network::Bitcoin)
        .unwrap();
}

pub mod fns {
    use super::*;
    use crate::Error;

    pub fn rawscript(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let bytes = args.remove(0).into_bytes()?;
        Ok(Script::from(bytes).into())
    }
}
