use ::miniscript::bitcoin::{Network, Script};

use crate::runtime::Value;
use crate::{Result, Scope};

pub mod miniscript;

/// Attach built-in functions and variables to the Minsc runtime environment
pub fn attach_stdlib(scope: &mut Scope) {
    self::miniscript::attach_stdlib(scope);

    // Network types
    scope.set("testnet", Network::Testnet).unwrap();
    scope.set("regtest", Network::Regtest).unwrap();
    scope
        .set("_$$_RECKLESSLY_RISK_MY_BITCOINS_$$_", Network::Bitcoin)
        .unwrap();
}