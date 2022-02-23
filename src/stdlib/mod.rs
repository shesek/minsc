use ::miniscript::bitcoin::{Network, Script};

use crate::runtime::{Execute, Value};
use crate::{ast, parse_lib, Result, Scope};

pub mod miniscript;

lazy_static! {
    static ref MINSC_STDLIB: ast::Library = parse_lib(include_str!("stdlib.minsc")).unwrap();
}

/// Attach built-in functions and variables to the Minsc runtime environment
pub fn attach_stdlib(scope: &mut Scope) {
    self::miniscript::attach_stdlib(scope);

    scope.set_fn("len", fns::len).unwrap();
    scope.set_fn("rawscript", fns::rawscript).unwrap();
    scope.set_fn("repeat", fns::repeat).unwrap();
    scope.set_fn("add", fns::add).unwrap();
    scope.set_fn("sub", fns::sub).unwrap();

    // Network types
    scope.set("testnet", Network::Testnet).unwrap();
    scope.set("regtest", Network::Regtest).unwrap();
    scope
        .set("_$$_RECKLESSLY_RISK_MY_BITCOINS_$$_", Network::Bitcoin)
        .unwrap();

    // Standard library implemented in Minsc
    MINSC_STDLIB.exec(scope).unwrap();
}

pub mod fns {
    use super::*;
    use crate::function::Call;
    use crate::Error;

    pub fn len(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let array_els = args.remove(0).into_array_elements()?;
        Ok(array_els.len().into())
    }

    pub fn rawscript(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let bytes = args.remove(0).into_bytes()?;
        Ok(Script::from(bytes).into())
    }

    pub fn repeat(mut args: Vec<Value>, scope: &Scope) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidArguments);
        let num = args.remove(0).into_usize()?;
        let producer = args.remove(0);
        Ok(Value::array(
            (0..num)
                .map(|n| match &producer {
                    Value::Function(callback) => callback.call(vec![n.into()], scope),
                    other => Ok(other.clone()),
                })
                .collect::<Result<_>>()?,
        ))
    }

    pub fn add(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidArguments);
        let a = args.remove(0).into_i64()?;
        let b = args.remove(0).into_i64()?;
        // TODO checked_add
        Ok((a + b).into())
    }

    pub fn sub(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidArguments);
        let a = args.remove(0).into_i64()?;
        let b = args.remove(0).into_i64()?;
        // TODO checked_sub
        Ok((a - b).into())
    }
}
