use std::convert::TryInto;

use miniscript::bitcoin::Network;

use crate::function::{Function, NativeFunction};
use crate::runtime::{Array, Value};
use crate::time::{duration_to_seq, parse_datetime};
use crate::{Descriptor, Policy, Result, Scope};

/// Attach built-in functions to the Minsc runtime envirnoment
pub fn attach_builtins(scope: &mut Scope) {
    let mut attach = |ident, body| {
        let func = Function::from(NativeFunction { body });
        scope.set(ident, func.into()).unwrap();
    };

    // Miniscript Policy functions exposed in the Minsc runtime
    attach("or", fns::or);
    attach("and", fns::and);
    attach("thresh", fns::thresh);
    attach("older", fns::older);
    attach("after", fns::after);
    attach("pk", fns::pk);
    attach("sha256", fns::sha256);
    attach("hash256", fns::hash256);
    attach("ripemd160", fns::ripemd160);
    attach("hash160", fns::hash160);

    // Descriptor functions
    attach("wsh", fns::wsh);
    attach("wpkh", fns::wpkh);
    attach("sh", fns::wsh);

    // Compile policy to miniscript
    attach("miniscript", fns::miniscript);
    // Address generation
    attach("address", fns::address);

    // Minsc functions
    attach("prob", fns::prob);
    attach("likely", fns::likely);
    attach("all", fns::all);
    attach("any", fns::any);
}

pub mod fns {
    use super::*;
    use crate::Error;
    const LIKELY_PROB: usize = 10;

    pub fn or(args: Vec<Value>) -> Result<Value> {
        let policies_with_probs = args
            .into_iter()
            .map(|p| match p {
                Value::WithProb(usize, policy) => Ok((usize, policy)),
                Value::Policy(policy) => Ok((1, policy)),
                _ => bail!(Error::InvalidArguments),
            })
            .collect::<Result<Vec<(usize, Policy)>>>()?;
        Ok(Policy::Or(policies_with_probs).into())
    }

    pub fn and(args: Vec<Value>) -> Result<Value> {
        let policies = map_policy(args)?;
        Ok(Policy::And(policies).into())
    }

    pub fn thresh(mut args: Vec<Value>) -> Result<Value> {
        let thresh_n = args.remove(0).into_usize()?;
        // Support thresh(n, $array) as well as thresh(n, pol1, pol2, ...) invocations
        let policies = map_policy(if args.len() == 1 && args[0].is_array() {
            get_elements(args.remove(0))
        } else {
            args
        })?;
        Ok(Policy::Threshold(thresh_n, policies).into())
    }

    pub fn older(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let locktime = match args.remove(0) {
            Value::Duration(dur) => duration_to_seq(&dur)?,
            Value::Number(num) => num as u32,
            _ => bail!(Error::InvalidArguments),
        };
        Ok(Policy::Older(locktime).into())
    }

    pub fn after(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let locktime = match args.remove(0) {
            Value::DateTime(datetime) => parse_datetime(&datetime)?,
            Value::Number(num) => num as u32,
            _ => bail!(Error::InvalidArguments),
        };
        Ok(Policy::After(locktime).into())
    }

    pub fn pk(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Policy::Key(args.remove(0).try_into()?).into())
    }

    pub fn sha256(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Policy::Sha256(args.remove(0).try_into()?).into())
    }
    pub fn hash256(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Policy::Hash256(args.remove(0).try_into()?).into())
    }

    pub fn ripemd160(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Policy::Ripemd160(args.remove(0).try_into()?).into())
    }
    pub fn hash160(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Policy::Hash160(args.remove(0).try_into()?).into())
    }

    // Policy -> Miniscript
    pub fn miniscript(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Value::Miniscript(args.remove(0).try_into()?))
    }

    // Policy or Miniscript -> Descriptor::Wpkh
    pub fn wpkh(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Descriptor::Wpkh(args.remove(0).try_into()?).into())
    }

    // Policy or Miniscript -> Descriptor::Wsh
    pub fn wsh(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Descriptor::Wsh(args.remove(0).try_into()?).into())
    }

    // Descriptor::Wsh or Descriptor::Wpkh -> Descriptor::Sh*
    pub fn sh(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(match args.remove(0).try_into()? {
            Descriptor::Wsh(miniscript) => Descriptor::ShWsh(miniscript),
            Descriptor::Wpkh(key) => Descriptor::ShWpkh(key),
            _ => bail!(Error::InvalidShUse),
        }
        .into())
    }

    pub fn address(args: Vec<Value>) -> Result<Value> {
        let mut args = args.into_iter();
        let descriptor = args.next().ok_or(Error::InvalidArguments)?.into_desc()?;
        let index = args.next().map_or(Ok(0), |arg| arg.into_usize())? as u32;
        ensure!(args.next().is_none(), Error::InvalidArguments);

        let descriptor = descriptor.derive(index.into());
        // TODO configurable network
        let address = descriptor.address(Network::Testnet).unwrap();
        Ok(address.into())
    }

    // `prob(A, B)` -> `A@B`
    pub fn prob(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidArguments);
        let prob_n = match args.remove(0) {
            #[allow(clippy::fn_address_comparisons)] // should be safe in this case
            // support the `likely@X` syntax as an alternative to the `likely(X)` function invocation
            Value::Function(Function::Native(f)) if f.body == fns::likely => LIKELY_PROB,
            v => v.into_usize()?,
        };
        let policy = args.remove(0).into_policy()?;
        Ok(Value::WithProb(prob_n, policy))
    }

    pub fn likely(mut args: Vec<Value>) -> Result<Value> {
        // XXX separate error
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Value::WithProb(LIKELY_PROB, args.remove(0).try_into()?))
    }

    pub fn all(mut args: Vec<Value>) -> Result<Value> {
        ensure!(
            args.len() == 1 && args[0].is_array(),
            Error::InvalidArguments
        );
        let policies = map_policy(get_elements(args.remove(0)))?;
        Ok(Policy::Threshold(policies.len(), policies).into())
    }

    pub fn any(mut args: Vec<Value>) -> Result<Value> {
        ensure!(
            args.len() == 1 && args[0].is_array(),
            Error::InvalidArguments
        );
        let policies = map_policy(get_elements(args.remove(0)))?;
        Ok(Policy::Threshold(1, policies).into())
    }
}

fn map_policy(args: Vec<Value>) -> Result<Vec<Policy>> {
    args.into_iter().map(Value::into_policy).collect()
}

fn get_elements(val: Value) -> Vec<Value> {
    match val {
        Value::Array(Array(elements)) => elements,
        // assumes that `val` is already known to be an array
        _ => unreachable!(),
    }
}
