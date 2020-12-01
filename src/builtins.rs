use std::convert::TryInto;

use miniscript::bitcoin::Network;

use crate::function::{Function, NativeFunction};
use crate::runtime::Value;
use crate::time::{duration_to_seq, parse_datetime};
use crate::util::get_descriptor_ctx;
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
    attach("sh", fns::sh);

    // Minsc policy functions
    attach("prob", fns::prob);
    attach("likely", fns::likely);
    attach("all", fns::all);
    attach("any", fns::any);

    // Compile policy to miniscript
    attach("miniscript", fns::miniscript);
    // Address generation
    attach("address", fns::address);

    // Network types
    scope.set("testnet", Network::Testnet.into()).unwrap();
    scope.set("regtest", Network::Regtest.into()).unwrap();
    scope
        .set(
            "_$$_RECKLESSLY_RISK_MY_BITCOINS_$$_",
            Network::Bitcoin.into(),
        )
        .unwrap();
}

pub mod fns {
    use super::*;
    use crate::Error;
    const LIKELY_PROB: usize = 10;

    pub fn or(args: Vec<Value>) -> Result<Value> {
        let policies_with_probs = args
            .into_iter()
            .map(|arg| match arg {
                Value::WithProb(usize, policy) => Ok((usize, policy)),
                arg => Ok((1, arg.into_policy()?)),
            })
            .collect::<Result<_>>()?;
        Ok(Policy::Or(policies_with_probs).into())
    }

    pub fn and(args: Vec<Value>) -> Result<Value> {
        let policies = map_policy(args)?;
        Ok(Policy::And(policies).into())
    }

    pub fn thresh(mut args: Vec<Value>) -> Result<Value> {
        let thresh_n = args.remove(0).into_usize()?;
        // Support thresh(n, $array) as well as thresh(n, pol1, pol2, ...) invocations
        let policies = if args.len() == 1 && args[0].is_array() {
            map_policy_array(args.remove(0))?
        } else {
            map_policy(args)?
        };
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
        Ok(Policy::Key(args.remove(0).into_key()?).into())
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
        Ok(args.remove(0).into_miniscript()?.into())
    }

    // Key -> Descriptor::Wpkh
    pub fn wpkh(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Descriptor::Wpkh(args.remove(0).into_key()?).into())
    }

    // Policy or Miniscript -> Descriptor::Wsh
    pub fn wsh(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Descriptor::Wsh(args.remove(0).into_miniscript()?).into())
    }

    // Descriptor::W{sh,pkh} -> Descriptor::ShW{sh,pkh}
    pub fn sh(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(match args.remove(0) {
            Value::Descriptor(desc) => match desc {
                Descriptor::Wsh(miniscript) => Descriptor::ShWsh(miniscript),
                Descriptor::Wpkh(key) => Descriptor::ShWpkh(key),
                _ => bail!(Error::InvalidShUse),
            },
            _ => bail!(Error::InvalidShUse),
        }
        .into())
    }

    // Descriptor, Policy, Miniscript, or Key -> Address
    pub fn address(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1 || args.len() == 2, Error::InvalidArguments);
        let descriptor = args.remove(0).into_desc()?;
        let network = args.pop().map_or(Ok(Network::Testnet), TryInto::try_into)?;
        let address = descriptor
            .address(network, get_descriptor_ctx(0))
            .expect("non-addressable descriptors cannot be constructed");
        Ok(address.into())
        // XXX support ctx child_code? already possible by deriving the descriptor, but using the ctx is cheaper
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
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Value::WithProb(LIKELY_PROB, args.remove(0).into_policy()?))
    }

    pub fn all(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let policies = map_policy_array(args.remove(0))?;
        Ok(Policy::Threshold(policies.len(), policies).into())
    }

    pub fn any(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let policies = map_policy_array(args.remove(0))?;
        Ok(Policy::Threshold(1, policies).into())
    }
}

fn map_policy(args: Vec<Value>) -> Result<Vec<Policy>> {
    args.into_iter().map(Value::into_policy).collect()
}

fn map_policy_array(array: Value) -> Result<Vec<Policy>> {
    map_policy(array.into_array_elements()?)
}
