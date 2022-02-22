use std::convert::TryInto;

use ::miniscript::bitcoin::{Address, Network};

use crate::runtime::Value;
use crate::time::{duration_to_seq, parse_datetime};
use crate::util::get_descriptor_ctx;
use crate::{Descriptor, Policy, Result, Scope};

const LIKELY_PROB: usize = 10;

pub fn attach_stdlib(scope: &mut Scope) {
    // Miniscript Policy functions exposed in the Minsc runtime
    scope.set_fn("or", fns::or).unwrap();
    scope.set_fn("and", fns::and).unwrap();
    scope.set_fn("thresh", fns::thresh).unwrap();
    scope.set_fn("older", fns::older).unwrap();
    scope.set_fn("after", fns::after).unwrap();
    scope.set_fn("pk", fns::pk).unwrap();
    scope.set_fn("sha256", fns::sha256).unwrap();
    scope.set_fn( "hash256", fns::hash256).unwrap();
    scope.set_fn("ripemd160", fns::ripemd160).unwrap();
    scope.set_fn("hash160", fns::hash160).unwrap();

    // Descriptor functions
    scope.set_fn("wsh", fns::wsh).unwrap();
    scope.set_fn("wpkh", fns::wpkh).unwrap();
    scope.set_fn("sh", fns::sh).unwrap();

    // Minsc policy functions
    scope.set_fn("all", fns::all).unwrap();
    scope.set_fn("any", fns::any).unwrap();
    scope.set_fn("prob", fns::prob).unwrap();

    // Compile policy to miniscript
    scope.set_fn("miniscript", fns::miniscript).unwrap();

    // Compile descriptor/miniscript to script
    scope.set_fn("script_pubkey", fns::script_pubkey).unwrap();
    scope.set_fn("script_witness", fns::script_witness).unwrap();

    // Address generation
    scope.set_fn("address", fns::address).unwrap();

    // `likely` as an alias for 10 (i.e. `likely@pk(A) || pk(B)`)
    scope.set("likely", LIKELY_PROB).unwrap();
}

pub mod fns {
    use super::*;
    use crate::Error;

    //
    // Miniscript Policy functions
    //

    pub fn or(args: Vec<Value>, _: &Scope) -> Result<Value> {
        let policies_with_probs = args
            .into_iter()
            .map(|arg| match arg {
                Value::WithProb(usize, policy) => Ok((usize, policy)),
                arg => Ok((1, arg.into_policy()?)),
            })
            .collect::<Result<_>>()?;
        Ok(Policy::Or(policies_with_probs).into())
    }

    pub fn and(args: Vec<Value>, _: &Scope) -> Result<Value> {
        let policies = map_policy(args)?;
        Ok(Policy::And(policies).into())
    }

    pub fn thresh(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        let thresh_n = args.remove(0).into_usize()?;
        // Support thresh(n, $array) as well as thresh(n, pol1, pol2, ...) invocations
        let policies = if args.len() == 1 && args[0].is_array() {
            map_policy_array(args.remove(0))?
        } else {
            map_policy(args)?
        };
        Ok(Policy::Threshold(thresh_n, policies).into())
    }

    pub fn older(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let locktime = match args.remove(0) {
            Value::Duration(dur) => duration_to_seq(&dur)?,
            Value::Number(num) => num as u32,
            _ => bail!(Error::InvalidArguments),
        };
        Ok(Policy::Older(locktime).into())
    }

    pub fn after(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let locktime = match args.remove(0) {
            Value::DateTime(datetime) => parse_datetime(&datetime)?,
            Value::Number(num) => num as u32,
            _ => bail!(Error::InvalidArguments),
        };
        Ok(Policy::After(locktime).into())
    }

    pub fn pk(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Policy::Key(args.remove(0).into_key()?).into())
    }

    pub fn sha256(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Policy::Sha256(args.remove(0).try_into()?).into())
    }
    pub fn hash256(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Policy::Hash256(args.remove(0).try_into()?).into())
    }

    pub fn ripemd160(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Policy::Ripemd160(args.remove(0).try_into()?).into())
    }
    pub fn hash160(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Policy::Hash160(args.remove(0).try_into()?).into())
    }

    // Policy -> Miniscript
    pub fn miniscript(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(args.remove(0).into_miniscript()?.into())
    }

    // Key -> Descriptor::Wpkh
    pub fn wpkh(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Descriptor::Wpkh(args.remove(0).into_key()?).into())
    }

    // Policy or Miniscript -> Descriptor::Wsh
    pub fn wsh(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Descriptor::Wsh(args.remove(0).into_miniscript()?).into())
    }

    // Descriptor::W{sh,pkh} -> Descriptor::ShW{sh,pkh}
    pub fn sh(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
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

    // Descriptor, Policy, Miniscript, or Key -> Pubkey Script
    pub fn script_pubkey(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let ctx = get_descriptor_ctx(0);
        let descriptor = args.remove(0).into_desc()?;
        Ok(descriptor.script_pubkey(ctx).into())
    }

    // Descriptor, Policy, Miniscript, or Key -> Witness Script
    pub fn script_witness(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let ctx = get_descriptor_ctx(0);
        let descriptor = args.remove(0).into_desc()?;
        Ok(descriptor.witness_script(ctx).into())
    }

    // Descriptor, Policy, Miniscript, Script or Key -> Address
    pub fn address(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1 || args.len() == 2, Error::InvalidArguments);
        let script = args.remove(0).into_script_pubkey()?;
        let network = args.pop().map_or(Ok(Network::Testnet), TryInto::try_into)?;
        let address = Address::from_script(&script, network)
            .expect("non-addressable descriptors cannot be constructed");
        Ok(address.into())
    }

    // `prob(A, B)` -> `A@B`
    pub fn prob(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidArguments);
        let prob_n = args.remove(0).into_usize()?;
        let policy = args.remove(0).into_policy()?;
        Ok(Value::WithProb(prob_n, policy))
    }

    // Turn `[A,B,C]` array into an `A && B && C` policy
    pub fn all(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        all_(args.remove(0))
    }

    pub fn all_(array: Value) -> Result<Value> {
        let policies = map_policy_array(array)?;
        Ok(Policy::Threshold(policies.len(), policies).into())
    }

    // Turn `[A,B,C]` array into an `A || B || C` policy
    pub fn any(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
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
