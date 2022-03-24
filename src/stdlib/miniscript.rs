use std::convert::TryInto;

use crate::runtime::Value;
use crate::util::DescriptorExt;
use crate::{DescriptorDpk as Descriptor, PolicyDpk as Policy, Result, Scope};

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
    scope.set_fn("hash256", fns::hash256).unwrap();
    scope.set_fn("ripemd160", fns::ripemd160).unwrap();
    scope.set_fn("hash160", fns::hash160).unwrap();

    // Descriptor functions
    scope.set_fn("wpkh", fns::wpkh).unwrap();
    scope.set_fn("wsh", fns::wsh).unwrap();
    scope.set_fn("sh", fns::sh).unwrap();

    // Minsc policy functions
    scope.set_fn("all", fns::all).unwrap();
    scope.set_fn("any", fns::any).unwrap();

    // Compile descriptor/policy to script
    scope.set_fn("scriptPubkey", fns::scriptPubkey).unwrap();
    scope.set_fn("explicitScript", fns::explicitScript).unwrap();
    scope.set_fn("tapscript", fns::tapscript).unwrap();
    scope.set_fn("segwitv0", fns::segwitv0).unwrap();

    // `likely` as an alias for 10 (i.e. `likely@pk(A) || pk(B)`)
    scope.set("likely", LIKELY_PROB).unwrap();
}

#[allow(non_snake_case)]
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
                Value::WithProb(prob, value) => Ok((prob, value.into_policy()?)),
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
        let locktime = args.remove(0).into_u32()?;
        Ok(Policy::Older(locktime).into())
    }

    pub fn after(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let locktime = args.remove(0).into_u32()?;
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

    // Key -> Descriptor::Wpkh
    pub fn wpkh(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(Descriptor::new_wpkh(args.remove(0).into_key()?)?.into())
    }

    /// wsh(Policy|Miniscript) -> Descriptor::Wsh
    /// wsh(Script witnessScript) -> Script scriptPubKey
    pub fn wsh(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let script_or_policy = args.remove(0);

        Ok(if script_or_policy.is_policy() {
            let miniscript = script_or_policy.into_miniscript()?;
            Descriptor::new_wsh(miniscript)?.into()
        } else if script_or_policy.is_rawscript_like() {
            let script = script_or_policy.raw_script()?;
            script.to_v0_p2wsh().into()
        } else {
            bail!(Error::InvalidArguments);
        })
    }

    /// Descriptor::W{sh,pkh} -> Descriptor::ShW{sh,pkh}
    pub fn sh(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        Ok(match args.remove(0) {
            Value::Descriptor(desc) => match desc {
                Descriptor::Wsh(wsh) => Descriptor::new_sh_with_wsh(wsh),
                Descriptor::Wpkh(wpkh) => Descriptor::new_sh_with_wpkh(wpkh),
                _ => bail!(Error::InvalidShUse),
            },
            _ => bail!(Error::InvalidShUse),
        }
        .into())
    }

    /// Descriptor -> Script scriptPubKey
    pub fn scriptPubkey(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let script = args.remove(0).into_spk()?;
        Ok(script.into())
    }

    /// Descriptor -> Script witnessScript
    pub fn explicitScript(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(
            args.len() == 1 && args[0].is_desc(),
            Error::InvalidArguments
        );
        let descriptor = args.remove(0).into_desc()?;
        Ok(descriptor.to_explicit_script()?.into())
    }

    /// Policy -> Script witnessScript
    pub fn tapscript(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(
            args.len() == 1 && args[0].is_policy(),
            Error::InvalidArguments
        );
        let script = args.remove(0).into_script::<miniscript::Tap>()?;
        Ok(script.into())
    }

    /// Policy -> Script (witnessScript)
    pub fn segwitv0(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(
            args.len() == 1 && args[0].is_policy(),
            Error::InvalidArguments
        );
        let script = args.remove(0).into_script::<miniscript::Segwitv0>()?;
        Ok(script.into())
    }

    // Turn `[A,B,C]` array into an `A && B && C` policy
    pub fn all(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let policies = map_policy_array(args.remove(0))?;
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
    map_policy(array.into_array()?)
}
