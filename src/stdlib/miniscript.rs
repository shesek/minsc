use std::convert::TryInto;
use std::sync::Arc;

use miniscript::bitcoin::Sequence;
use miniscript::AbsLockTime;

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

    // Descriptor utilities
    scope
        .set_fn("single_descriptors", fns::single_descriptors)
        .unwrap();
    scope.set_fn("pubkey", fns::pubkey).unwrap();

    // Minsc policy functions
    scope.set_fn("all", fns::all).unwrap();
    scope.set_fn("any", fns::any).unwrap();

    // Compile descriptor/policy to script
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
        Ok(Policy::Or(into_prob_policies(args)?).into())
    }

    pub fn and(args: Vec<Value>, _: &Scope) -> Result<Value> {
        Ok(Policy::And(into_policies(args)?).into())
    }

    pub fn thresh(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        let thresh_n = args.remove(0).into_usize()?;
        // Support thresh(n, $array) as well as thresh(n, pol1, pol2, ...) invocations
        let policies = if args.len() == 1 && args[0].is_array() {
            into_policies(args.remove(0).into_array()?)?
        } else {
            into_policies(args)?
        };
        Ok(Policy::Threshold(thresh_n, policies).into())
    }

    pub fn older(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let locktime = args.remove(0).into_u32()?;
        Ok(Policy::Older(Sequence(locktime)).into())
    }

    pub fn after(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let locktime = args.remove(0).into_u32()?;
        Ok(Policy::After(AbsLockTime::from_consensus(locktime).into()).into())
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

        Ok(match args.remove(0) {
            Value::Policy(policy) => {
                let miniscript = policy.compile()?;
                Descriptor::new_wsh(miniscript)?.into()
            }
            Value::Script(script) => script.to_p2wsh().into(),
            _ => bail!(Error::InvalidArguments),
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

    /// Policy -> Script witnessScript
    pub fn segwitv0(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(
            args.len() == 1 && args[0].is_policy(),
            Error::InvalidArguments
        );
        let script = args.remove(0).into_script::<miniscript::Segwitv0>()?;
        Ok(script.into())
    }

    /// Descriptor<Multi> -> Array<Descriptor<Single>>
    pub fn single_descriptors(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let desc = args.remove(0).into_desc()?;
        let descs = desc.into_single_descriptors()?;
        Ok(Value::Array(
            descs.into_iter().map(Value::Descriptor).collect(),
        ))
    }

    /// Cast 32/33 long Bytes into a Single DescriptorPubKey
    /// PubKeys are returned as-is
    /// pubkey(Bytes|PubKey) -> PubKey
    pub fn pubkey(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let pubkey = args.remove(0).into_key()?;
        Ok(pubkey.into())
    }

    // Turn `[A,B,C]` array into an `A && B && C` policy
    pub fn all(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let policies = into_policies(args.remove(0).into_array()?)?;
        Ok(Policy::Threshold(policies.len(), policies).into())
    }

    // Turn `[A,B,C]` array into an `A || B || C` policy
    pub fn any(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let policies = into_policies(args.remove(0).into_array()?)?;
        Ok(Policy::Threshold(1, policies).into())
    }
}

pub fn into_policies(args: Vec<Value>) -> Result<Vec<Arc<Policy>>> {
    args.into_iter()
        .map(|v| Ok(Arc::new(Value::into_policy(v)?)))
        .collect()
}

fn into_prob_policies(values: Vec<Value>) -> Result<Vec<(usize, Arc<Policy>)>> {
    values
        .into_iter()
        .map(|arg| {
            Ok(match arg {
                Value::WithProb(prob, value) => (prob, Arc::new(value.into_policy()?)),
                arg => (1, Arc::new(arg.into_policy()?)),
            })
        })
        .collect()
}
