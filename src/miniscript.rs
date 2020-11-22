use std::convert::TryInto;

use miniscript::{descriptor, policy};

use crate::error::Result;
use crate::function::{Function, NativeFunction};
use crate::runtime::{Array, Value};
use crate::scope::Scope;
use crate::time::{duration_to_seq, parse_datetime};

pub type Policy = policy::concrete::Policy<descriptor::DescriptorPublicKey>;

pub fn attach_builtins(scope: &mut Scope) {
    let mut attach = |ident, body| {
        let func = Function::from(NativeFunction { body });
        scope.set(ident, func.into()).unwrap();
    };

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

    attach("prob", fns::prob);
    attach("likely", fns::likely);
    attach("all", fns::all);
    attach("any", fns::any);

    /* FIXME attach("boo", |_| {
        Ok(Policy::frag(BOO, vec![Policy::word(BOO_A)]).into())
    });*/
}

/// Miniscript Policy functions exposed in the Minsc runtime
pub mod fns {
    use super::*;

    const LIKELY_PROB: usize = 10;

    // Representation for functions natively available in the Miniscript Policy language

    pub fn or(args: Vec<Value>) -> Result<Value> {
        let policies_with_probs = args
            .into_iter()
            .map(|p| match p {
                Value::WithProb(usize, policy) => Ok((usize, policy)),
                Value::Policy(policy) => Ok((1, policy)),
                _ => bail!(Error::InvalidOrArguments),
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
        ensure!(args.len() == 1, Error::InvalidOlderArguments);
        let locktime = match args.remove(0) {
            Value::Duration(dur) => duration_to_seq(&dur)?,
            Value::Number(num) => num as u32,
            _ => bail!(Error::InvalidOlderArguments),
        };
        Ok(Policy::Older(locktime).into())
    }

    pub fn after(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidAfterArguments);
        let locktime = match args.remove(0) {
            Value::DateTime(datetime) => parse_datetime(&datetime)?,
            Value::Number(num) => num as u32,
            _ => bail!(Error::InvalidAfterArguments),
        };
        Ok(Policy::After(locktime).into())
    }

    pub fn pk(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidPkArguments);
        Ok(Policy::Key(args.remove(0).try_into()?).into())
    }

    pub fn sha256(mut args: Vec<Value>) -> Result<Value> {
        ensure!(
            args.len() == 1,
            Error::InvalidHashArguments("sha256".into())
        );
        Ok(Policy::Sha256(args.remove(0).try_into()?).into())
    }
    pub fn hash256(mut args: Vec<Value>) -> Result<Value> {
        ensure!(
            args.len() == 1,
            Error::InvalidHashArguments("hash256".into())
        );
        Ok(Policy::Sha256(args.remove(0).try_into()?).into())
    }

    pub fn ripemd160(mut args: Vec<Value>) -> Result<Value> {
        ensure!(
            args.len() == 1,
            Error::InvalidHashArguments("ripemd160".into())
        );
        Ok(Policy::Sha256(args.remove(0).try_into()?).into())
    }
    pub fn hash160(mut args: Vec<Value>) -> Result<Value> {
        ensure!(
            args.len() == 1,
            Error::InvalidHashArguments("hash160".into())
        );
        Ok(Policy::Sha256(args.remove(0).try_into()?).into())
    }

    // Below are functions not natively available in Miniscript
    // TODO move this elsewhere

    // A 'virtual' function to create probabilistic expressions, `prob(A, B)` -> `A@B`
    pub fn prob(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidProbArguments);
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
        ensure!(args.len() == 1, Error::InvalidProbArguments);
        Ok(Value::WithProb(LIKELY_PROB, args.remove(0).try_into()?))
    }

    pub fn all(mut args: Vec<Value>) -> Result<Value> {
        ensure!(
            args.len() == 1 && args[0].is_array(),
            Error::InvalidAllArguments
        );
        let policies = map_policy(get_elements(args.remove(0)))?;
        Ok(Policy::Threshold(policies.len(), policies).into())
    }

    pub fn any(mut args: Vec<Value>) -> Result<Value> {
        ensure!(
            args.len() == 1 && args[0].is_array(),
            Error::InvalidAnyArguments
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

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid or() arguments, expected two policy fragments with optional probabilities")]
    InvalidOrArguments,

    #[error("Invalid and() arguments, expected two policy fragments without probabilities")]
    InvalidAndArguments,

    #[error("Invalid thresh() arguments, expected a threshold number and a variable number of policy fragments (without probabilities)")]
    InvalidThreshArguments,

    #[error("Invalid probability, expected a number and policy fragment")]
    InvalidProbArguments,

    #[error("Invalid older() arguments, expected 1 argument with a number or duration")]
    InvalidOlderArguments,

    #[error("Invalid after() arguments, expected 1 argument with a number or datetime")]
    InvalidAfterArguments,

    #[error("Invalid pk() arguments, expected a named identifier")]
    InvalidPkArguments,

    #[error("Invalid {0}() arguments, expected a named identifier")]
    InvalidHashArguments(String),

    #[error("Invalid all() arguments, expected an array")]
    InvalidAllArguments,

    #[error("Invalid any() arguments, expected an array")]
    InvalidAnyArguments,
}

const BOO: &str = r"          .     .
         (>\---/<)
         ,'     `.
        /  q   p  \
       (  >(_Y_)<  )
        >-' `-' `-<-.
       /  _.== ,=.,- \
      /,    )`  '(    )
     ; `._.'      `--<
    :     \        |  )
    \      )       ;_/
     `._ _/_  ___.'-\\\
        `--\\\
       ";
const BOO_A: &str = ")   Boo   (";
