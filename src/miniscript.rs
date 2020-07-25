use std::fmt;

use crate::error::Result;
use crate::function::{Function, NativeFunction};
use crate::runtime::{Array, Value};
use crate::scope::Scope;
use crate::time::{duration_to_seq, parse_datetime};

/// A simplified, crude description of the Miniscript policy language syntax
#[derive(Debug, Clone)]
pub enum Policy {
    Fragment(String, Vec<Policy>),
    TermWord(String),
    WithProb(usize, Box<Policy>),
}

impl Policy {
    pub fn word<T: ToString>(term: T) -> Self {
        Policy::TermWord(term.to_string())
    }

    fn frag<T: ToString>(name: T, args: Vec<Policy>) -> Self {
        Policy::Fragment(name.to_string(), args)
    }

    fn prob(prob: usize, policy: Policy) -> Self {
        Policy::WithProb(prob, policy.into())
    }

    fn is_word(&self) -> bool {
        match self {
            Policy::TermWord(..) => true,
            _ => false,
        }
    }

    fn is_frag(&self) -> bool {
        match self {
            Policy::Fragment(..) => true,
            _ => false,
        }
    }

    fn is_prob(&self) -> bool {
        match self {
            Policy::WithProb(..) => true,
            _ => false,
        }
    }

    fn is_int(&self) -> bool {
        match self {
            Policy::TermWord(word) => word.parse::<usize>().is_ok(),
            _ => false,
        }
    }

    pub fn as_top_level(self) -> Result<Policy> {
        ensure!(self.is_frag(), Error::InvalidTopLevel);
        Ok(self)
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Policy::Fragment(name, args) => {
                write!(f, "{}(", name)?;
                for (i, policy) in args.iter().enumerate() {
                    let comma = if i < args.len() - 1 { "," } else { "" };
                    write!(f, "{}{}", policy, comma)?;
                }
                write!(f, ")")
            }
            Policy::TermWord(term) => write!(f, "{}", term),
            Policy::WithProb(prob, policy) => write!(f, "{}@{}", prob, policy),
        }
    }
}

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
}

/// Miniscript Policy functions exposed in the Minsc runtime
pub mod fns {
    use super::*;

    const LIKELY_PROB: usize = 10;

    // Representation for functions natively available in the Miniscript Policy language

    pub fn or(args: Vec<Value>) -> Result<Value> {
        let policies = map_policy(args)?;
        ensure!(
            policies.len() == 2 && policies.iter().all(|a| a.is_frag() || a.is_prob()),
            Error::InvalidOrArguments
        );
        Ok(Policy::frag("or", policies).into())
    }

    pub fn and(args: Vec<Value>) -> Result<Value> {
        let policies = map_policy(args)?;
        ensure!(
            policies.len() == 2 && policies.iter().all(|a| a.is_frag()),
            Error::InvalidAndArguments
        );
        Ok(Policy::frag("and", policies).into())
    }

    pub fn thresh(mut args: Vec<Value>) -> Result<Value> {
        // Expand thresh(n, $array) invocations into thresh(n, $array.0, $array.1, ...)
        let args = map_policy(if args.len() == 2 && args[1].is_array() {
            let thresh_n = args.remove(0);
            let mut args = get_elements(args.remove(0));
            args.insert(0, thresh_n);
            args
        } else {
            args
        })?;
        ensure!(
            args.len() >= 2 && args[0].is_int() && args.iter().skip(1).all(|a| a.is_frag()),
            Error::InvalidThreshArguments
        );
        Ok(Policy::frag("thresh", args).into())
    }

    pub fn older(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidOlderArguments);
        let value = match args.remove(0) {
            Value::Duration(dur) => Policy::word(duration_to_seq(&dur.0)?),
            Value::Policy(policy) if policy.is_int() => policy,
            _ => bail!(Error::InvalidAfterArguments),
        };
        Ok(Policy::frag("older", vec![value]).into())
    }

    pub fn after(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidAfterArguments);
        let value = match args.remove(0) {
            Value::DateTime(datetime) => Policy::word(parse_datetime(&datetime.0)?),
            Value::Policy(policy) if policy.is_int() => policy,
            _ => bail!(Error::InvalidAfterArguments),
        };
        Ok(Policy::frag("after", vec![value]).into())
    }

    pub fn pk(args: Vec<Value>) -> Result<Value> {
        let args = map_policy(args)?;
        ensure!(
            args.len() == 1 && args[0].is_word(),
            Error::InvalidPkArguments
        );
        Ok(Policy::frag("pk", args).into())
    }

    fn hash_fn(name: &str, args: Vec<Value>) -> Result<Value> {
        let args = map_policy(args)?;
        ensure!(
            args.len() == 1 && args[0].is_word(),
            Error::InvalidHashArguments(name.into())
        );

        // Always compile as `hash_fn(H)` with a literl H, this is the only value supported by Miniscript policy
        Ok(Policy::frag(name, vec![Policy::word("H")]).into())
    }

    pub fn sha256(args: Vec<Value>) -> Result<Value> {
        hash_fn("sha256", args)
    }
    pub fn hash256(args: Vec<Value>) -> Result<Value> {
        hash_fn("hash256", args)
    }
    pub fn ripemd160(args: Vec<Value>) -> Result<Value> {
        hash_fn("ripemd160", args)
    }
    pub fn hash160(args: Vec<Value>) -> Result<Value> {
        hash_fn("hash160", args)
    }

    // Below are functions not natively available in Miniscript
    // TODO move this elsewhere

    // A 'virtual' function to create probabilistic expressions, `prob(A, B)` -> `A@B`
    pub fn prob(mut args: Vec<Value>) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidProbArguments);
        let prob_n = match args.remove(0) {
            // support the `likely@X` syntax as an alternative to the `likely(X)` function invocation
            Value::Function(Function::Native(f)) if f.body == fns::likely => LIKELY_PROB,
            v => v.into_usize()?,
        };
        let policy = args.remove(0).into_policy()?;
        ensure!(policy.is_frag(), Error::InvalidProbArguments);
        Ok(Policy::prob(prob_n, policy).into())
    }

    pub fn likely(mut args: Vec<Value>) -> Result<Value> {
        args.insert(0, Policy::word(LIKELY_PROB).into());
        prob(args)
    }

    pub fn all(mut args: Vec<Value>) -> Result<Value> {
        ensure!(
            args.len() == 1 && args[0].is_array(),
            Error::InvalidAllArguments
        );
        let mut args = get_elements(args.remove(0));
        let thresh_n = Policy::word(args.len());
        args.insert(0, thresh_n.into());
        thresh(args)
    }

    pub fn any(mut args: Vec<Value>) -> Result<Value> {
        ensure!(
            args.len() == 1 && args[0].is_array(),
            Error::InvalidAnyArguments
        );
        let mut args = get_elements(args.remove(0));
        let thresh_n = Policy::word(1);
        args.insert(0, thresh_n.into());
        thresh(args)
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

    #[error("Invalid top-level, expecting a policy fragment")]
    InvalidTopLevel,
}
