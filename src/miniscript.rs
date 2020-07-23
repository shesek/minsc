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

fn attach_builtin(scope: &mut Scope, ident: &str, body: fn(Vec<Value>) -> Result<Value>) {
    let func = Function::from(NativeFunction { body });
    scope.set(ident, func.into()).unwrap();
}

pub fn attach_builtins(scope: &mut Scope) {
    attach_builtin(scope, "or", |args| {
        let policies = map_policy(args)?;
        ensure!(
            policies.len() == 2 && policies.iter().all(|a| a.is_frag() || a.is_prob()),
            Error::InvalidOrArguments
        );
        Ok(Policy::frag("or", policies).into())
    });

    attach_builtin(scope, "and", |args| {
        let policies = map_policy(args)?;
        ensure!(
            policies.len() == 2 && policies.iter().all(|a| a.is_frag()),
            Error::InvalidAndArguments
        );
        Ok(Policy::frag("and", policies).into())
    });

    attach_builtin(scope, "thresh", |mut args| {
        let args = map_policy(if args.len() == 2 && args[1].is_array() {
            // Expand thresh(n, $array) invocations into thresh(n, $array.0, $array.1, ...)
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
    });

    attach_builtin(scope, "prob", |args| {
        let mut args = flatten(args);
        ensure!(args.len() == 2, Error::InvalidProbArguments);
        let prob_n = match args.swap_remove(0) {
            Value::Policy(Policy::TermWord(w)) if w == "likely" => 10,
            v => v.into_usize()?,
        };
        let policy = args.swap_remove(0).into_policy()?;
        Ok(Policy::prob(prob_n, policy).into())
    });

    attach_builtin(scope, "older", |mut args| {
        ensure!(args.len() == 1, Error::InvalidOlderArguments);
        let value = match args.pop().unwrap() {
            Value::Duration(dur) => Policy::word(duration_to_seq(&dur.0)?),
            Value::Policy(policy) if policy.is_int() => policy,
            _ => bail!(Error::InvalidAfterArguments),
        };
        Ok(Policy::frag("older", vec![value]).into())
    });

    attach_builtin(scope, "after", |mut args| {
        ensure!(args.len() == 1, Error::InvalidAfterArguments);
        let value = match args.pop().unwrap() {
            Value::DateTime(datetime) => Policy::word(parse_datetime(&datetime.0)?),
            Value::Policy(policy) if policy.is_int() => policy,
            _ => bail!(Error::InvalidAfterArguments),
        };
        Ok(Policy::frag("after", vec![value]).into())
    });

    attach_builtin(scope, "pk", |args| {
        let args = map_policy(args)?;
        ensure!(
            args.len() == 1 && args[0].is_word(),
            Error::InvalidPkArguments
        );
        Ok(Policy::frag("pk", args).into())
    });

    attach_builtin(scope, "sha256", |args| hash_fn("sha256", args));
    attach_builtin(scope, "hash256", |args| hash_fn("hash256", args));
    attach_builtin(scope, "ripemd160", |args| hash_fn("ripemd160", args));
    attach_builtin(scope, "hash160", |args| hash_fn("hash160", args));
}

fn hash_fn(name: &str, args: Vec<Value>) -> Result<Value> {
    let args = map_policy(args)?;
    ensure!(
        args.len() == 1 && args[0].is_word(),
        Error::InvalidHashArguments(name.into())
    );

    // Always compile as `hash_fn(H)` with a literla H, this is the only value supported by Miniscript policy
    Ok(Policy::frag(name, vec![Policy::word("H")]).into())
}

// Map the values into policies
fn map_policy(args: Vec<Value>) -> Result<Vec<Policy>> {
    args.into_iter().map(Value::into_policy).collect()
}

// Extract elements from the known-to-be-an-array `val`
fn get_elements(val: Value) -> Vec<Value> {
    match val {
        Value::Array(Array(elements)) => elements,
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
}
