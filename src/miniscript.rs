use std::fmt;

use crate::error::Result;
use crate::function::{Function, NativeFunction};
use crate::runtime::{Array, Value};
use crate::scope::Scope;

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
        let policies = map_policy(flatten(args))?;
        ensure!(
            policies.len() == 2 && policies.iter().all(|a| a.is_frag() || a.is_prob()),
            Error::InvalidOrArguments
        );
        Ok(Policy::frag("or", policies).into())
    });

    attach_builtin(scope, "and", |args| {
        let policies = map_policy(flatten(args))?;
        ensure!(
            policies.len() == 2 && policies.iter().all(|a| a.is_frag()),
            Error::InvalidAndArguments
        );
        Ok(Policy::frag("and", policies).into())
    });

    attach_builtin(scope, "thresh", |args| {
        let args = map_policy(flatten(args))?;
        ensure!(
            args.len() >= 2 && args[0].is_int() && args.iter().skip(1).all(|a| a.is_frag()),
            Error::InvalidThreshArguments
        );
        Ok(Policy::frag("thresh", args).into())
    });

    attach_builtin(scope, "prob", |args| {
        let mut args = flatten(args);
        ensure!(args.len() == 2, Error::InvalidProbArguments);
        let prob_n = args.swap_remove(0).into_usize()?;
        let policy = args.swap_remove(0).into_policy()?;
        Ok(Policy::prob(prob_n, policy).into())
    });

    // Functions accepting a single terminal word argument
    attach_builtin(scope, "pk", |args| word_fn("pk", args));
    attach_builtin(scope, "sha256", |args| word_fn("sha256", args));
    attach_builtin(scope, "hash256", |args| word_fn("hash256", args));
    attach_builtin(scope, "ripemd160", |args| word_fn("ripemd160", args));
    attach_builtin(scope, "hash160", |args| word_fn("hash160", args));
    attach_builtin(scope, "older", |args| word_fn("older", args));
    attach_builtin(scope, "after", |args| word_fn("after", args));
}

fn word_fn(name: &str, args: Vec<Value>) -> Result<Value> {
    let policies = map_policy(flatten(args))?;
    ensure!(
        policies.len() == 1 && policies[0].is_word(),
        Error::InvalidWordArgument(name.into())
    );
    Ok(Policy::frag(name, policies).into())
}

// Map the values into policies
fn map_policy(args: Vec<Value>) -> Result<Vec<Policy>> {
    args.into_iter().map(Value::into_policy).collect()
}

// Flatten the values to expand Array arguments into multiple arguments
fn flatten(values: Vec<Value>) -> Vec<Value> {
    values
        .into_iter()
        .flat_map(|val| match val {
            Value::Array(Array(elements)) => flatten(elements),
            val => vec![val],
        })
        .collect()
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

    #[error("Invalid {0}() arguments, expected a single terminal")]
    InvalidWordArgument(String),
}
