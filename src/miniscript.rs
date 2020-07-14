use std::fmt;

use crate::ast::Ident;
use crate::function::{Function, MiniscriptFunction};
use crate::scope::Scope;

/// A simplified, crude description of the Miniscript policy language syntax
#[derive(Debug, Clone)]
pub enum Policy {
    Fragment(String, Vec<Policy>),
    TermWord(String),
    WithProb(usize, Box<Policy>),
}

const BUILTINS: [&str; 10] = [
    "pk",
    "after",
    "older",
    "sha256",
    "hash256",
    "ripemd160",
    "hash160",
    "and",
    "or",
    "thresh",
];

pub fn attach_builtins(scope: &mut Scope) {
    for name in &BUILTINS {
        let ident: Ident = (*name).into();
        let func = Function::from(MiniscriptFunction {
            ident: ident.clone(),
        });
        scope.set(ident, func.into()).unwrap();
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
