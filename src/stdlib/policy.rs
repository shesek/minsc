use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

use miniscript::{DescriptorPublicKey, ForEachKey, Threshold};

use crate::runtime::{Array, Error, Evaluate, FieldAccess, Mutable, Result, ScopeRef, Value};
use crate::util::{DeriveExt, DescriptorSecretKeyExt};
use crate::{ast, PolicyDpk as Policy};

pub use crate::runtime::AndOr;

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();

    // Miniscript Policy functions
    scope.set_fn("or", fns::or).unwrap();
    scope.set_fn("and", fns::and).unwrap();
    scope.set_fn("older", fns::older).unwrap();
    scope.set_fn("after", fns::after).unwrap();
    scope.set_fn("pk", fns::pk).unwrap();
    scope.set_fn("sha256", fns::sha256).unwrap();
    scope.set_fn("hash256", fns::hash256).unwrap();
    scope.set_fn("ripemd160", fns::ripemd160).unwrap();
    scope.set_fn("hash160", fns::hash160).unwrap();
    scope.set_fn("any", fns::or).unwrap(); // alias
    scope.set_fn("all", fns::and).unwrap(); // alias

    // thresh() is defined in miniscript.rs, supporting both policies and miniscripts

    // Expose TRIVIAL and UNSATISFIABLE policies
    scope.set("TRIVIAL", Policy::Trivial).unwrap();
    scope.set("UNSATISFIABLE", Policy::Unsatisfiable).unwrap();

    // likely probability alias, for e.g. `likely@pk(A) || pk(B)`
    scope.set("likely", 10i64).unwrap();
}

// Threshold between policies (thresh() must be used for miniscripts)
impl Evaluate for ast::Thresh {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let thresh_n = self.thresh.eval(scope)?.into_usize()?;
        let policies = into_policies(self.policies.eval(scope)?.into_vec()?)?;
        Ok(Policy::Thresh(Threshold::new(thresh_n, policies)?).into())
    }
}

// AND/OR for policies, with support for >2 policies using thresh()
pub fn multi_andor(andor: AndOr, mut policies: Vec<Value>) -> Result<Policy> {
    Ok(if policies.len() == 1 {
        // If just one policy was provided, return it as-is
        policies.remove(0).try_into()?
    } else if policies.len() == 2 {
        // Use Miniscript's and()/or() when there are exactly 2 policies (more are not supported)
        match andor {
            AndOr::And => Policy::And(into_policies(policies)?),
            AndOr::Or => Policy::Or(into_prob_policies(policies)?),
        }
    } else if !policies.is_empty() {
        // Otherwise, simulate it through thresh(). This works similarly, except for not supporting execution probabilities.
        let policies = into_policies(policies)?;
        Policy::Thresh(match andor {
            AndOr::And => Threshold::and_n(policies),
            AndOr::Or => Threshold::or_n(policies),
        })
    } else {
        bail!(Error::InvalidArguments)
    })
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;

    /// `or(Policy, Policy, ..) -> Policy`  
    /// `or(Array<Policy>) -> Policy`
    pub fn or(mut args: Array, _: &ScopeRef) -> Result<Value> {
        if args.len() == 1 && args[0].is_array() {
            args = args.remove(0).into_array()?;
        }
        Ok(multi_andor(AndOr::Or, args.into_inner())?.into())
    }

    /// `and(Policy, Policy, ..) -> Policy`  
    /// `and(Array<Policy>) -> Policy`
    pub fn and(mut args: Array, _: &ScopeRef) -> Result<Value> {
        if args.len() == 1 && args[0].is_array() {
            args = args.remove(0).into_array()?;
        }
        Ok(multi_andor(AndOr::And, args.into_inner())?.into())
    }

    pub fn older(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Policy::Older(args.arg_into()?).into())
    }
    pub fn after(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Policy::After(args.arg_into()?).into())
    }

    pub fn pk(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Policy::Key(args.arg_into()?).into())
    }

    macro_rules! impl_policy_hash_fn {
        ($hash_name:ident, $policy_variant:path) => {
            pub fn $hash_name(args: Array, _: &ScopeRef) -> Result<Value> {
                let hash = args.arg_into().map_err(|e| {
                    // A specialized error for possible misuse of policy functions to hash data (e.g. sha256() instead of hash::sha256())
                    Error::InvalidMiniscriptPolicyHash(stringify!($hash_name), e.into())
                })?;
                Ok($policy_variant(hash).into())
            }
        };
    }

    impl_policy_hash_fn!(sha256, Policy::Sha256);
    impl_policy_hash_fn!(hash256, Policy::Hash256);
    impl_policy_hash_fn!(ripemd160, Policy::Ripemd160);
    impl_policy_hash_fn!(hash160, Policy::Hash160);
}

impl FieldAccess for Policy {
    fn get_field(self, field: &Value) -> Option<Value> {
        Some(match field.as_str()? {
            "keys" => self.keys().into_iter().cloned().collect(),
            "is_valid" => self.is_valid().is_ok().into(),
            "is_safe" => self.is_safe_nonmalleable().0.into(),
            "is_nonmalleable" => self.is_safe_nonmalleable().1.into(),
            "is_wildcard" => self.has_wildcards().into(),
            "is_multipath" => policy_is_multipath(&self).into(),
            "is_definite" => (!self.has_wildcards() && !policy_is_multipath(&self)).into(),
            _ => return None,
        })
    }
}

fn policy_is_multipath(policy: &Policy) -> bool {
    policy.for_any_key(DescriptorPublicKey::is_multipath)
}

pub fn into_policies(values: Vec<Value>) -> Result<Vec<Arc<Policy>>> {
    values
        .into_iter()
        .map(|v| match v {
            Value::WithProb(_, _) => Err(Error::InvalidPolicyProb),
            _ => Ok(Arc::new(v.into_policy()?)),
        })
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

impl TryFrom<Value> for Policy {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Policy(policy) => Ok(policy),
            // PubKeys are coerced into a pk() policy
            Value::PubKey(pubkey) => Ok(Policy::Key(pubkey)),
            // SecKeys are coerced into a PubKey, then to a pk()
            Value::SecKey(seckey) => Ok(Policy::Key(seckey.to_public_()?)),
            v => Err(Error::NotPolicyLike(v.into())),
        }
    }
}

impl TryFrom<Value> for miniscript::RelLockTime {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Self::from_consensus(val.into_u32()?)?)
    }
}
impl TryFrom<Value> for miniscript::AbsLockTime {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Self::from_consensus(val.into_u32()?)?)
    }
}

impl Value {
    pub fn into_policy(self) -> Result<Policy> {
        self.try_into()
    }

    pub fn is_policy_coercible(&self) -> bool {
        matches!(self, Value::Policy(_) | Value::PubKey(_) | Value::SecKey(_))
    }
}
