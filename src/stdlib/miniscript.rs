use std::convert::{TryFrom, TryInto};
use std::{fmt, sync::Arc};

use miniscript::descriptor::{ShInner, WshInner};
use miniscript::{ScriptContext, Threshold};

use crate::runtime::scope::{Mutable, ScopeRef};
use crate::runtime::{Array, Error, Evaluate, ExprRepr, Result, Value};
use crate::stdlib::btc::WshScript;
use crate::util::{DescriptorExt, DescriptorSecretKeyExt, MiniscriptExt};
use crate::{ast, DescriptorDpk as Descriptor, MiniscriptDpk as Miniscript, PolicyDpk as Policy};

pub use crate::runtime::AndOr;

// While technically part of the miniscript crate, the functions and conversions for miniscript::Descriptor{Public,Secret}Key
// are implemented as part of keys.rs. They are used as the primary representation for keys in Minsc (its Value::{Pub,Sec}Key),
// even when not used for Miniscript-related stuff.

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();

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
    scope.set_fn("any", fns::or).unwrap(); // alias
    scope.set_fn("all", fns::and).unwrap(); // alias

    // Miniscript Descriptor functions
    scope.set_fn("wpkh", fns::wpkh).unwrap();
    scope.set_fn("wsh", fns::wsh).unwrap();
    scope.set_fn("sh", fns::sh).unwrap();
    scope.set_fn("sortedmulti", fns::sortedmulti).unwrap();
    // tr() is also available, defined in taproot.rs

    // Expose TRIVIAL and UNSATISFIABLE policies
    scope.set("TRIVIAL", Policy::Trivial).unwrap();
    scope.set("UNSATISFIABLE", Policy::Unsatisfiable).unwrap();

    // Policy to Script compilation
    scope.set_fn("tapscript", fns::tapscript).unwrap();
    scope.set_fn("segwitv0", fns::segwitv0).unwrap();

    // Other descriptor functions
    scope.set_fn("descriptor", fns::descriptor).unwrap();

    // multi() and thresh() are basically the same; a thresh() policy between keys compiles into Miniscript as multi()
    scope.set_fn("multi", fns::thresh).unwrap();

    // likely probability alias, for e.g. `likely@pk(A) || pk(B)`
    scope.set("likely", 10i64).unwrap();
}

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

    //
    // Miniscript Policy functions
    //

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

    /// `thresh(Int thresh_n, Policy, Policy, ..) -> Policy`  
    /// `thresh(Int thresh_n, Array<Policy>) -> Policy`
    pub fn thresh(args: Array, _: &ScopeRef) -> Result<Value> {
        let args = args.check_varlen(2, usize::MAX)?;
        let is_array_call = args.len() == 2 && args[1].is_array();
        let mut args_iter = args.into_iter();
        let thresh_n: usize = args_iter.next_into()?;

        let policies = if is_array_call {
            into_policies(args_iter.next_into()?)?
        } else {
            into_policies(args_iter.collect())?
        };

        Ok(Policy::Thresh(Threshold::new(thresh_n, policies)?).into())
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

    pub fn sha256(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Policy::Sha256(args.arg_into()?).into())
    }
    pub fn hash256(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Policy::Hash256(args.arg_into()?).into())
    }
    pub fn ripemd160(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Policy::Ripemd160(args.arg_into()?).into())
    }
    pub fn hash160(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Policy::Hash160(args.arg_into()?).into())
    }

    //
    // Miniscript Descriptor functions
    //

    // wpkh(PubKey) -> Descriptor::Wpkh
    pub fn wpkh(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Descriptor::new_wpkh(args.arg_into()?)?.into())
    }

    /// `wsh(Policy) -> Descriptor`
    /// `wsh(Array<tagged:sortedmulti>) -> Descriptor` (see `sortedmulti()`)
    /// `wsh(Script witnessScript) -> WshScript`
    pub fn wsh(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Policy(policy) => {
                let miniscript = policy.compile()?;
                Descriptor::new_wsh(miniscript)?.into()
            }
            Value::Array(arr) if arr.is_tagged_with("sortedmulti") => {
                let (_tag, thresh_k, pks): (String, _, _) = arr.try_into()?;
                Descriptor::new_wsh_sortedmulti(thresh_k, pks)?.into()
            }
            // miniscript::Descriptor::Wsh cannot represent raw (non-Miniscript) Script,
            // return a WshScript representation instead.
            Value::Script(script) => WshScript(script).into(),
            _ => bail!(Error::InvalidArguments),
        })
    }

    /// sh(Descriptor::W{sh,pkh}) -> Descriptor::ShW{sh,pkh}
    /// Can only be used to wrap over wsh()/wpkh(). Minsc does not support pre-segwit descriptors.
    pub fn sh(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Descriptor::Wsh(wsh) => Descriptor::new_sh_with_wsh(wsh),
            Descriptor::Wpkh(wpkh) => Descriptor::new_sh_with_wpkh(wpkh),
            _ => bail!(Error::InvalidShUse),
        }
        .into())
    }

    /// sortedmulti(Int thresh_k, ...PubKey) -> Array<tagged:sortedmulti>
    /// sortedmulti(Int thresh_k, Array<PubKey>) -> Array<tagged:sortedmulti>
    ///
    /// Can be used within wsh() only - sortedmulti() within tr() is currently unsupported by rust-miniscript
    /// and intentionally unsupported in sh() by minsc.
    pub fn sortedmulti(args: Array, _: &ScopeRef) -> Result<Value> {
        let mut args = args.check_varlen(2, usize::MAX)?;
        let thresh_k: usize = args.remove(0).try_into()?;
        let pks = if args.len() == 1 && args[0].is_array() {
            args.remove(0) // called as sortedmulti($n, $keys)
        } else {
            Value::Array(args) // called as sortedmulti($n, $key1, $key2, ...)
        };
        // Return a tagged array, later detected by wsh() to construct a SortedMultiVec. Uses an unusual representation because
        // sortedmulti() is not a quite descriptor nor a policy, and so cannot be represented directly as a first-class Minsc Value.
        Ok(("sortedmulti", thresh_k, pks).into())
    }

    //
    // Policy to Script compilation
    //

    /// tapscript(Policy) -> Script witnessScript
    pub fn tapscript(args: Array, _: &ScopeRef) -> Result<Value> {
        let policy: Policy = args.arg_into()?;
        let miniscript = policy.compile::<miniscript::Tap>()?;
        Ok(miniscript.derive_keys()?.encode().into())
    }

    /// segwitv0(Policy) -> Script witnessScript
    pub fn segwitv0(args: Array, _: &ScopeRef) -> Result<Value> {
        let policy: Policy = args.arg_into()?;
        let miniscript = policy.compile::<miniscript::Segwitv0>()?;
        Ok(miniscript.derive_keys()?.encode().into())
    }

    //
    // Descriptor utilities
    //

    /// descriptor(String|Descriptor) -> Descriptor
    pub fn descriptor(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::Descriptor(match args.arg_into()? {
            Value::String(desc_str) => desc_str.parse()?,
            other => other.try_into()?,
        }))
    }
}

fn into_policies(values: Vec<Value>) -> Result<Vec<Arc<Policy>>> {
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

// Convert from Value to Miniscript types

impl_simple_into_variant!(Descriptor, Descriptor, into_descriptor, NotDescriptor);

impl TryFrom<Value> for Policy {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Policy(policy) => Ok(policy),
            // PubKeys are coerced into a pk() policy
            Value::PubKey(pubkey) => Ok(Policy::Key(pubkey)),
            // SecKeys are coerced into a PubKey, then to a pk()
            Value::SecKey(seckey) => {
                let pubkey = seckey.to_public_()?;
                Ok(Policy::Key(pubkey))
            }
            v => Err(Error::NotPolicyLike(v.into())),
        }
    }
}

impl TryFrom<Value> for miniscript::Descriptor<miniscript::DefiniteDescriptorKey> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Descriptor::try_from(value)?.definite()
    }
}
impl<Ctx: ScriptContext> TryFrom<Value> for Miniscript<Ctx> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(value.into_policy()?.compile()?)
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

    pub fn is_descriptor(&self) -> bool {
        matches!(self, Value::Descriptor(_))
    }
}

impl ExprRepr for Descriptor {
    fn repr_fmt<W: fmt::Write>(&self, f: &mut W) -> fmt::Result {
        match self {
            // Descriptors with key-based paths only (Pkh, Wpkh, Sh-Wpkh, Wsh-SortedMulti and script-less Tr) are already
            // round-trip-able using their rust-miniscript's Display as a Minsc expression (:# modifier to exclude checksum)
            // (technically Sh-Wsh-SortedMulti and Sh-SortedMulti too, but they're uncommon so just stringify them.)
            Descriptor::Pkh(_) | Descriptor::Wpkh(_) => write!(f, "{:#}", self),
            Descriptor::Tr(tr) if tr.tap_tree().is_none() => write!(f, "{:#}", self),
            Descriptor::Sh(sh) if matches!(sh.as_inner(), ShInner::Wpkh(_)) => {
                write!(f, "{:#}", self)
            }
            Descriptor::Wsh(wsh) if matches!(wsh.as_inner(), WshInner::SortedMulti(_)) => {
                write!(f, "{:#}", self)
            }

            // Descriptors with inner Miniscripts for script-based paths must be encoded as string.
            // (while the Policy syntax can be used as a Minsc expression, Miniscript's cannot.)
            _ => write!(f, "descriptor(\"{}\")", self),
        }
    }
}
