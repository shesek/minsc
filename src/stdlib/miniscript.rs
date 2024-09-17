use std::convert::{TryFrom, TryInto};
use std::{fmt, sync::Arc};

use miniscript::{descriptor::ShInner, ScriptContext, Threshold};

use crate::runtime::scope::{Mutable, ScopeRef};
use crate::runtime::{Array, Error, Evaluate, ExprRepr, Result, Value};
use crate::util::{DescriptorExt, MiniscriptExt, EC};
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

    // Miniscript Descriptor functions
    scope.set_fn("wpkh", fns::wpkh).unwrap();
    scope.set_fn("wsh", fns::wsh).unwrap();
    scope.set_fn("sh", fns::sh).unwrap();
    // tr() is also available, defined in taproot.rs

    // Expose TRIVIAL and UNSATISFIABLE policies
    scope.set("TRIVIAL", Policy::Trivial).unwrap();
    scope.set("UNSATISFIABLE", Policy::Unsatisfiable).unwrap();

    // Other descriptor functions
    scope.set_fn("descriptor", fns::descriptor).unwrap();
    scope.set_fn("explicitScript", fns::explicitScript).unwrap();
    scope
        .set_fn("descriptor::singles", fns::descriptor_singles)
        .unwrap();

    // Policy to Script compilation
    scope.set_fn("tapscript", fns::tapscript).unwrap();
    scope.set_fn("segwitv0", fns::segwitv0).unwrap();
}

impl Evaluate for ast::Thresh {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let thresh_n = self.thresh.eval(&scope)?.into_usize()?;
        let policies = into_policies(self.policies.eval(&scope)?.into_vec()?)?;
        Ok(Policy::Thresh(Threshold::new(thresh_n, policies)?).into())
    }
}

// AND/OR for policies, with support for >2 policies using thresh()
pub fn multi_andor(andor: AndOr, policies: Vec<Value>) -> Result<Policy> {
    Ok(if policies.len() == 2 {
        // Use Miniscript's and()/or() when there are exactly 2 policies (more are not supported)
        match andor {
            AndOr::And => Policy::And(into_policies(policies)?),
            AndOr::Or => Policy::Or(into_prob_policies(policies)?),
        }
    } else {
        // Otherwise, simulate it through thresh(). This works similarly, except for not supporting execution probabilities.
        let policies = into_policies(policies)?;
        Policy::Thresh(match andor {
            AndOr::And => Threshold::and_n(policies),
            AndOr::Or => Threshold::or_n(policies),
        })
    })
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;

    //
    // Miniscript Policy functions
    //

    pub fn or(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Policy::Or(into_prob_policies(args.into_inner())?).into())
    }
    pub fn and(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Policy::And(into_policies(args.into_inner())?).into())
    }
    pub fn thresh(args: Array, _: &ScopeRef) -> Result<Value> {
        let args = args.check_varlen(2, usize::MAX)?;
        let is_array_call = args.len() == 2 && args[1].is_array();
        let mut args_iter = args.into_iter();
        let thresh_n: usize = args_iter.next_into()?;

        let policies = if is_array_call {
            // Called as thresh($n, $policies_array)
            into_policies(args_iter.next_into()?)?
        } else {
            // Called as thresh($n, $policy1, $policy2, ...)
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

    /// wsh(Policy|Miniscript) -> Descriptor::Wsh
    /// wsh(Script witnessScript) -> Script scriptPubKey
    pub fn wsh(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Policy(policy) => {
                let miniscript = policy.compile()?;
                Descriptor::new_wsh(miniscript)?.into()
            }
            Value::Script(script) => script.to_p2wsh().into(),
            _ => bail!(Error::InvalidArguments),
        })
    }

    /// sh(Descriptor::W{sh,pkh}) -> Descriptor::ShW{sh,pkh}
    pub fn sh(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Descriptor(desc) => match desc {
                Descriptor::Wsh(wsh) => Descriptor::new_sh_with_wsh(wsh),
                Descriptor::Wpkh(wpkh) => Descriptor::new_sh_with_wpkh(wpkh),
                _ => bail!(Error::InvalidShUse),
            },
            _ => bail!(Error::InvalidShUse),
        }
        .into())
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

    /// explicitScript(Descriptor) -> Script
    /// Get the Descriptor's underlying Script (before any hashing is done - AKA the witnessScript for Wsh,
    /// scriptPubKey for Wpkh, or the redeemScript for ShWpkh). Tr descriptors don't have an explicitScript.
    /// To get the scriptPubKey of descriptors, use scriptPubKey().
    pub fn explicitScript(args: Array, _: &ScopeRef) -> Result<Value> {
        let descriptor: Descriptor = args.arg_into()?;
        Ok(descriptor.to_explicit_script()?.into())
    }

    /// descriptor::singles(Descriptor<Multi>) -> Array<Descriptor<Single>>
    pub fn descriptor_singles(args: Array, _: &ScopeRef) -> Result<Value> {
        let desc: Descriptor = args.arg_into()?;
        let descs = desc.into_single_descriptors()?;
        Ok(Value::array(
            descs.into_iter().map(Value::Descriptor).collect(),
        ))
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

impl TryFrom<Value> for Policy {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Policy(policy) => Ok(policy),
            // PubKeys are coerced into a pk() policy
            Value::PubKey(pubkey) => Ok(Policy::Key(pubkey)),
            // SecKeys are coerced into a PubKey, then to a pk()
            Value::SecKey(seckey) => {
                let pubkey = seckey.to_public(&EC)?;
                Ok(Policy::Key(pubkey))
            }
            v => Err(Error::NotPolicyLike(v.into())),
        }
    }
}

impl TryFrom<Value> for Descriptor {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Descriptor(x) => Ok(x),
            // PubKeys are coerced into a wpkh() descriptor
            Value::PubKey(x) => Ok(Descriptor::new_wpkh(x)?),
            v => Err(Error::NotDescriptorLike(v.into())),
        }
    }
}
impl TryFrom<Value> for miniscript::Descriptor<miniscript::DefiniteDescriptorKey> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(Descriptor::try_from(value)?.at_derivation_index(0)?)
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
            // Descriptors with key-based paths only (Pkh, Wpkh, Sh-Wpkh and script-less Tr) are already round-trip-able
            // using their native rust-miniscript's Display as a Minsc expression (:# modifier to exclude checksum)
            Descriptor::Pkh(_) | Descriptor::Wpkh(_) => write!(f, "{:#}", self),
            Descriptor::Tr(tr) if tr.tap_tree().is_none() => write!(f, "{:#}", self),
            Descriptor::Sh(sh) if matches!(sh.as_inner(), ShInner::Wpkh(_)) => {
                write!(f, "{:#}", self)
            }

            // Descriptors with inner Miniscripts for script-based paths must be encoded as string.
            // (while the Policy syntax can be used as a Minsc expression, Miniscript's cannot.)
            _ => write!(f, "descriptor(\"{}\")", self),
        }
    }
}
