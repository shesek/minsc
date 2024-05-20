use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

use bitcoin::bip32::{DerivationPath, Xpub};
use bitcoin::key::TweakedPublicKey;
use bitcoin::{PublicKey, Sequence, XOnlyPublicKey};
use miniscript::descriptor::{self, DescriptorPublicKey, DescriptorXKey, SinglePub, SinglePubKey};
use miniscript::{bitcoin, AbsLockTime, ScriptContext};

use crate::runtime::scope::{Mutable, ScopeRef};
use crate::runtime::{Array, Error, Evaluate, Result, Value};
use crate::util::{DescriptorExt, MiniscriptExt};
use crate::{ast, DescriptorDpk as Descriptor, MiniscriptDpk as Miniscript, PolicyDpk as Policy};

pub use crate::runtime::AndOr;

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

    // Expose TRIVIAL (always true) and UNSATISFIABLE (always false) policies
    scope.set("TRIVIAL", Policy::Trivial).unwrap();
    scope.set("UNSATISFIABLE", Policy::Unsatisfiable).unwrap();

    // Descriptor utility functions
    scope.set_fn("pubkey", fns::pubkey).unwrap();
    scope
        .set_fn("singleDescriptors", fns::singleDescriptors)
        .unwrap();

    // Compile descriptor/policy to script
    scope.set_fn("explicitScript", fns::explicitScript).unwrap();
    scope.set_fn("tapscript", fns::tapscript).unwrap();
    scope.set_fn("segwitv0", fns::segwitv0).unwrap();
}

impl Evaluate for ast::Thresh {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let thresh_n = self.thresh.eval(&scope)?.into_usize()?;
        let policies = into_policies(self.policies.eval(&scope)?.into_vec()?)?;
        Ok(Policy::Threshold(thresh_n, policies).into())
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
        let thresh_n = match andor {
            AndOr::And => policies.len(),
            AndOr::Or => 1,
        };
        Policy::Threshold(thresh_n, into_policies(policies)?)
    })
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;
    use miniscript::DescriptorPublicKey;

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

        Ok(Policy::Threshold(thresh_n, policies).into())
    }

    pub fn older(args: Array, _: &ScopeRef) -> Result<Value> {
        let locktime = Sequence(args.arg_into()?);
        Ok(Policy::Older(locktime).into())
    }
    pub fn after(args: Array, _: &ScopeRef) -> Result<Value> {
        let locktime = AbsLockTime::from_consensus(args.arg_into()?);
        Ok(Policy::After(locktime).into())
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

    /// Descriptor::W{sh,pkh} -> Descriptor::ShW{sh,pkh}
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

    /// Descriptor -> Script witnessScript
    pub fn explicitScript(args: Array, _: &ScopeRef) -> Result<Value> {
        let descriptor: Descriptor = args.arg_into()?;
        Ok(descriptor.to_explicit_script()?.into())
    }

    /// Policy -> Script witnessScript
    pub fn tapscript(args: Array, _: &ScopeRef) -> Result<Value> {
        let policy: Policy = args.arg_into()?;
        let miniscript = policy.compile::<miniscript::Tap>()?;
        Ok(miniscript.derive_keys()?.encode().into())
    }

    /// Policy -> Script witnessScript
    pub fn segwitv0(args: Array, _: &ScopeRef) -> Result<Value> {
        let policy: Policy = args.arg_into()?;
        let miniscript = policy.compile::<miniscript::Segwitv0>()?;
        Ok(miniscript.derive_keys()?.encode().into())
    }

    /// Descriptor<Multi> -> Array<Descriptor<Single>>
    /// XXX rename descriptors() or singleDescriptors?
    pub fn singleDescriptors(args: Array, _: &ScopeRef) -> Result<Value> {
        let desc: Descriptor = args.arg_into()?;
        let descs = desc.into_single_descriptors()?;
        Ok(Value::array(
            descs.into_iter().map(Value::Descriptor).collect(),
        ))
    }

    /// Cast 32/33 long Bytes into a Single DescriptorPubKey
    /// PubKeys are returned as-is
    /// pubkey(Bytes|PubKey) -> PubKey
    pub fn pubkey(args: Array, _: &ScopeRef) -> Result<Value> {
        let pubkey: DescriptorPublicKey = args.arg_into()?;
        Ok(pubkey.into())
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

// Convert from Miniscript types to Value

impl From<XOnlyPublicKey> for Value {
    fn from(key: XOnlyPublicKey) -> Self {
        Value::PubKey(DescriptorPublicKey::Single(SinglePub {
            key: SinglePubKey::XOnly(key),
            origin: None,
        }))
    }
}
impl From<TweakedPublicKey> for Value {
    fn from(key: TweakedPublicKey) -> Self {
        key.to_inner().into()
    }
}
impl From<Xpub> for Value {
    fn from(xpub: Xpub) -> Self {
        Value::PubKey(DescriptorPublicKey::XPub(DescriptorXKey {
            xkey: xpub,
            derivation_path: DerivationPath::master(),
            wildcard: descriptor::Wildcard::Unhardened,
            origin: if xpub.depth > 0 {
                Some((xpub.parent_fingerprint, [xpub.child_number][..].into()))
            } else {
                None
            },
        }))
    }
}

// Convert from Value to Miniscript types
impl TryFrom<Value> for Policy {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Policy(policy) => Ok(policy),
            // Pubkeys are coerced into a pk() policy
            Value::PubKey(pubkey) => Ok(Policy::Key(pubkey)),
            v => Err(Error::NotPolicyLike(v.into())),
        }
    }
}
impl TryFrom<Value> for DescriptorPublicKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::PubKey(x) => Ok(x),
            // Bytes are coerced into a PubKey when they are 33 or 32 bytes long
            Value::Bytes(bytes) => {
                let key = match bytes.len() {
                    33 => SinglePubKey::FullKey(PublicKey::from_slice(&bytes)?),
                    32 => SinglePubKey::XOnly(XOnlyPublicKey::from_slice(&bytes)?),
                    // uncompressed keys are currently unsupported
                    len => bail!(Error::InvalidPubKeyLen(len)),
                };
                Ok(DescriptorPublicKey::Single(SinglePub { key, origin: None }))
            }
            v => Err(Error::NotPubKey(v.into())),
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
impl<Ctx: ScriptContext> TryFrom<Value> for Miniscript<Ctx> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(value.into_policy()?.compile()?)
    }
}

impl Value {
    pub fn into_policy(self) -> Result<Policy> {
        self.try_into()
    }
    pub fn into_key(self) -> Result<DescriptorPublicKey> {
        self.try_into()
    }
    pub fn into_desc(self) -> Result<Descriptor> {
        self.try_into()
    }
    pub fn into_miniscript<Ctx: ScriptContext>(self) -> Result<Miniscript<Ctx>> {
        self.try_into()
    }
}
