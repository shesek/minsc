use std::convert::{TryFrom, TryInto};
use std::fmt;

use miniscript::descriptor::{DescriptorType, ShInner, WshInner};
use miniscript::{ForEachKey, MiniscriptKey};

use crate::runtime::scope::{Mutable, ScopeRef};
use crate::runtime::{Array, ExprRepr, FieldAccess, PrettyDisplay, Result, Error, Value};
use crate::stdlib::{btc::WshInfo, taproot::tap_scripts_to_val};
use crate::util::{DescriptorExt, TapInfoExt};
use crate::{DescriptorDpk as Descriptor, PolicyDpk as Policy};

pub use crate::runtime::AndOr;

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();

    // Descriptor functions
    scope.set_fn("wpkh", fns::wpkh).unwrap();
    scope.set_fn("wsh", fns::wsh).unwrap();
    scope.set_fn("sh", fns::sh).unwrap();
    scope.set_fn("pkh", fns::pkh).unwrap();
    scope.set_fn("bare", fns::r#bare).unwrap();
    scope.set_fn("sortedmulti", fns::sortedmulti).unwrap();
    // tr() is available too, defined in taproot.rs
    // multi() constructs a Miniscript, defined in miniscript.rs

    // Explicit conversion from String (or existing Descriptor)
    scope.set_fn("descriptor", fns::descriptor).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;

    // wpkh(PubKey) -> Descriptor::Wpkh
    pub fn wpkh(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Descriptor::new_wpkh(args.arg_into()?)?.into())
    }

    /// `wsh(Policy) -> Descriptor`
    /// `wsh(Array<tagged:sortedmulti>) -> Descriptor` (see `sortedmulti()`)
    /// `wsh(Script witnessScript) -> WshInfo`
    pub fn wsh(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Policy(policy) => {
                Descriptor::new_wsh(verify_no_xonly(policy)?.compile()?)?.into()
            }
            Value::Array(arr) if arr.is_tagged_with("sortedmulti") => {
                let (_tag, thresh_k, pks): (String, _, _) = arr.try_into()?;
                Descriptor::new_wsh_sortedmulti(thresh_k, pks)?.into()
            }
            // miniscript::Descriptor::Wsh cannot represent raw (non-Miniscript) Script,
            // return a WshInfo representation instead.
            Value::Script(script) => WshInfo(script).into(),
            other => bail!(Error::InvalidValue(other.into())),
        })
    }

    /// sh(Descriptor::W{sh,pkh}) -> Descriptor::ShW{sh,pkh}
    /// sh(Policy|Array<tagged:sortedmulti>) -> Descriptor::Sh
    pub fn sh(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Descriptor(Descriptor::Wsh(wsh)) => Descriptor::new_sh_with_wsh(wsh),
            Value::Descriptor(Descriptor::Wpkh(wpkh)) => Descriptor::new_sh_with_wpkh(wpkh),
            Value::Policy(policy) => Descriptor::new_sh(verify_no_xonly(policy)?.compile()?)?,
            Value::Array(arr) if arr.is_tagged_with("sortedmulti") => {
                let (_tag, thresh_k, pks): (String, _, _) = arr.try_into()?;
                Descriptor::new_sh_sortedmulti(thresh_k, pks)?
            }
            // XXX Script in sh() is currently not supported (no WshInfo-like structure)
            other => bail!(Error::InvalidValue(other.into())),
        }
        .into())
    }

    /// pkh(PubKey) -> Descriptor::Pkh
    pub fn pkh(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Descriptor::new_pkh(args.arg_into()?)?.into())
    }

    /// bare(Policy) -> Descriptor::Bare
    pub fn r#bare(args: Array, _: &ScopeRef) -> Result<Value> {
        let policy = verify_no_xonly(args.arg_into()?)?;
        Ok(Descriptor::new_bare(policy.compile()?)?.into())
    }

    /// sortedmulti(Int thresh_k, ...PubKey) -> Array<tagged:sortedmulti>
    /// sortedmulti(Int thresh_k, Array<PubKey>) -> Array<tagged:sortedmulti>
    ///
    /// Can be used within wsh()/sh() only - sortedmulti() within tr()/bare is currently unsupported by rust-miniscript
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

    /// descriptor(String|Descriptor) -> Descriptor
    pub fn descriptor(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::Descriptor(match args.arg_into()? {
            Value::Descriptor(desc) => desc,
            Value::String(desc_str) => desc_str.parse()?,
            other => bail!(Error::InvalidValue(other.into())),
        }))
    }

    fn verify_no_xonly(policy: Policy) -> Result<Policy> {
        // Temporary workaround to avoid panicking. Can be removed once
        // https://github.com/rust-bitcoin/rust-miniscript/pull/761 is merged.
        ensure!(
            policy.for_each_key(|pk| !pk.is_x_only_key()),
            Error::InvalidPreTapXonly
        );
        Ok(policy)
    }
}

impl FieldAccess for Descriptor {
    fn get_field(self, field: &Value) -> Option<Value> {
        Some(match field.as_str()? {
            "descriptor_type" => self.desc_type().into(),
            "address_type" => self.address_type()?.into(), // not available for Bare
            "max_weight" => self.max_weight_to_satisfy().ok()?.into(),
            "singles" => self.into_single_descriptors().ok()?.into(),
            "is_safe" => self.sanity_check().is_ok().into(),
            "is_multipath" => self.is_multipath().into(),
            "is_wildcard" => self.has_wildcard().into(),
            "is_definite" => (!self.has_wildcard() && !self.is_multipath()).into(),

            // Only available for definite descriptors (non-multi-path and no underived wildcards)
            "script_pubkey" => self.to_script_pubkey().ok()?.into(),
            // Only available for definite non-taproot descriptors
            "explicit_script" => self.to_explicit_script().ok()?.into(),
            // Only available for definite segwit descriptors
            "witness_program" => self.witness_program().ok()??.into(),

            // Only available for taproot descriptors (similar fields mirrored on TaprootSpendInfo)
            "internal_key" => self.tr()?.internal_key().clone().into(),
            // Only available for definite taproot descriptors
            "output_key" => self.tap_info().ok()??.output_key().into(),
            "output_key_parity" => self.tap_info().ok()??.output_key_parity().into(),
            "scripts" => tap_scripts_to_val(&*self.tap_info().ok()??),
            // Only available for definite taproot descriptors with script paths
            "merkle_root" => self.tap_info().ok()??.merkle_root()?.into(),
            "script_tree" => self.tap_info().ok()??.script_tree()?.into(),
            _ => {
                return None;
            }
        })
    }
}

impl_simple_to_value!(DescriptorType, t, format!("{:?}", t));

impl_simple_into_variant!(Descriptor, Descriptor, into_descriptor, NotDescriptor);

impl TryFrom<Value> for miniscript::Descriptor<miniscript::DefiniteDescriptorKey> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Descriptor::try_from(value)?.definite()
    }
}

impl Value {
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

impl PrettyDisplay for Descriptor {
    const AUTOFMT_ENABLED: bool = false;
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        match self {
            Descriptor::Bare(_) => write!(f, "bare({:#})", self),
            _ => write!(f, "{:#}", self),
        }
    }
}
