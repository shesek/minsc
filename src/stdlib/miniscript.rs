use std::convert::{TryFrom, TryInto};
use std::sync::Arc;
use std::{fmt, ops, result};

use miniscript::{
    Descriptor, DescriptorPublicKey, ForEachKey, ScriptContext, Terminal, Threshold, TranslatePk,
};

use crate::runtime::{Array, Error, FieldAccess, FromValue, Mutable, Result, ScopeRef, Value};
use crate::util::{FnTranslator, MiniscriptExt, PolicyExt};
use crate::{runtime, stdlib, ExprRepr, MiniscriptDpk as Miniscript, PolicyDpk as Policy};

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();

    scope.set_fn("miniscript", fns::miniscript).unwrap();
    scope
        .set_fn("miniscript::bare", fns::miniscript_bare)
        .unwrap();
    scope
        .set_fn("miniscript::legacy", fns::miniscript_legacy)
        .unwrap();
    scope
        .set_fn("miniscript::segwitv0", fns::miniscript_segwitv0)
        .unwrap();
    scope
        .set_fn("miniscript::tap", fns::miniscript_tap)
        .unwrap();
    scope.set_fn("segwitv0", fns::miniscript_segwitv0).unwrap(); // alias
    scope.set_fn("tap", fns::miniscript_tap).unwrap(); // alias

    scope
        .set_fn("miniscript::lift", fns::miniscript_lift)
        .unwrap();

    // Miniscript fragments

    // Some function names are shared for Miniscript and Policy/Descriptors,
    // initially constructing a different type that later coerces into a Miniscript:
    //
    // - pk(), older(), after(), sha256(), ripemd160(), hash256() and hash160()
    //   are defined in policy.rs and initially construct a Value::Policy
    // - pkh() is defined in descriptors.rs and initially construct a Value::Descriptor
    //
    // pk(k) == c:pk_k(k)
    // pkh(k) == c:pk_h(k)

    scope.set_fn("pk_k", fns::pk_k).unwrap();
    scope.set_fn("pk_h", fns::pk_h).unwrap();
    scope.set_fn("expr_raw_pkh", fns::expr_raw_pkh).unwrap();

    scope.set_fn("or_b", fns::or_b).unwrap();
    scope.set_fn("or_c", fns::or_c).unwrap();
    scope.set_fn("or_d", fns::or_d).unwrap();
    scope.set_fn("or_i", fns::or_i).unwrap();
    scope.set_fn("and_v", fns::and_v).unwrap();
    scope.set_fn("and_b", fns::and_b).unwrap();
    scope.set_fn("and_n", fns::and_n).unwrap();
    scope.set_fn("andor", fns::andor).unwrap();
    scope.set_fn("thresh", fns::thresh).unwrap(); // works with policies too
    scope.set_fn("multi", fns::multi).unwrap();
    scope.set_fn("multi_a", fns::multi_a).unwrap();

    // Wrappers
    scope.set("a", MiniscriptWrapper::Alt).unwrap();
    scope.set("s", MiniscriptWrapper::Swap).unwrap();
    scope.set("c", MiniscriptWrapper::Check).unwrap();
    scope.set("d", MiniscriptWrapper::DupIf).unwrap();
    scope.set("v", MiniscriptWrapper::Verify).unwrap();
    scope.set("j", MiniscriptWrapper::NonZero).unwrap();
    scope.set("n", MiniscriptWrapper::ZeroNotEqual).unwrap();
    scope.set("t", MiniscriptWrapper::T).unwrap();
    scope.set("u", MiniscriptWrapper::U).unwrap();
    scope.set("l", MiniscriptWrapper::L).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {

    use miniscript::policy::Liftable;

    use super::*;

    // Constructors/Converters

    /// `miniscript(Miniscript-coercible) -> Miniscript`
    pub fn miniscript(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args.arg_into::<AnyMiniscript>()?.into())
    }
    /// `miniscript::bare(RawMiniscript|Miniscript<Bare>) -> Miniscript<Bare>`
    pub fn miniscript_bare(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args.arg_into::<Miniscript<miniscript::BareCtx>>()?.into())
    }
    /// `miniscript::legacy(RawMiniscript|Miniscript<Legacy>) -> Miniscript<Legacy>`
    pub fn miniscript_legacy(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args.arg_into::<Miniscript<miniscript::Legacy>>()?.into())
    }
    /// `miniscript::segwitv0(RawMiniscript|Miniscript<Segwitv0>) -> Miniscript<Segwitv0>`
    pub fn miniscript_segwitv0(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args.arg_into::<Miniscript<miniscript::Segwitv0>>()?.into())
    }
    /// `miniscript::tap(RawMiniscript|Miniscript<Tap>) -> Miniscript<Tap>`
    pub fn miniscript_tap(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args.arg_into::<Miniscript<miniscript::Tap>>()?.into())
    }

    // Policy analysis

    /// `miniscript::lift(Miniscript<Ctx>) -> String`
    pub fn miniscript_lift(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            AnyMiniscript::Bare(cms) => cms.lift()?,
            AnyMiniscript::Legacy(cms) => cms.lift()?,
            AnyMiniscript::Segwitv0(cms) => cms.lift()?,
            AnyMiniscript::Tap(cms) => cms.lift()?,
            AnyMiniscript::Raw(rms) => bail!(Error::MiniscriptUnexpectedRaw(rms.into())),
        }
        .to_string()
        .into())
    }

    // Miniscript fragments

    /// `pk_k(PubKey) -> Miniscript<Raw>`
    pub fn pk_k(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(RawMiniscript::PkK(args.arg_into()?).into())
    }
    /// `pk_h(PubKey) -> Miniscript<Raw>`
    pub fn pk_h(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(RawMiniscript::PkH(args.arg_into()?).into())
    }
    /// `expr_raw_pkh(PubKey) -> Miniscript<Raw>`
    pub fn expr_raw_pkh(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(RawMiniscript::RawPkH(args.arg_into()?).into())
    }

    macro_rules! impl_miniscript_binary_fn {
        ($fn_name:ident) => {
            /// `f(Miniscript<C>, Miniscript<C>) -> Miniscript<C>`
            pub fn $fn_name(args: Array, _: &ScopeRef) -> Result<Value> {
                let (a, b) = args.args_into()?;
                Ok(AnyMiniscript::$fn_name(a, b)?.into())
            }
        };
    }
    impl_miniscript_binary_fn!(or_b);
    impl_miniscript_binary_fn!(or_c);
    impl_miniscript_binary_fn!(or_d);
    impl_miniscript_binary_fn!(or_i);
    impl_miniscript_binary_fn!(and_v);
    impl_miniscript_binary_fn!(and_b);
    impl_miniscript_binary_fn!(and_n); // and_n(a, b) == andor(a, b, 0)

    /// `andor(Miniscript<C>, Miniscript<C>, Miniscript<C>) -> Miniscript<C>`
    pub fn andor(args: Array, _: &ScopeRef) -> Result<Value> {
        let (a, b, c) = args.args_into()?;
        Ok(AnyMiniscript::andor(a, b, c)?.into())
    }

    /// `multi(Int, Array<PubKey>|...PubKey) -> Miniscript<Raw>`
    pub fn multi(args: Array, _: &ScopeRef) -> Result<Value> {
        let (thresh_k, pks) = _multi_args(args)?;
        Ok(AnyMiniscript::multi(thresh_k, pks)?.into())
    }

    /// `multi_a(Int, Array<PubKey>|...PubKey) -> Miniscript<Raw>`
    pub fn multi_a(args: Array, _: &ScopeRef) -> Result<Value> {
        let (thresh_k, pks) = _multi_args(args)?;
        Ok(AnyMiniscript::multi_a(thresh_k, pks)?.into())
    }

    /// `thresh(Int, Array<Policy>|...Policy) ->  Policy`
    /// `thresh(Int, Array<Miniscript<C>>|...Miniscript<C>) -> Miniscript<C>`
    pub fn thresh(args: Array, _: &ScopeRef) -> Result<Value> {
        let (thresh_k, elements) = _multi_args(args)?;
        // Check for the case of all-policy-coercibles first, to prioritize it over all-miniscript-coercibles.
        // For example, `thresh(1,pk($alice))` is ambiguous and could mean either a policy or a miniscript.
        // This is handled by first constructing a Policy::Thresh, then later converting it into a Miniscript
        // if it turns out to be used as one. See lookalike_policy_to_raw_miniscript().
        if elements.iter().all(Value::is_policy_coercible) {
            let policies = stdlib::policy::into_policies(elements)?;
            Ok(Policy::Thresh(Threshold::new(thresh_k, policies)?).into())
        } else {
            let miniscripts = elements
                .into_iter()
                .map(AnyMiniscript::try_from)
                .collect::<Result<_>>()?;
            Ok(AnyMiniscript::thresh(thresh_k, miniscripts)?.into())
        }
    }

    fn _multi_args<T: FromValue>(args: Array) -> Result<(usize, Vec<T>)> {
        let is_array_call = args.len() == 2 && args[1].is_array();
        let mut args_iter = args.check_varlen(2, usize::MAX)?.into_iter();
        let thresh_k: usize = args_iter.next_into()?;
        let elements = if is_array_call {
            args_iter.next_into()? // called as f(k, [ a, b, ... ])
        } else {
            args_iter.collect_into()? // called as f(k, a, b, ...)
        };
        Ok((thresh_k, elements))
    }
}

impl FieldAccess for AnyMiniscript {
    fn get_field(self, field: &Value) -> Option<Value> {
        Some(match field.as_str()? {
            // Only exists for Miniscripts with a known ScriptContext
            "context" => self.context()?.to_string().into(),
            "is_safe" => self.sanity_check()?.is_ok().into(),
            "analysis_error" => self.sanity_check()?.err()?.to_string().into(),
            // Exists for all Miniscripts, including Raw
            "keys" => self.keys().into(),
            "is_multipath" => self.is_multipath().into(),
            "is_wildcard" => self.has_wildcard().into(),
            "is_definite" => self.is_definite().into(),
            // TODO script_size, max_satisfaction_size, max_satisfaction_witness_elements
            _ => return None,
        })
    }
}

impl Value {
    pub fn is_miniscript_like(&self) -> bool {
        match self {
            Value::Miniscript(_) => true,
            Value::Array(arr) => arr.len() == 2 && arr[0].is_miniscript_wrapper(),
            // Any policy can (attempt to) compile into a Miniscript<Ctx>,
            // some policies (lookalikes) can also be translated into RawMiniscript
            Value::Policy(_) => true,
            // pkh() descriptors are coercible into a pkh() miniscript fragment (as RawMiniscript, alias for c:pk_h())
            Value::Descriptor(Descriptor::Pkh(_)) => true,

            // Int(0|1) are also convertible into AnyMiniscript, but intentionally not considered "miniscript-like"
            // for the purpose of overloaded call resolution. They are accepted where only a Miniscript is expected
            // (e.g. `and_v(v:1,0)`), but must be constructed explicitly for overloaded functions (e.g. `wsh(miniscript(1))`)

            // Script/String/PubKey/SecKey also not included, they can convert into a Miniscript<Ctx>
            // given a specific context but not into an AnyMiniscript/RawMiniscript.
            _ => false,
        }
    }

    pub fn is_wrapped_miniscript(&self) -> bool {
        matches!(self, Value::Array(arr) if arr.len() == 2 && arr[0].is_miniscript_wrapper())
    }

    pub fn is_miniscript_wrapper(&self) -> bool {
        matches!(self, Value::MiniscriptWrapper(_))
    }

    pub fn into_miniscript(self) -> Result<AnyMiniscript> {
        self.try_into()
    }

    pub fn into_miniscript_ctx<Ctx: ScriptContext>(self) -> Result<Miniscript<Ctx>>
    where
        Miniscript<Ctx>: TryFrom<Self, Error = Error>,
    {
        self.try_into()
    }
}

/// Wrapper over all Miniscript types with a known ScriptContext plus the
/// context-less RawMiniscript, with conversions between them
#[derive(Debug, Clone, PartialEq)]
pub enum AnyMiniscript {
    Raw(RawMiniscript),
    Bare(Miniscript<miniscript::BareCtx>),
    Legacy(Miniscript<miniscript::Legacy>),
    Segwitv0(Miniscript<miniscript::Segwitv0>),
    Tap(Miniscript<miniscript::Tap>),
}
impl_from_variant!(RawMiniscript, AnyMiniscript, Raw);

impl TryFrom<Value> for AnyMiniscript {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val {
            Value::Miniscript(ams) => ams,
            // Translate miniscript-lookalike policies - pk() older() after() sha256() ripemd160() hash256() hash160(),
            // or a thresh() between lookalikes
            Value::Policy(policy) => lookalike_policy_to_raw_miniscript(policy)?.into(),
            // Translate miniscript-lookalike pkh() descriptor (alias for c:pk_h())
            Value::Descriptor(Descriptor::Pkh(dpkh)) => {
                let pk = dpkh.into_inner();
                RawMiniscript::Check(RawMiniscript::PkH(pk).into()).into()
            }
            // Handle tuples of `Wrapper:Miniscript`
            Value::Array(arr) if arr.len() == 2 && arr[0].is_miniscript_wrapper() => {
                let (wrapper, ams): (MiniscriptWrapper, AnyMiniscript) = arr.try_into()?;
                wrapper.wrap(ams)?
            }
            Value::Int(1) => RawMiniscript::True.into(),
            Value::Int(0) => RawMiniscript::False.into(),
            other => bail!(Error::NotMiniscriptLike(other.into())),
        })
    }
}

fn lookalike_policy_to_raw_miniscript(policy: Policy) -> Result<RawMiniscript> {
    Ok(match policy {
        // pk() == c:pk_k()
        Policy::Key(pk) => RawMiniscript::Check(RawMiniscript::PkK(pk).into()),
        Policy::Older(duration) => RawMiniscript::Older(duration),
        Policy::After(time) => RawMiniscript::After(time),
        Policy::Sha256(hash) => RawMiniscript::Sha256(hash),
        Policy::Ripemd160(hash) => RawMiniscript::Ripemd160(hash),
        Policy::Hash256(hash) => RawMiniscript::Hash256(hash),
        Policy::Hash160(hash) => RawMiniscript::Hash160(hash),
        // Recurse to transform Thresh over miniscript-lookalike sub-policies,
        // only if all of the sub-policies are lookalikes
        Policy::Thresh(thresh) => RawMiniscript::Thresh(
            Threshold::new(
                thresh.k(),
                thresh
                    .into_iter()
                    .map(Arc::unwrap_or_clone)
                    .map(lookalike_policy_to_raw_miniscript)
                    .collect::<Result<_>>()?,
            )
            .expect("cannot fail with known k>0 and MAX==0"),
        ),
        p => bail!(Error::NotMiniscriptLike(Value::from(p).into())),
    })
}

// From inner miniscript types to Value::Miniscript
impl_simple_to_value!(RawMiniscript, rms, AnyMiniscript::Raw(rms));
#[rustfmt::skip]
impl_simple_to_value!(Miniscript<miniscript::BareCtx>, cms, AnyMiniscript::Bare(cms));
#[rustfmt::skip]
impl_simple_to_value!(Miniscript<miniscript::Legacy>, cms, AnyMiniscript::Legacy(cms));
#[rustfmt::skip]
impl_simple_to_value!(Miniscript<miniscript::Segwitv0>, cms, AnyMiniscript::Segwitv0(cms));
impl_simple_to_value!(Miniscript<miniscript::Tap>, cms, AnyMiniscript::Tap(cms));

// From Value to a specific Miniscript<Ctx>
impl<Ctx: ScriptContext> TryFrom<Value> for Miniscript<Ctx>
where
    Miniscript<Ctx>: TryFrom<AnyMiniscript, Error = Error>,
    Ctx::Key: Into<Value>,
{
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val {
            Value::Miniscript(ams) => ams.try_into()?,
            // XXX should lookalike policies be translated or compiled?
            Value::Policy(policy) => policy.compile_()?,
            _ if val.is_policy_coercible() => Policy::try_from(val)?.compile_()?,
            Value::Script(script) => from_script(&script)?,
            Value::String(s) => s.parse()?,
            Value::Array(arr) if arr.len() == 2 && arr[0].is_miniscript_wrapper() => {
                let (wrapper, cms): (MiniscriptWrapper, Miniscript<Ctx>) = arr.try_into()?;
                wrapper.wrap_ctx(cms)?
            }
            // Handle other Miniscript-coercibles by first converting into AnyMiniscript as Raw, then into Miniscript<Ctx>
            Value::Descriptor(Descriptor::Pkh(_)) | Value::Int(0 | 1) => {
                AnyMiniscript::try_from(val)?.try_into()?
            }
            other => bail!(Error::NotMiniscriptLike(other.into())),
        })
    }
}
fn from_script<Ctx: ScriptContext>(script: &bitcoin::Script) -> Result<Miniscript<Ctx>>
where
    Ctx::Key: Into<Value>,
{
    // Must be parsed into a Miniscript<Ctx::Key, Ctx> (plain PublicKey or XOnlyPublicKey) first,
    // then translated into a Miniscript<DescriptorPublicKey, Ctx>
    let plain_pks_ms = miniscript::Miniscript::<Ctx::Key, Ctx>::parse(script)?;
    Ok(plain_pks_ms.translate_pk(
        // Convert the Ctx::Key into a Value::PubKey, then extract the inner DescriptorPublicKey
        // Not the most efficient way to do this, but it works. :)
        &mut FnTranslator::new(|pk: &Ctx::Key| pk.clone().into().try_into()),
    )?)
}

#[derive(Debug, Clone, PartialEq)]
pub enum RawMiniscript {
    // Atoms
    True,
    False,
    PkK(DescriptorPublicKey),
    PkH(DescriptorPublicKey),
    RawPkH(bitcoin::hashes::hash160::Hash),
    After(miniscript::AbsLockTime),
    Older(miniscript::RelLockTime),
    Sha256(bitcoin::hashes::sha256::Hash),
    Hash256(miniscript::hash256::Hash),
    Ripemd160(bitcoin::hashes::ripemd160::Hash),
    Hash160(bitcoin::hashes::hash160::Hash),
    // Wrappers
    Alt(Box<RawMiniscript>),
    Swap(Box<RawMiniscript>),
    Check(Box<RawMiniscript>),
    DupIf(Box<RawMiniscript>),
    Verify(Box<RawMiniscript>),
    NonZero(Box<RawMiniscript>),
    ZeroNotEqual(Box<RawMiniscript>),
    // Conjunctions
    AndV(Box<RawMiniscript>, Box<RawMiniscript>),
    AndB(Box<RawMiniscript>, Box<RawMiniscript>),
    AndOr(Box<RawMiniscript>, Box<RawMiniscript>, Box<RawMiniscript>),
    // Disjunctions
    OrB(Box<RawMiniscript>, Box<RawMiniscript>),
    OrD(Box<RawMiniscript>, Box<RawMiniscript>),
    OrC(Box<RawMiniscript>, Box<RawMiniscript>),
    OrI(Box<RawMiniscript>, Box<RawMiniscript>),
    // Thresholds
    Thresh(Threshold<RawMiniscript, 0>),
    Multi(Threshold<DescriptorPublicKey, 0>),
    MultiA(Threshold<DescriptorPublicKey, 0>),
}

macro_rules! impl_anyminiscript_binary {
    ($fn_name:ident, $variant:ident) => {
        pub fn $fn_name(a: AnyMiniscript, b: AnyMiniscript) -> Result<AnyMiniscript> {
            use {AnyMiniscript::*, Miniscript as Ms, Terminal as Term};
            Ok(match (a, b) {
                (Raw(a), Raw(b)) => Raw(RawMiniscript::$variant(a.into(), b.into())),
                (Legacy(a), Legacy(b)) => Legacy(Ms::from_ast(Term::$variant(a.into(), b.into()))?),
                (Bare(a), Bare(b)) => Bare(Ms::from_ast(Term::$variant(a.into(), b.into()))?),
                (Tap(a), Tap(b)) => Tap(Ms::from_ast(Term::$variant(a.into(), b.into()))?),
                (Segwitv0(a), Segwitv0(b)) => {
                    Segwitv0(Ms::from_ast(Term::$variant(a.into(), b.into()))?)
                }
                // XXX can support mixed raw and known context
                (a, b) => bail!(Error::MiniscriptMixedBinaryCtx(a.into(), b.into())),
            })
        }
    };
}

impl AnyMiniscript {
    impl_anyminiscript_binary!(and_v, AndV);
    impl_anyminiscript_binary!(and_b, AndB);
    impl_anyminiscript_binary!(or_b, OrB);
    impl_anyminiscript_binary!(or_c, OrC);
    impl_anyminiscript_binary!(or_d, OrD);
    impl_anyminiscript_binary!(or_i, OrI);

    pub fn andor(a: AnyMiniscript, b: AnyMiniscript, c: AnyMiniscript) -> Result<AnyMiniscript> {
        use AnyMiniscript::*;
        Ok(match (a, b, c) {
            (Raw(a), Raw(b), Raw(c)) => Raw(RawMiniscript::AndOr(a.into(), b.into(), c.into())),
            (Bare(a), Bare(b), Bare(c)) => Bare(Self::_andor_ctx(a, b, c)?),
            (Legacy(a), Legacy(b), Legacy(c)) => Legacy(Self::_andor_ctx(a, b, c)?),
            (Segwitv0(a), Segwitv0(b), Segwitv0(c)) => Segwitv0(Self::_andor_ctx(a, b, c)?),
            (Tap(a), Tap(b), Tap(c)) => Tap(Self::_andor_ctx(a, b, c)?),
            // XXX can support mixed raw and known context
            (a, b, c) => bail!(Error::MiniscriptMixedTernaryCtx(
                a.into(),
                b.into(),
                c.into()
            )),
        })
    }
    fn _andor_ctx<Ctx: ScriptContext>(
        a: Miniscript<Ctx>,
        b: Miniscript<Ctx>,
        c: Miniscript<Ctx>,
    ) -> Result<Miniscript<Ctx>> {
        let term = Terminal::AndOr(Arc::new(a), Arc::new(b), Arc::new(c));
        Ok(Miniscript::from_ast(term)?)
    }

    /// and_n(a, b) == andor(a, b, 0)
    pub fn and_n(a: AnyMiniscript, b: AnyMiniscript) -> Result<AnyMiniscript> {
        let c = match a {
            AnyMiniscript::Raw(_) => AnyMiniscript::Raw(RawMiniscript::False),
            AnyMiniscript::Bare(_) => AnyMiniscript::Bare(Miniscript::FALSE),
            AnyMiniscript::Legacy(_) => AnyMiniscript::Legacy(Miniscript::FALSE),
            AnyMiniscript::Segwitv0(_) => AnyMiniscript::Segwitv0(Miniscript::FALSE),
            AnyMiniscript::Tap(_) => AnyMiniscript::Tap(Miniscript::FALSE),
        };
        AnyMiniscript::andor(a, b, c)
    }

    pub fn multi(k: usize, keys: Vec<DescriptorPublicKey>) -> Result<AnyMiniscript> {
        let thresh = Threshold::new(k, keys)?;
        Ok(AnyMiniscript::Raw(RawMiniscript::Multi(thresh)))
    }

    pub fn multi_a(k: usize, keys: Vec<DescriptorPublicKey>) -> Result<AnyMiniscript> {
        let thresh = Threshold::new(k, keys)?;
        Ok(AnyMiniscript::Raw(RawMiniscript::MultiA(thresh)))
    }

    pub fn thresh(k: usize, miniscripts: Vec<AnyMiniscript>) -> Result<AnyMiniscript> {
        // If any of the miniscripts has a known context, assume that context for
        // the whole Thresh and convert any RawMiniscript into the same context.
        // Incompatible miniscripts with different contexts will error.
        let first_ctx = miniscripts.iter().find_map(AnyMiniscript::context);

        Ok(match first_ctx {
            Some(CtxType::Segwitv0) => AnyMiniscript::Segwitv0(Self::_thresh_ctx(k, miniscripts)?),
            Some(CtxType::Tap) => AnyMiniscript::Tap(Self::_thresh_ctx(k, miniscripts)?),
            Some(CtxType::Legacy) => AnyMiniscript::Legacy(Self::_thresh_ctx(k, miniscripts)?),
            Some(CtxType::Bare) => AnyMiniscript::Bare(Self::_thresh_ctx(k, miniscripts)?),
            None => {
                // Otherwise, they are all RawMiniscripts
                let miniscripts_raw = miniscripts
                    .into_iter()
                    .map(RawMiniscript::try_from)
                    .collect::<Result<_>>()?;
                let thresh = Threshold::new(k, miniscripts_raw)?;
                AnyMiniscript::Raw(RawMiniscript::Thresh(thresh))
            }
        })
    }
    fn _thresh_ctx<Ctx: ScriptContext>(
        k: usize,
        miniscripts: Vec<AnyMiniscript>,
    ) -> Result<Miniscript<Ctx>>
    where
        Miniscript<Ctx>: TryFrom<AnyMiniscript, Error = Error>,
    {
        // Convert all AnyMiniscripts into the same Miniscript<Ctx>, or fail if they're incompatible
        let miniscripts_ctx: Vec<Arc<Miniscript<Ctx>>> = miniscripts
            .into_iter()
            .map(|ams| Ok(Arc::new(ams.try_into()?)))
            .collect::<Result<_>>()
            .map_err(|e| match e {
                Error::MiniscriptIncompatibleCtx(ctx, ams) => {
                    Error::MiniscriptMixedThreshCtx(ctx, ams)
                }
                e => e,
            })?;
        let thresh = Threshold::new(k, miniscripts_ctx)?;
        Ok(Miniscript::from_ast(Terminal::Thresh(thresh))?)
    }
}

// Convert from AnyMiniscript to a specific Miniscript<Ctx>, either by extracting
// the matching Ctx enum variant or converting RawMiniscript into the Ctx

impl TryFrom<AnyMiniscript> for Miniscript<miniscript::Segwitv0> {
    type Error = Error;
    fn try_from(ams: AnyMiniscript) -> Result<Self> {
        Ok(match ams {
            AnyMiniscript::Raw(rms) => rms.ctxify()?,
            AnyMiniscript::Segwitv0(cms) => cms,
            x => bail!(Error::MiniscriptIncompatibleCtx(
                CtxType::Segwitv0,
                x.into()
            )),
        })
    }
}
impl TryFrom<AnyMiniscript> for Miniscript<miniscript::Tap> {
    type Error = Error;
    fn try_from(ams: AnyMiniscript) -> Result<Self> {
        Ok(match ams {
            AnyMiniscript::Raw(rms) => rms.ctxify()?,
            AnyMiniscript::Tap(cms) => cms,
            x => bail!(Error::MiniscriptIncompatibleCtx(CtxType::Tap, x.into())),
        })
    }
}
impl TryFrom<AnyMiniscript> for Miniscript<miniscript::BareCtx> {
    type Error = Error;
    fn try_from(ams: AnyMiniscript) -> Result<Self> {
        Ok(match ams {
            AnyMiniscript::Raw(rms) => rms.ctxify()?,
            AnyMiniscript::Bare(cms) => cms,
            x => bail!(Error::MiniscriptIncompatibleCtx(CtxType::Bare, x.into())),
        })
    }
}
impl TryFrom<AnyMiniscript> for Miniscript<miniscript::Legacy> {
    type Error = Error;
    fn try_from(ams: AnyMiniscript) -> Result<Self> {
        Ok(match ams {
            AnyMiniscript::Raw(rms) => rms.ctxify()?,
            AnyMiniscript::Legacy(cms) => cms,
            x => bail!(Error::MiniscriptIncompatibleCtx(CtxType::Legacy, x.into())),
        })
    }
}

// Convert from AnyMiniscript into RawMiniscript
impl TryFrom<AnyMiniscript> for RawMiniscript {
    type Error = Error;
    fn try_from(ams: AnyMiniscript) -> Result<Self> {
        Ok(match ams {
            AnyMiniscript::Raw(rms) => rms,
            x => bail!(Error::MiniscriptUnexpectedCtx(x.into())),
        })
    }
}

impl RawMiniscript {
    /// Convert context-less RawMiniscript into a known Miniscript<Ctx>
    /// This can error if the RawMiniscript is illegal under the Ctx rules
    pub fn ctxify<Ctx: ScriptContext>(self) -> Result<Miniscript<Ctx>> {
        use RawMiniscript::*;
        let term = match self {
            True => Terminal::True,
            False => Terminal::False,
            PkK(pk) => Terminal::PkK(pk),
            PkH(pk) => Terminal::PkH(pk),
            RawPkH(hash) => Terminal::RawPkH(hash),
            Older(duration) => Terminal::Older(duration),
            After(time) => Terminal::After(time),
            Sha256(hash) => Terminal::Sha256(hash),
            Ripemd160(hash) => Terminal::Ripemd160(hash),
            Hash256(hash) => Terminal::Hash256(hash),
            Hash160(hash) => Terminal::Hash160(hash),

            Alt(m) => Terminal::Alt(m.ctxify()?.into()),
            Swap(m) => Terminal::Swap(m.ctxify()?.into()),
            Check(m) => Terminal::Check(m.ctxify()?.into()),
            DupIf(m) => Terminal::DupIf(m.ctxify()?.into()),
            Verify(m) => Terminal::Verify(m.ctxify()?.into()),
            NonZero(m) => Terminal::NonZero(m.ctxify()?.into()),
            ZeroNotEqual(m) => Terminal::ZeroNotEqual(m.ctxify()?.into()),

            AndV(a, b) => Terminal::AndV(a.ctxify()?.into(), b.ctxify()?.into()),
            AndB(a, b) => Terminal::AndB(a.ctxify()?.into(), b.ctxify()?.into()),
            AndOr(a, b, c) => {
                Terminal::AndOr(a.ctxify()?.into(), b.ctxify()?.into(), c.ctxify()?.into())
            }
            OrB(a, b) => Terminal::OrB(a.ctxify()?.into(), b.ctxify()?.into()),
            OrD(a, b) => Terminal::OrD(a.ctxify()?.into(), b.ctxify()?.into()),
            OrC(a, b) => Terminal::OrC(a.ctxify()?.into(), b.ctxify()?.into()),
            OrI(a, b) => Terminal::OrI(a.ctxify()?.into(), b.ctxify()?.into()),

            Thresh(thresh) => {
                let thresh = Threshold::new(
                    thresh.k(),
                    thresh
                        .into_iter()
                        .map(|rms| Ok(rms.ctxify::<Ctx>()?.into()))
                        .collect::<Result<_>>()?,
                )?;
                Terminal::Thresh(thresh)
            }
            Multi(thresh) => Terminal::Multi(Threshold::new(thresh.k(), thresh.into_data())?),
            MultiA(thresh) => Terminal::MultiA(Threshold::new(thresh.k(), thresh.into_data())?),
        };
        Ok(Miniscript::from_ast(term)?)
    }
}

impl<Ctx: ScriptContext> TryFrom<RawMiniscript> for Miniscript<Ctx> {
    type Error = Error;
    fn try_from(rms: RawMiniscript) -> Result<Self> {
        rms.ctxify()
    }
}

impl AnyMiniscript {
    pub fn context(&self) -> Option<CtxType> {
        Some(match self {
            Self::Segwitv0(_) => CtxType::Segwitv0,
            Self::Tap(_) => CtxType::Tap,
            Self::Legacy(_) => CtxType::Legacy,
            Self::Bare(_) => CtxType::Bare,
            Self::Raw(_) => return None,
        })
    }

    pub fn translate_pk<F: Fn(&DescriptorPublicKey) -> Result<DescriptorPublicKey>>(
        &self,
        func: &F,
    ) -> Result<Self> {
        use AnyMiniscript::*;
        Ok(match self {
            Raw(rms) => Raw(rms.translate_pk(func)?),
            Bare(cms) => Bare(cms.translate_pk(&mut FnTranslator::new(func))?),
            Legacy(cms) => Legacy(cms.translate_pk(&mut FnTranslator::new(func))?),
            Segwitv0(cms) => Segwitv0(cms.translate_pk(&mut FnTranslator::new(func))?),
            Tap(cms) => Tap(cms.translate_pk(&mut FnTranslator::new(func))?),
        })
    }

    pub fn is_multipath(&self) -> bool {
        self.for_any_key(DescriptorPublicKey::is_multipath)
    }
    pub fn has_wildcard(&self) -> bool {
        self.for_any_key(DescriptorPublicKey::has_wildcard)
    }
    pub fn is_definite(&self) -> bool {
        self.for_each_key(|pk| !pk.is_multipath() && !pk.has_wildcard())
    }

    pub fn keys(&self) -> Vec<DescriptorPublicKey> {
        let mut pks = vec![];
        self.for_each_key(|pk| {
            pks.push(pk.clone());
            true
        });
        pks
    }

    pub fn into_ctx<Ctx: ScriptContext>(self) -> Result<Miniscript<Ctx>>
    where
        Miniscript<Ctx>: TryFrom<Self, Error = Error>,
    {
        self.try_into()
    }

    pub fn encode_script(&self) -> Result<bitcoin::ScriptBuf> {
        Ok(match self {
            Self::Bare(cms) => cms.derive_keys()?.encode(),
            Self::Legacy(cms) => cms.derive_keys()?.encode(),
            Self::Segwitv0(cms) => cms.derive_keys()?.encode(),
            Self::Tap(cms) => cms.derive_keys()?.encode(),
            Self::Raw(rms) => bail!(Error::MiniscriptUnexpectedRaw(rms.clone().into())),
        })
    }

    pub fn sanity_check(&self) -> Option<result::Result<(), miniscript::AnalysisError>> {
        Some(match self {
            Self::Bare(cms) => cms.sanity_check(),
            Self::Legacy(cms) => cms.sanity_check(),
            Self::Segwitv0(cms) => cms.sanity_check(),
            Self::Tap(cms) => cms.sanity_check(),
            Self::Raw(_) => return None,
        })
    }
}

impl ForEachKey<DescriptorPublicKey> for AnyMiniscript {
    fn for_each_key<'a, F: FnMut(&'a DescriptorPublicKey) -> bool>(&'a self, mut pred: F) -> bool {
        match self {
            Self::Raw(rms) => rms.for_each_key(&mut pred),
            Self::Bare(cms) => cms.for_each_key(pred),
            Self::Legacy(cms) => cms.for_each_key(pred),
            Self::Segwitv0(cms) => cms.for_each_key(pred),
            Self::Tap(cms) => cms.for_each_key(pred),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CtxType {
    Segwitv0,
    Tap,
    Legacy,
    Bare,
}

impl RawMiniscript {
    pub fn translate_pk<F: Fn(&DescriptorPublicKey) -> Result<DescriptorPublicKey>>(
        &self,
        func: &F,
    ) -> Result<Self> {
        use RawMiniscript::*;
        Ok(match self {
            rms @ (True | False | RawPkH(_) | After(_) | Older(_) | Sha256(_) | Hash256(_)
            | Ripemd160(_) | Hash160(_)) => rms.clone(),
            // Keys
            PkK(pk) => PkK(func(pk)?),
            PkH(pk) => PkH(func(pk)?),
            // Wrappers
            Alt(rms) => Alt(rms.translate_pk(func)?.into()),
            Swap(rms) => Swap(rms.translate_pk(func)?.into()),
            Check(rms) => Check(rms.translate_pk(func)?.into()),
            DupIf(rms) => DupIf(rms.translate_pk(func)?.into()),
            Verify(rms) => Verify(rms.translate_pk(func)?.into()),
            NonZero(rms) => NonZero(rms.translate_pk(func)?.into()),
            ZeroNotEqual(rms) => ZeroNotEqual(rms.translate_pk(func)?.into()),
            // Conjunctions
            AndV(a, b) => AndV(a.translate_pk(func)?.into(), b.translate_pk(func)?.into()),
            AndB(a, b) => AndB(a.translate_pk(func)?.into(), b.translate_pk(func)?.into()),
            AndOr(a, b, c) => AndOr(
                a.translate_pk(func)?.into(),
                b.translate_pk(func)?.into(),
                c.translate_pk(func)?.into(),
            ),
            // Disjunctions
            OrB(a, b) => OrB(a.translate_pk(func)?.into(), b.translate_pk(func)?.into()),
            OrD(a, b) => OrD(a.translate_pk(func)?.into(), b.translate_pk(func)?.into()),
            OrC(a, b) => OrC(a.translate_pk(func)?.into(), b.translate_pk(func)?.into()),
            OrI(a, b) => OrI(a.translate_pk(func)?.into(), b.translate_pk(func)?.into()),
            // Thresholds
            Thresh(thresh) => Thresh(Threshold::new(
                thresh.k(),
                thresh
                    .iter()
                    .map(|rms| rms.translate_pk(func))
                    .collect::<Result<_>>()?,
            )?),
            Multi(thresh) => Multi(Threshold::new(
                thresh.k(),
                thresh.iter().map(func).collect::<Result<_>>()?,
            )?),
            MultiA(thresh) => MultiA(Threshold::new(
                thresh.k(),
                thresh.iter().map(func).collect::<Result<_>>()?,
            )?),
        })
    }

    pub fn for_each_key<'a, F: FnMut(&'a DescriptorPublicKey) -> bool>(
        &'a self,
        pred: &mut F,
    ) -> bool {
        use RawMiniscript::*;
        match self {
            True | False | RawPkH(_) | After(_) | Older(_) | Sha256(_) | Hash256(_)
            | Ripemd160(_) | Hash160(_) => true,
            // Keys
            PkK(pk) => pred(pk),
            PkH(pk) => pred(pk),
            // Wrappers
            Alt(rms) => rms.for_each_key(pred),
            Swap(rms) => rms.for_each_key(pred),
            Check(rms) => rms.for_each_key(pred),
            DupIf(rms) => rms.for_each_key(pred),
            Verify(rms) => rms.for_each_key(pred),
            NonZero(rms) => rms.for_each_key(pred),
            ZeroNotEqual(rms) => rms.for_each_key(pred),
            // Conjunctions
            AndV(a, b) => a.for_each_key(pred) && b.for_each_key(pred),
            AndB(a, b) => a.for_each_key(pred) && b.for_each_key(pred),
            AndOr(a, b, c) => a.for_each_key(pred) && b.for_each_key(pred) && c.for_each_key(pred),
            // Disjunctions
            OrB(a, b) => a.for_each_key(pred) && b.for_each_key(pred),
            OrD(a, b) => a.for_each_key(pred) && b.for_each_key(pred),
            OrC(a, b) => a.for_each_key(pred) && b.for_each_key(pred),
            OrI(a, b) => a.for_each_key(pred) && b.for_each_key(pred),
            // Thresholds
            Thresh(thresh) => thresh.iter().all(|rms| rms.for_each_key(pred)),
            Multi(thresh) => thresh.iter().all(pred),
            MultiA(thresh) => thresh.iter().all(pred),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MiniscriptWrapper {
    Alt,          // a
    Swap,         // s
    Check,        // c
    DupIf,        // d
    Verify,       // v
    NonZero,      // j
    ZeroNotEqual, // n

    // syntactic sugar aliases
    T, // t
    U, // u
    L, // l

    MultiWrap(Vec<MiniscriptWrapper>),
}

impl MiniscriptWrapper {
    pub fn wrap(&self, ams: AnyMiniscript) -> Result<AnyMiniscript> {
        Ok(match ams {
            AnyMiniscript::Raw(rms) => AnyMiniscript::Raw(self.wrap_raw(rms)),
            AnyMiniscript::Bare(cms) => AnyMiniscript::Bare(self.wrap_ctx(cms)?),
            AnyMiniscript::Legacy(cms) => AnyMiniscript::Legacy(self.wrap_ctx(cms)?),
            AnyMiniscript::Segwitv0(cms) => AnyMiniscript::Segwitv0(self.wrap_ctx(cms)?),
            AnyMiniscript::Tap(cms) => AnyMiniscript::Tap(self.wrap_ctx(cms)?),
        })
    }

    fn wrap_raw(&self, rms: RawMiniscript) -> RawMiniscript {
        match self {
            Self::Alt => RawMiniscript::Alt(rms.into()),
            Self::Swap => RawMiniscript::Swap(rms.into()),
            Self::Check => RawMiniscript::Check(rms.into()),
            Self::DupIf => RawMiniscript::DupIf(rms.into()),
            Self::Verify => RawMiniscript::Verify(rms.into()),
            Self::NonZero => RawMiniscript::NonZero(rms.into()),
            Self::ZeroNotEqual => RawMiniscript::ZeroNotEqual(rms.into()),
            Self::T => RawMiniscript::AndV(rms.into(), RawMiniscript::True.into()),
            Self::U => RawMiniscript::OrI(rms.into(), RawMiniscript::False.into()),
            Self::L => RawMiniscript::OrI(RawMiniscript::False.into(), rms.into()),
            Self::MultiWrap(wrappers) => {
                wrappers
                    .iter()
                    .rev() // so inner-most wrappers apply first
                    .fold(rms, |curr, wrapper| wrapper.wrap_raw(curr))
            }
        }
    }

    fn wrap_ctx<Ctx: ScriptContext>(&self, cms: Miniscript<Ctx>) -> Result<Miniscript<Ctx>> {
        use miniscript::Terminal;
        Ok(Miniscript::from_ast(match self {
            Self::Alt => Terminal::Alt(cms.into()),
            Self::Swap => Terminal::Swap(cms.into()),
            Self::Check => Terminal::Check(cms.into()),
            Self::DupIf => Terminal::DupIf(cms.into()),
            Self::Verify => Terminal::Verify(cms.into()),
            Self::NonZero => Terminal::NonZero(cms.into()),
            Self::ZeroNotEqual => Terminal::ZeroNotEqual(cms.into()),
            Self::T => Terminal::AndV(cms.into(), Miniscript::TRUE.into()),
            Self::U => Terminal::OrI(cms.into(), Miniscript::FALSE.into()),
            Self::L => Terminal::OrI(Miniscript::FALSE.into(), cms.into()),
            Self::MultiWrap(wrappers) => {
                return wrappers
                    .iter()
                    .rev() // so inner-most wrappers apply first
                    .try_fold(cms, |curr, wrapper| wrapper.wrap_ctx(curr));
            }
        })?)
    }
}

impl ops::Add for MiniscriptWrapper {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        let mut wrappers = Vec::new();
        for w in [self, other] {
            match w {
                Self::MultiWrap(ws) => wrappers.extend(ws),
                w => wrappers.push(w),
            }
        }
        MiniscriptWrapper::MultiWrap(wrappers)
    }
}

// Support using wrappers as functions too, e.g. `c(pk_k(..))` instead of `c:pk_k()`
impl runtime::Call for MiniscriptWrapper {
    fn call(&self, args: Vec<Value>, _: &ScopeRef) -> Result<Value> {
        Ok(self.wrap(Array(args).arg_into()?)?.into())
    }
}

#[rustfmt::skip]
impl_simple_into_variant!(MiniscriptWrapper, MiniscriptWrapper, into_ms_wrapper, NotMiniscriptWrapper);

impl fmt::Display for AnyMiniscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Raw(rms) => write!(f, "miniscript({})", rms),
            Self::Bare(cms) => write!(f, "miniscript::bare({})", cms),
            Self::Legacy(cms) => write!(f, "miniscript::legacy({})", cms),
            Self::Segwitv0(cms) => write!(f, "miniscript::segwitv0({})", cms),
            Self::Tap(cms) => write!(f, "miniscript::tap({})", cms),
        }
    }
}

impl ExprRepr for AnyMiniscript {
    fn repr_fmt<W: fmt::Write>(&self, f: &mut W) -> fmt::Result {
        match self {
            Self::Raw(rms) => write!(f, "miniscript({})", rms),
            // Use rust-miniscript's Display/FromStr directly, without going through the Minsc parser and runtime
            // This is both safer and more efficient, and doesn't depend on multi-wrapper-letter variable names existing in the env
            Self::Bare(cms) => write!(f, "miniscript::bare(\"{}\")", cms),
            Self::Legacy(cms) => write!(f, "miniscript::legacy(\"{}\")", cms),
            Self::Segwitv0(cms) => write!(f, "miniscript::segwitv0(\"{}\")", cms),
            Self::Tap(cms) => write!(f, "miniscript::tap(\"{}\")", cms),
        }
    }
}

// XXX Unlike rust-miniscript's Display impl for Miniscript<Ctx>, this doesn't re-sugar
// the pk()/pkh()/and_n() aliases or the l: t: u syntatic sugar wrappers (which are encoded
// in fully expanded form) and doesn't merge wrapper letters together (e.g. `v:c:`, not `vc:`)
impl fmt::Display for RawMiniscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use RawMiniscript::*;
        match self {
            True => write!(f, "1"),
            False => write!(f, "0"),
            PkK(pk) => write!(f, "pk_k({})", pk),
            PkH(pk) => write!(f, "pk_h({})", pk),
            RawPkH(hash) => write!(f, "expr_raw_pkh({})", hash),

            // The encoding for timelock/hashlock miniscript fragments is identical to that of policies,
            // which initially evaluates back to a Policy and is later coerced back into a Miniscript as necessary.
            Older(duration) => write!(f, "older({})", duration),
            After(time) => write!(f, "after({})", time),
            Sha256(hash) => write!(f, "sha256({})", hash),
            Ripemd160(hash) => write!(f, "ripemd160({})", hash),
            Hash256(hash) => write!(f, "hash256({})", hash),
            Hash160(hash) => write!(f, "hash160({})", hash),

            // The encoding for X: wrappers evaluate back to a tuple array, not a Miniscript,
            // and is later coerced back into a Miniscript as necessary.
            Alt(rms) => write!(f, "a:{}", rms),
            Swap(rms) => write!(f, "s:{}", rms),
            Check(rms) => write!(f, "c:{}", rms),
            DupIf(rms) => write!(f, "d:{}", rms),
            Verify(rms) => write!(f, "v:{}", rms),
            NonZero(rms) => write!(f, "j:{}", rms),
            ZeroNotEqual(rms) => write!(f, "n:{}", rms),

            AndV(a, b) => write!(f, "and_v({},{})", a, b),
            AndB(a, b) => write!(f, "and_b({},{})", a, b),
            AndOr(a, b, c) => write!(f, "andor({},{},{})", a, b, c),
            OrB(a, b) => write!(f, "or_b({},{})", a, b),
            OrD(a, b) => write!(f, "or_d({},{})", a, b),
            OrC(a, b) => write!(f, "or_c({},{})", a, b),
            OrI(a, b) => write!(f, "or_i({},{})", a, b),

            Thresh(thresh) => {
                write!(f, "thresh({}", thresh.k())?;
                for rms in thresh.iter() {
                    write!(f, ",{}", rms)?
                }
                write!(f, ")")
            }
            Multi(thresh) => {
                write!(f, "multi({}", thresh.k())?;
                for pk in thresh.iter() {
                    write!(f, ",{}", pk)?
                }
                write!(f, ")")
            }
            MultiA(thresh) => {
                write!(f, "multi_a({}", thresh.k())?;
                for pk in thresh.iter() {
                    write!(f, ",{}", pk)?
                }
                write!(f, ")")
            }
        }
    }
}

impl fmt::Display for MiniscriptWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alt => write!(f, "a"),
            Self::Swap => write!(f, "s"),
            Self::Check => write!(f, "c"),
            Self::DupIf => write!(f, "d"),
            Self::Verify => write!(f, "v"),
            Self::NonZero => write!(f, "j"),
            Self::ZeroNotEqual => write!(f, "n"),
            Self::L => write!(f, "l"),
            Self::T => write!(f, "t"),
            Self::U => write!(f, "u"),
            // Encode MultiWrap concatenated as `xyz`, which is only round-trip-able
            // if a matching multi-wrapper-letter variable name exists in the env
            Self::MultiWrap(wrappers) => {
                for wrapper in wrappers {
                    write!(f, "{}", wrapper)?;
                }
                Ok(())
            }
        }
    }
}

impl ExprRepr for MiniscriptWrapper {
    fn repr_fmt<W: fmt::Write>(&self, f: &mut W) -> fmt::Result {
        match self {
            // Encode MultiWrap as `(x+y+z)`, which is round-trip-able without relying on multi-wrapper-letter variables existing
            Self::MultiWrap(wrappers) => {
                write!(f, "(")?;
                for (i, wrapper) in wrappers.iter().enumerate() {
                    if i > 0 {
                        write!(f, "+")?;
                    }
                    write!(f, "{}", wrapper)?;
                }
                write!(f, ")")
            }
            single => write!(f, "{}", single),
        }
    }
}

impl fmt::Display for CtxType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CtxType::Segwitv0 => write!(f, "segwitv0"),
            CtxType::Tap => write!(f, "tap"),
            CtxType::Legacy => write!(f, "legacy"),
            CtxType::Bare => write!(f, "bare"),
        }
    }
}
