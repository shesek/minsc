use std::marker::PhantomData;

use bitcoin::bip32::{ChildNumber, IntoDerivationPath};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{secp256k1, PublicKey};
use miniscript::descriptor::{DerivPaths, DescriptorMultiXKey, DescriptorPublicKey, Wildcard};
use miniscript::{bitcoin, ForEachKey, MiniscriptKey, TranslatePk, Translator};

use crate::runtime::{Array, Error, Result, Value};

lazy_static! {
    pub static ref EC: secp256k1::Secp256k1<secp256k1::VerifyOnly> =
        secp256k1::Secp256k1::verification_only();
}

pub trait MiniscriptExt<T: miniscript::ScriptContext> {
    fn derive_keys(self) -> Result<miniscript::Miniscript<PublicKey, T>>;
}

impl<Ctx: miniscript::ScriptContext> MiniscriptExt<Ctx>
    for miniscript::Miniscript<DescriptorPublicKey, Ctx>
{
    fn derive_keys(self) -> Result<miniscript::Miniscript<PublicKey, Ctx>> {
        Ok(
            self.translate_pk(&mut FnTranslator::new(|xpk: &DescriptorPublicKey| {
                Ok(xpk.clone().at_derivation_index(0)?.derive_public_key(&EC)?)
            }))?,
        )
    }
}
pub trait DescriptorExt {
    fn derive_keys(&self) -> Result<miniscript::Descriptor<PublicKey>>;
    fn to_script_pubkey(&self) -> Result<bitcoin::ScriptBuf>;
    fn to_explicit_script(&self) -> Result<bitcoin::ScriptBuf>;
    fn to_address(&self, network: bitcoin::Network) -> Result<bitcoin::Address>;
}

impl DescriptorExt for crate::DescriptorDpk {
    fn derive_keys(&self) -> Result<miniscript::Descriptor<PublicKey>> {
        // XXX verify no wildcard?
        Ok(self.derived_descriptor(&EC, 0)?)
    }
    fn to_script_pubkey(&self) -> Result<bitcoin::ScriptBuf> {
        Ok(self.derive_keys()?.script_pubkey())
    }
    fn to_explicit_script(&self) -> Result<bitcoin::ScriptBuf> {
        Ok(self.derive_keys()?.explicit_script()?)
    }
    fn to_address(&self, network: bitcoin::Network) -> Result<bitcoin::Address> {
        Ok(self.derive_keys()?.address(network)?)
    }
}

pub trait DeriveExt {
    fn derive_path<P: DerivePath>(self, path: P, is_wildcard: bool) -> Result<Self>
    where
        Self: Sized;
    fn derive_multi<P: DerivePath>(self, paths: &[P], is_wildcard: bool) -> Result<Self>
    where
        Self: Sized;
    fn is_deriveable(&self) -> bool;
}

// Used as a trait alias shortcut
pub trait DerivePath: IntoDerivationPath + Clone {}
impl<T: IntoDerivationPath + Clone> DerivePath for T {}

impl DeriveExt for DescriptorPublicKey {
    fn derive_path<P: DerivePath>(self, path: P, is_wildcard: bool) -> Result<Self> {
        let path = path.into_derivation_path()?;
        match self {
            DescriptorPublicKey::XPub(mut xpub) => {
                xpub.derivation_path = xpub.derivation_path.extend(path);
                // XXX hardened derivation is currently unsupported
                xpub.wildcard = iif!(is_wildcard, Wildcard::Unhardened, Wildcard::None);
                Ok(DescriptorPublicKey::XPub(xpub))
            }
            DescriptorPublicKey::MultiXPub(mut mxpub) => {
                mxpub.derivation_paths = DerivPaths::new(
                    mxpub
                        .derivation_paths
                        .into_paths()
                        .into_iter()
                        .map(|mx_path| mx_path.extend(&path))
                        .collect(),
                )
                .expect("path cannot be empty");
                Ok(DescriptorPublicKey::MultiXPub(mxpub))
            }
            DescriptorPublicKey::Single(_) => bail!(Error::NonDeriveableSingle),
        }
    }

    fn derive_multi<P: DerivePath>(self, paths: &[P], is_wildcard: bool) -> Result<Self> {
        let paths = paths
            .into_iter()
            .map(|p| Ok(p.clone().into_derivation_path()?))
            .collect::<Result<Vec<_>>>()?;

        let parent_paths = self.full_derivation_paths();

        let child_paths = paths
            .into_iter()
            .flat_map(|child_path| {
                parent_paths
                    .iter()
                    .map(move |parent_path| parent_path.extend(child_path.clone()))
            })
            .collect::<Vec<_>>();

        let (origin, xkey) = match self {
            DescriptorPublicKey::XPub(xpub) => (xpub.origin, xpub.xkey),
            DescriptorPublicKey::MultiXPub(mxpub) => (mxpub.origin, mxpub.xkey),
            DescriptorPublicKey::Single(_) => bail!(Error::NonDeriveableSingle),
        };
        Ok(DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: origin,
            xkey: xkey,
            derivation_paths: DerivPaths::new(child_paths).expect("cannot be empty"),
            wildcard: iif!(is_wildcard, Wildcard::Unhardened, Wildcard::None),
        }))
    }
    fn is_deriveable(&self) -> bool {
        // Xpubs are always derivable, even without the * wildcard suffix
        matches!(self, DescriptorPublicKey::XPub(_))
    }
}
impl DeriveExt for crate::PolicyDpk {
    fn derive_path<P: DerivePath>(self, path: P, is_wildcard: bool) -> Result<Self> {
        // ensure!(self.is_deriveable(), Error::NonDeriveableNoWildcard);
        let path = path.into_derivation_path()?;
        self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
            Ok(pk.clone().derive_path(path.clone(), is_wildcard)?)
        }))
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], is_wildcard: bool) -> Result<Self> {
        // ensure!(self.is_deriveable(), Error::NonDeriveableNoWildcard);
        self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
            Ok(pk.clone().derive_multi(paths, is_wildcard)?)
        }))
    }
    fn is_deriveable(&self) -> bool {
        self.for_any_key(|key| key.has_wildcard())
    }
}
impl<Ctx: miniscript::ScriptContext> DeriveExt for crate::MiniscriptDpk<Ctx> {
    fn derive_path<P: DerivePath>(self, path: P, is_wildcard: bool) -> Result<Self> {
        ensure!(self.is_deriveable(), Error::NonDeriveableNoWildcard);
        let path = path.into_derivation_path()?;
        Ok(
            self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
                pk.clone().derive_path(path.clone(), is_wildcard)
            }))?,
        )
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], is_wildcard: bool) -> Result<Self> {
        ensure!(self.is_deriveable(), Error::NonDeriveableNoWildcard);
        Ok(
            self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
                pk.clone().derive_multi(paths, is_wildcard)
            }))?,
        )
    }
    fn is_deriveable(&self) -> bool {
        self.for_any_key(|pk| pk.has_wildcard())
    }
}
impl DeriveExt for crate::DescriptorDpk {
    fn derive_path<P: DerivePath>(self, path: P, is_wildcard: bool) -> Result<Self> {
        ensure!(
            DeriveExt::is_deriveable(&self),
            Error::NonDeriveableNoWildcard
        );
        let path = path.into_derivation_path()?;
        Ok(
            self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
                pk.clone().derive_path(path.clone(), is_wildcard)
            }))?,
        )
    }

    fn derive_multi<P: DerivePath>(self, paths: &[P], is_wildcard: bool) -> Result<Self> {
        ensure!(
            DeriveExt::is_deriveable(&self),
            Error::NonDeriveableNoWildcard
        );
        Ok(
            self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
                pk.clone().derive_multi(paths, is_wildcard)
            }))?,
        )
    }
    fn is_deriveable(&self) -> bool {
        self.has_wildcard()
    }
}
impl DeriveExt for Value {
    fn derive_path<P: DerivePath>(self, path: P, is_wildcard: bool) -> Result<Self> {
        Ok(match self {
            Value::PubKey(key) => key.derive_path(path, is_wildcard)?.into(),
            Value::Descriptor(desc) => desc.derive_path(path, is_wildcard)?.into(),
            Value::Policy(policy) => policy.derive_path(path, is_wildcard)?.into(),
            Value::Array(array) => array.derive_path(path, is_wildcard)?.into(),
            _ => bail!(Error::NonDeriveableType),
        })
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], is_wildcard: bool) -> Result<Self> {
        Ok(match self {
            Value::PubKey(key) => key.derive_multi(paths, is_wildcard)?.into(),
            Value::Descriptor(desc) => desc.derive_multi(paths, is_wildcard)?.into(),
            Value::Policy(policy) => policy.derive_multi(paths, is_wildcard)?.into(),
            Value::Array(array) => array.derive_multi(paths, is_wildcard)?.into(),
            _ => bail!(Error::NonDeriveableType),
        })
    }
    fn is_deriveable(&self) -> bool {
        match self {
            Value::PubKey(key) => DeriveExt::is_deriveable(key),
            Value::Descriptor(desc) => DeriveExt::is_deriveable(desc),
            Value::Policy(policy) => policy.is_deriveable(),
            Value::Array(array) => array.is_deriveable(),
            _ => false,
        }
    }
}

impl DeriveExt for Array {
    fn derive_path<P: DerivePath>(self, path: P, is_wildcard: bool) -> Result<Self> {
        Ok(Array(
            self.into_iter()
                .map(|v| v.derive_path(path.clone(), is_wildcard))
                .collect::<Result<_>>()?,
        ))
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], is_wildcard: bool) -> Result<Self> {
        Ok(Array(
            self.into_iter()
                .map(|v| v.derive_multi(paths, is_wildcard))
                .collect::<Result<_>>()?,
        ))
    }
    fn is_deriveable(&self) -> bool {
        self.iter().any(|v| v.is_deriveable())
    }
}

// A `Translator` for keys using a closure function, similar to
// the `TranslatePk2` available in prior rust-miniscript releases
struct FnTranslator<P: MiniscriptKey, Q: MiniscriptKey, F: Fn(&P) -> Result<Q>> {
    func: F,
    _marker: PhantomData<(P, Q)>,
}

impl<P: MiniscriptKey, Q: MiniscriptKey, F: Fn(&P) -> Result<Q>> FnTranslator<P, Q, F> {
    pub fn new(func: F) -> Self {
        FnTranslator {
            func,
            _marker: PhantomData,
        }
    }
}

impl<P, Q, F> Translator<P, Q, Error> for FnTranslator<P, Q, F>
where
    P: MiniscriptKey,
    // hashes are passed through as-is, P and Q must share the same hash types
    Q: MiniscriptKey<
        Sha256 = P::Sha256,
        Hash256 = P::Hash256,
        Ripemd160 = P::Ripemd160,
        Hash160 = P::Hash160,
    >,
    F: Fn(&P) -> Result<Q>,
{
    fn pk(&mut self, pk: &P) -> Result<Q> {
        (self.func)(pk)
    }

    fn sha256(&mut self, sha256: &P::Sha256) -> Result<Q::Sha256> {
        Ok(sha256.clone())
    }
    fn hash256(&mut self, hash256: &P::Hash256) -> Result<Q::Hash256> {
        Ok(hash256.clone())
    }
    fn ripemd160(&mut self, ripemd160: &P::Ripemd160) -> Result<Q::Ripemd160> {
        Ok(ripemd160.clone())
    }
    fn hash160(&mut self, ripemd160: &P::Hash160) -> Result<Q::Hash160> {
        Ok(ripemd160.clone())
    }
}

/// Compute a derivation path from a sha256 hash.
///
/// Format is a bit peculiar, it's 9 u32's with the top bit as 0 (for unhardened
/// derivation). We take each u32 in the hash (big endian) and mask off the top bit.
/// Then we go over the 8 u32s and make a 8 bit u32 from the top bits.
///
/// This is because the ChildNumber is a enum u31 where the top bit is used to
/// indicate hardened or not, so we can't just do the simple thing.
///
/// Copied from https://github.com/sapio-lang/sapio/blob/072b8835dcf4ba6f8f00f3a5d9034ef8e021e0a7/ctv_emulators/src/lib.rs
pub fn hash_to_child_vec(h: sha256::Hash) -> Vec<ChildNumber> {
    let a: [u8; 32] = h.to_byte_array();
    let b: [[u8; 4]; 8] = unsafe { std::mem::transmute(a) };
    let mut c: Vec<ChildNumber> = b
        .iter()
        // Note: We mask off the top bit. This removes 8 bits of entropy from the hash,
        // but we add it back in later.
        .map(|x| (u32::from_be_bytes(*x) << 1) >> 1)
        .map(ChildNumber::from)
        .collect();
    // Add a unique 9th path for the MSB's
    c.push(
        b.iter()
            .enumerate()
            .map(|(i, x)| (u32::from_be_bytes(*x) >> 31) << i)
            .sum::<u32>()
            .into(),
    );
    c
}

pub fn concat<T>(mut list: Vec<T>, val: Option<T>) -> Vec<T> {
    if let Some(val) = val {
        list.push(val);
    }
    list
}
