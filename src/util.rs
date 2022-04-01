use std::fmt::Debug;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::util::bip32::{ChildNumber, IntoDerivationPath};
use bitcoin::{secp256k1, PublicKey};
use miniscript::descriptor::{DescriptorPublicKey, DescriptorTrait, Wildcard};
use miniscript::{bitcoin, ForEachKey, TranslatePk2};

use crate::{Error, Result, Value};

lazy_static! {
    pub static ref EC: secp256k1::Secp256k1<secp256k1::VerifyOnly> =
        secp256k1::Secp256k1::verification_only();
}

pub trait MiniscriptExt<T: miniscript::ScriptContext> {
    fn derive_keys(&self) -> Result<miniscript::Miniscript<PublicKey, T>>;
}

impl<Ctx: miniscript::ScriptContext> MiniscriptExt<Ctx>
    for miniscript::Miniscript<DescriptorPublicKey, Ctx>
{
    fn derive_keys(&self) -> Result<miniscript::Miniscript<PublicKey, Ctx>> {
        Ok(self.translate_pk2(|xpk| xpk.derive_public_key(&EC))?)
    }
}
pub trait DescriptorExt {
    fn derive_keys(&self) -> Result<miniscript::Descriptor<PublicKey>>;
    fn to_script_pubkey(&self) -> Result<bitcoin::Script>;
    fn to_explicit_script(&self) -> Result<bitcoin::Script>;
    fn to_address(&self, network: bitcoin::Network) -> Result<bitcoin::Address>;
}

impl DescriptorExt for crate::DescriptorDpk {
    fn derive_keys(&self) -> Result<miniscript::Descriptor<PublicKey>> {
        Ok(self.translate_pk2(|xpk| xpk.derive_public_key(&EC))?)
    }
    fn to_script_pubkey(&self) -> Result<bitcoin::Script> {
        Ok(self.derive_keys()?.script_pubkey())
    }
    fn to_explicit_script(&self) -> Result<bitcoin::Script> {
        Ok(self.derive_keys()?.explicit_script()?)
    }
    fn to_address(&self, network: bitcoin::Network) -> Result<bitcoin::Address> {
        Ok(self.derive_keys()?.address(network)?)
    }
}

pub trait DeriveExt {
    fn derive_path<P: DerivePath>(&self, path: P, is_wildcard: bool) -> Result<Self>
    where
        Self: Sized;
    fn is_deriveable(&self) -> bool;
}

// Used as a trait alias shortcut
pub trait DerivePath: IntoDerivationPath + Clone {}
impl<T: IntoDerivationPath + Clone> DerivePath for T {}

impl DeriveExt for DescriptorPublicKey {
    fn derive_path<P: DerivePath>(&self, path: P, is_wildcard: bool) -> Result<Self> {
        let mut xpub = match self {
            DescriptorPublicKey::XPub(xpub) => xpub.clone(),
            DescriptorPublicKey::SinglePub(_) => bail!(Error::NonDeriveableSingle),
        };
        xpub.derivation_path = xpub.derivation_path.extend(path.into_derivation_path()?);
        // XXX hardened derivation is currently unsupported
        xpub.wildcard = iif!(is_wildcard, Wildcard::Unhardened, Wildcard::None);
        Ok(DescriptorPublicKey::XPub(xpub))
    }
    fn is_deriveable(&self) -> bool {
        // Xpubs are always derivable, even without the * wildcard suffix
        matches!(self, DescriptorPublicKey::XPub(_))
    }
}
impl DeriveExt for crate::PolicyDpk {
    fn derive_path<P: DerivePath>(&self, path: P, is_wildcard: bool) -> Result<Self> {
        // ensure!(self.is_deriveable(), Error::NonDeriveableNoWildcard);
        let path = path.into_derivation_path()?;
        self.translate_pk(|pk| pk.derive_path(path.clone(), is_wildcard))
    }
    fn is_deriveable(&self) -> bool {
        // TODO This fails with 'reached the recursion limit while instantiating'
        // self.for_any_key(|key| key.as_key().is_deriveable())
        true
    }
}
impl<Ctx: miniscript::ScriptContext> DeriveExt for crate::MiniscriptDpk<Ctx> {
    fn derive_path<P: DerivePath>(&self, path: P, is_wildcard: bool) -> Result<Self> {
        ensure!(self.is_deriveable(), Error::NonDeriveableNoWildcard);
        let path = path.into_derivation_path()?;
        self.translate_pk2(|pk| pk.derive_path(path.clone(), is_wildcard))
    }
    fn is_deriveable(&self) -> bool {
        self.for_any_key(|key| key.as_key().is_deriveable())
    }
}
impl DeriveExt for crate::DescriptorDpk {
    fn derive_path<P: DerivePath>(&self, path: P, is_wildcard: bool) -> Result<Self> {
        ensure!(self.is_deriveable(), Error::NonDeriveableNoWildcard);
        let path = path.into_derivation_path()?;
        self.translate_pk2(|pk| pk.derive_path(path.clone(), is_wildcard))
    }
    fn is_deriveable(&self) -> bool {
        // delegate to miniscript::Descriptor::is_derivable()
        self.is_deriveable()
    }
}
impl DeriveExt for Value {
    fn derive_path<P: DerivePath>(&self, path: P, is_wildcard: bool) -> Result<Self> {
        Ok(match self {
            Value::PubKey(key) => key.derive_path(path, is_wildcard)?.into(),
            Value::Descriptor(desc) => desc.derive_path(path, is_wildcard)?.into(),
            Value::Policy(policy) => policy.derive_path(path, is_wildcard)?.into(),
            Value::Array(array) => array.derive_path(path, is_wildcard)?.into(),
            _ => bail!(Error::NonDeriveableType),
        })
    }
    fn is_deriveable(&self) -> bool {
        match self {
            Value::PubKey(key) => key.is_deriveable(),
            Value::Descriptor(desc) => desc.is_deriveable(),
            Value::Policy(policy) => policy.is_deriveable(),
            Value::Array(array) => array.is_deriveable(),
            _ => false,
        }
    }
}
impl DeriveExt for Vec<Value> {
    fn derive_path<P: DerivePath>(&self, path: P, is_wildcard: bool) -> Result<Self> {
        self.into_iter()
            .map(|v| v.derive_path(path.clone(), is_wildcard))
            .collect::<Result<_>>()
    }
    fn is_deriveable(&self) -> bool {
        self.iter().any(|v| v.is_deriveable())
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
    let a: [u8; 32] = h.into_inner();
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

// extract N out of "N years"
// `s` is assumed to be valid, because the parser already matched it against a regex
pub fn parse_str_prefix<T: FromStr>(s: &str) -> T
where
    <T as FromStr>::Err: Debug,
{
    s.split_ascii_whitespace().next().unwrap().parse().unwrap()
}
