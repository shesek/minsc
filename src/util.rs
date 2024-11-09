use std::marker::PhantomData;
use std::sync::Arc;
use std::{fmt, iter};

use bitcoin::bip32::{self, ChildNumber, DerivationPath, IntoDerivationPath};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{psbt, secp256k1, PublicKey};
use miniscript::descriptor::{
    self, DerivPaths, DescriptorMultiXKey, DescriptorPublicKey, DescriptorSecretKey, Wildcard,
};
use miniscript::{
    bitcoin, DefiniteDescriptorKey, Descriptor, ForEachKey, MiniscriptKey, TranslatePk, Translator,
};

use crate::runtime::{Array, Error, Result, Value};

lazy_static! {
    pub static ref EC: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

// Taproot utilities

pub trait TapInfoExt {
    fn witness_program(&self) -> bitcoin::WitnessProgram;
    fn script_pubkey(&self) -> bitcoin::ScriptBuf {
        bitcoin::ScriptBuf::new_witness_program(&self.witness_program())
    }
}
impl TapInfoExt for TaprootSpendInfo {
    fn witness_program(&self) -> bitcoin::WitnessProgram {
        bitcoin::WitnessProgram::p2tr_tweaked(self.output_key())
    }
}

pub trait PsbtTaprootExt {
    /// Update PSBT fields using the TaprootSpendInfo
    fn update_with_taproot(&mut self, tapinfo: &TaprootSpendInfo) -> Result<()>;
}
impl PsbtTaprootExt for psbt::Input {
    fn update_with_taproot(&mut self, tapinfo: &TaprootSpendInfo) -> Result<()> {
        self.tap_merkle_root = tapinfo.merkle_root();
        self.tap_internal_key = Some(tapinfo.internal_key());
        self.tap_scripts = tapinfo
            .script_map()
            .iter()
            .map(|(script_ver, _)| {
                let ctrl = tapinfo.control_block(script_ver).expect("must exists");
                (ctrl, script_ver.clone())
            })
            .collect();
        // `tap_key_origins` needs to be filled in manually
        Ok(())
    }
}
impl PsbtTaprootExt for psbt::Output {
    fn update_with_taproot(&mut self, tapinfo: &TaprootSpendInfo) -> Result<()> {
        self.tap_internal_key = Some(tapinfo.internal_key());
        // `tap_key_origins` needs to be filled in manually
        // TODO autofill `tap_tree`
        Ok(())
    }
}

// Miniscript utilities

pub trait MiniscriptExt<T: miniscript::ScriptContext> {
    fn derive_keys(self) -> Result<miniscript::Miniscript<PublicKey, T>>;
}

impl<Ctx: miniscript::ScriptContext> MiniscriptExt<Ctx>
    for miniscript::Miniscript<DescriptorPublicKey, Ctx>
{
    fn derive_keys(self) -> Result<miniscript::Miniscript<PublicKey, Ctx>> {
        Ok(
            self.translate_pk(&mut FnTranslator::new(|xpk: &DescriptorPublicKey| {
                xpk.clone().derive_definite()
            }))?,
        )
    }
}
pub trait DescriptorExt {
    /// Convert into a Descriptor over definite pubkeys. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn definite(&self) -> Result<Descriptor<DefiniteDescriptorKey>>;

    /// Convert into a Descriptor over derived pubkeys. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn derive_definite(&self) -> Result<Descriptor<PublicKey>> {
        Ok(self.definite()?.derived_descriptor(&EC)?)
    }

    /// Get the scriptPubKey. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn to_script_pubkey(&self) -> Result<bitcoin::ScriptBuf> {
        Ok(self.derive_definite()?.script_pubkey())
    }

    /// Get the explicit script. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn to_explicit_script(&self) -> Result<bitcoin::ScriptBuf> {
        Ok(self.derive_definite()?.explicit_script()?)
    }

    /// Get the address. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn to_address(&self, network: bitcoin::Network) -> Result<bitcoin::Address> {
        Ok(self.derive_definite()?.address(network)?)
    }

    /// Get the witness program. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn witness_program(&self) -> Result<Option<bitcoin::WitnessProgram>> {
        Ok(self
            .to_address(bitcoin::Network::Bitcoin)?
            .witness_program())
    }

    /// Get the inner Tr, if it is a Tr descriptors
    fn tr(&self) -> Option<&descriptor::Tr<DescriptorPublicKey>>;

    /// Get a TaprootSpendInfo representation of this Tr descriptor
    /// Returna an Ok(None) for non-Taproot descriptors, or an Err for Taproot
    /// descriptors that are not definite (contain underived wildcards).
    fn tap_info(&self) -> Result<Option<Arc<TaprootSpendInfo>>>;
}

impl DescriptorExt for Descriptor<DescriptorPublicKey> {
    fn definite(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        ensure!(
            !self.has_wildcard(),
            Error::UnexpectedWildcardDescriptor(self.clone().into())
        );
        ensure!(
            !self.is_multipath(),
            Error::UnexpectedMultiPathDescriptor(self.clone().into())
        );
        Ok(self.at_derivation_index(0).expect("index is valid"))
    }

    fn tr(&self) -> Option<&descriptor::Tr<DescriptorPublicKey>> {
        match self {
            Descriptor::Tr(tr) => Some(tr),
            _ => None,
        }
    }

    fn tap_info(&self) -> Result<Option<Arc<TaprootSpendInfo>>> {
        if matches!(self, Descriptor::Tr(_)) {
            Ok(match self.definite()? {
                Descriptor::Tr(tr) => Some(tr.spend_info().clone()),
                _ => unreachable!(),
            })
        } else {
            Ok(None)
        }
    }
}

// BIP32 derivation utilities

pub trait DeriveExt: Sized {
    /// Always derives when called directly on Xpubs/Xprivs, even if their wildcard modifier
    /// was not enabled. Calling directly on single keys raises an error.
    /// For Policies/Descriptors, inner xpubs with wildcards are derived (at least
    /// one is required) while non-wildcard/single inner keys are left as-is.
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self>;

    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self>;

    /// Whether there are any Xpubs/Xprivs with wildcards
    fn has_wildcards(&self) -> bool;

    /// Derive if there are wildcards. Unlike derive_path(), this is a no-op for single and non-wildcard keys
    fn maybe_derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self>
    where
        Self: Sized,
    {
        if self.has_wildcards() {
            self.derive_path(path, wildcard)
        } else {
            Ok(self)
        }
    }

    fn maybe_derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self>
    where
        Self: Sized,
    {
        if self.has_wildcards() {
            self.derive_multi(paths, wildcard)
        } else {
            Ok(self)
        }
    }
}

pub trait DerivePath: IntoDerivationPath + Clone {} // trait alias
impl<T: IntoDerivationPath + Clone> DerivePath for T {}

impl DeriveExt for DescriptorPublicKey {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        let path = path.into_derivation_path()?;
        match self {
            DescriptorPublicKey::XPub(mut xpub) => {
                xpub.derivation_path = xpub.derivation_path.extend(path);
                xpub.wildcard = wildcard;
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
                mxpub.wildcard = wildcard;
                Ok(DescriptorPublicKey::MultiXPub(mxpub))
            }
            DescriptorPublicKey::Single(_) => bail!(Error::NonDeriveableSingle),
        }
    }

    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        let paths = paths
            .iter()
            .map(|p| Ok(p.clone().into_derivation_path()?))
            .collect::<Result<Vec<_>>>()?;

        let parent_paths = self.derivation_paths();

        let derived_paths = parent_paths
            .into_iter()
            .flat_map(|parent_path| paths.iter().map(move |path| parent_path.extend(path)))
            .collect::<Vec<_>>();

        let (origin, xkey) = match self {
            DescriptorPublicKey::XPub(xpub) => (xpub.origin, xpub.xkey),
            DescriptorPublicKey::MultiXPub(mxpub) => (mxpub.origin, mxpub.xkey),
            DescriptorPublicKey::Single(_) => bail!(Error::NonDeriveableSingle),
        };
        Ok(DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin,
            xkey,
            derivation_paths: DerivPaths::new(derived_paths).expect("cannot be empty"),
            wildcard,
        }))
    }
    fn has_wildcards(&self) -> bool {
        self.has_wildcard()
    }
}

// much code duplication, so wow ^.^
impl DeriveExt for DescriptorSecretKey {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        let path = path.into_derivation_path()?;
        match self {
            DescriptorSecretKey::XPrv(mut xprv) => {
                xprv.derivation_path = xprv.derivation_path.extend(path);
                xprv.wildcard = wildcard;
                Ok(DescriptorSecretKey::XPrv(xprv))
            }
            DescriptorSecretKey::MultiXPrv(mut mxprv) => {
                mxprv.derivation_paths = DerivPaths::new(
                    mxprv
                        .derivation_paths
                        .into_paths()
                        .into_iter()
                        .map(|mx_path| mx_path.extend(&path))
                        .collect(),
                )
                .expect("path cannot be empty");
                mxprv.wildcard = wildcard;
                Ok(DescriptorSecretKey::MultiXPrv(mxprv))
            }
            DescriptorSecretKey::Single(_) => bail!(Error::NonDeriveableSingle),
        }
    }

    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        let paths = paths
            .iter()
            .map(|p| Ok(p.clone().into_derivation_path()?))
            .collect::<Result<Vec<DerivationPath>>>()?;

        let parent_paths = self.full_derivation_paths();

        let derived_paths = parent_paths
            .into_iter()
            .flat_map(|parent_path| paths.iter().map(move |path| parent_path.extend(path)))
            .collect::<Vec<_>>();

        let (origin, xkey) = match self {
            DescriptorSecretKey::XPrv(xprv) => (xprv.origin, xprv.xkey),
            DescriptorSecretKey::MultiXPrv(mxpriv) => (mxpriv.origin, mxpriv.xkey),
            DescriptorSecretKey::Single(_) => bail!(Error::NonDeriveableSingle),
        };
        Ok(DescriptorSecretKey::MultiXPrv(DescriptorMultiXKey {
            origin,
            xkey,
            derivation_paths: DerivPaths::new(derived_paths).expect("cannot be empty"),
            wildcard,
        }))
    }
    fn has_wildcards(&self) -> bool {
        match self {
            DescriptorSecretKey::Single(..) => false,
            DescriptorSecretKey::XPrv(xprv) => xprv.wildcard != Wildcard::None,
            DescriptorSecretKey::MultiXPrv(xprv) => xprv.wildcard != Wildcard::None,
        }
    }
}

impl DeriveExt for crate::PolicyDpk {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        let path = path.into_derivation_path()?;
        self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
            pk.clone().maybe_derive_path(path.clone(), wildcard)
        }))
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
            pk.clone().maybe_derive_multi(paths, wildcard)
        }))
    }
    fn has_wildcards(&self) -> bool {
        self.for_any_key(DeriveExt::has_wildcards)
    }
}

impl DeriveExt for crate::DescriptorDpk {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        let path = path.into_derivation_path()?;
        Ok(
            self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
                pk.clone().maybe_derive_path(path.clone(), wildcard)
            }))?,
        )
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        Ok(
            self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
                pk.clone().maybe_derive_multi(paths, wildcard)
            }))?,
        )
    }
    fn has_wildcards(&self) -> bool {
        self.has_wildcard()
    }
}

impl DeriveExt for Value {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        Ok(match self {
            Value::PubKey(pubkey) => pubkey.derive_path(path, wildcard)?.into(),
            Value::SecKey(seckey) => seckey.derive_path(path, wildcard)?.into(),
            Value::Descriptor(desc) => desc.derive_path(path, wildcard)?.into(),
            Value::Policy(policy) => policy.derive_path(path, wildcard)?.into(),
            Value::Array(array) => array.derive_path(path, wildcard)?.into(),
            _ => bail!(Error::NonDeriveableType),
        })
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        Ok(match self {
            Value::PubKey(pubkey) => pubkey.derive_multi(paths, wildcard)?.into(),
            Value::SecKey(seckey) => seckey.derive_multi(paths, wildcard)?.into(),
            Value::Descriptor(desc) => desc.derive_multi(paths, wildcard)?.into(),
            Value::Policy(policy) => policy.derive_multi(paths, wildcard)?.into(),
            Value::Array(array) => array.derive_multi(paths, wildcard)?.into(),
            _ => bail!(Error::NonDeriveableType),
        })
    }
    fn has_wildcards(&self) -> bool {
        match self {
            Value::PubKey(pubkey) => pubkey.has_wildcards(),
            Value::SecKey(seckey) => seckey.has_wildcards(),
            Value::Descriptor(desc) => desc.has_wildcards(),
            Value::Policy(policy) => policy.has_wildcards(),
            Value::Array(array) => array.has_wildcards(),
            _ => false,
        }
    }
}

impl DeriveExt for Array {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        Ok(Array(
            self.into_iter()
                .map(|v| v.maybe_derive_path(path.clone(), wildcard))
                .collect::<Result<_>>()?,
        ))
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        Ok(Array(
            self.into_iter()
                .map(|v| v.maybe_derive_multi(paths, wildcard))
                .collect::<Result<_>>()?,
        ))
    }
    fn has_wildcards(&self) -> bool {
        self.iter().any(DeriveExt::has_wildcards)
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
    // XXX could use miniscript::translate_hash_clone!() if is used std::result:Result or if we avoided replacing Result with a type alias
}

// Keys utilities

pub trait DescriptorPubKeyExt: Sized {
    /// Convert into a definite pubkey. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn definite(self) -> Result<DefiniteDescriptorKey>;

    /// Convert into a derived pubkey. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn derive_definite(self) -> Result<bitcoin::PublicKey> {
        Ok(self.definite()?.derive_public_key(&EC)?)
    }

    /// Convert into a derived x-only pubkey. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn derive_xonly(self) -> Result<bitcoin::XOnlyPublicKey> {
        Ok(self.derive_definite()?.inner.into())
    }

    /// Return the derivation paths from the key itself, excluding the path from the origin key (unlike full_derivation_paths())
    fn derivation_paths(&self) -> Vec<DerivationPath>;
}

impl DescriptorPubKeyExt for DescriptorPublicKey {
    fn definite(self) -> Result<DefiniteDescriptorKey> {
        ensure!(
            !self.has_wildcard(),
            Error::UnexpectedWildcardPubKey(self.clone().into())
        );
        ensure!(
            !self.is_multipath(),
            Error::UnexpectedMultiPathPubKey(self.clone().into())
        );
        Ok(self.at_derivation_index(0).expect("index is valid"))
    }

    fn derivation_paths(&self) -> Vec<DerivationPath> {
        match self {
            DescriptorPublicKey::MultiXPub(mxpub) => mxpub.derivation_paths.paths().clone(),
            DescriptorPublicKey::XPub(xpub) => vec![xpub.derivation_path.clone()],
            DescriptorPublicKey::Single(single) => {
                vec![single
                    .origin
                    .as_ref()
                    .map_or_else(DerivationPath::master, |(_, path)| path.clone())]
            }
        }
    }
}

pub trait DescriptorSecretKeyExt {
    /// Like `DescriptorPublicKey::full_derivation_paths()`, which isn't available for secret keys
    fn full_derivation_paths(&self) -> Vec<DerivationPath>;

    fn to_public_(&self) -> Result<DescriptorPublicKey>;
}
impl DescriptorSecretKeyExt for DescriptorSecretKey {
    fn full_derivation_paths(&self) -> Vec<DerivationPath> {
        match self {
            DescriptorSecretKey::MultiXPrv(xprv) => {
                let origin_path = if let Some((_, ref path)) = xprv.origin {
                    path.clone()
                } else {
                    DerivationPath::from(vec![])
                };
                xprv.derivation_paths
                    .paths()
                    .iter()
                    .map(|p| origin_path.extend(p))
                    .collect()
            }
            DescriptorSecretKey::XPrv(ref xpub) => {
                let origin_path = if let Some((_, ref path)) = xpub.origin {
                    path.clone()
                } else {
                    DerivationPath::from(vec![])
                };
                vec![origin_path.extend(&xpub.derivation_path)]
            }
            DescriptorSecretKey::Single(ref single) => {
                vec![if let Some((_, ref path)) = single.origin {
                    path.clone()
                } else {
                    DerivationPath::from(vec![])
                }]
            }
        }
    }

    fn to_public_(&self) -> Result<DescriptorPublicKey> {
        Ok(match self {
            DescriptorSecretKey::Single(_) | DescriptorSecretKey::XPrv(_) => self.to_public(&EC)?,
            DescriptorSecretKey::MultiXPrv(mxprv) => {
                DescriptorPublicKey::MultiXPub(multi_xpriv_to_public(mxprv)?)
            }
        })
    }
}

// Pending https://github.com/rust-bitcoin/rust-miniscript/pull/757
fn multi_xpriv_to_public(
    mxprv: &DescriptorMultiXKey<bip32::Xpriv>,
) -> Result<DescriptorMultiXKey<bip32::Xpub>> {
    assert!(
        !mxprv.derivation_paths.paths().is_empty(),
        "MultiXkey is never empty"
    );

    let deriv_paths = mxprv.derivation_paths.paths();

    let shared_prefix: Vec<_> = deriv_paths[0]
        .into_iter()
        .enumerate()
        .take_while(|(index, child_num)| {
            deriv_paths[1..]
                .iter()
                .all(|other_path| other_path.len() > *index && other_path[*index] == **child_num)
        })
        .map(|(_, child_num)| *child_num)
        .collect();

    let suffixes: Vec<Vec<_>> = deriv_paths
        .iter()
        .map(|path| {
            path.into_iter()
                .skip(shared_prefix.len())
                .map(|child_num| {
                    // Hardended derivation steps are only allowed within the shared prefix
                    ensure!(child_num.is_normal(), Error::InvalidHardenedMultiXprvToXpub);
                    Ok(*child_num)
                })
                .collect()
        })
        .collect::<Result<_>>()?;

    let unhardened = shared_prefix
        .iter()
        .rev()
        .take_while(|c| c.is_normal())
        .count();
    let last_hardened_idx = shared_prefix.len() - unhardened;

    let hardened_path = &shared_prefix[..last_hardened_idx];
    let unhardened_path = &shared_prefix[last_hardened_idx..];

    let xprv = mxprv.xkey.derive_priv(&EC, &hardened_path)?;
    let xpub = bip32::Xpub::from_priv(&EC, &xprv);

    let origin = match &mxprv.origin {
        Some((fingerprint, path)) => Some((
            *fingerprint,
            path.into_iter()
                .chain(hardened_path.iter())
                .copied()
                .collect(),
        )),
        None if !hardened_path.is_empty() => {
            Some((mxprv.xkey.fingerprint(&EC), hardened_path.into()))
        }
        None => None,
    };
    let new_deriv_paths = suffixes
        .into_iter()
        .map(|suffix| {
            let path = unhardened_path.iter().copied().chain(suffix);
            path.collect::<Vec<_>>().into()
        })
        .collect();

    Ok(DescriptorMultiXKey {
        origin,
        xkey: xpub,
        derivation_paths: DerivPaths::new(new_deriv_paths).expect("not empty"),
        wildcard: mxprv.wildcard,
    })
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

pub fn fmt_quoted_str<W: fmt::Write>(f: &mut W, str: &str) -> fmt::Result {
    write!(f, "\"")?;
    for char in str.chars() {
        match char {
            '\r' => write!(f, "\\r")?,
            '\n' => write!(f, "\\n")?,
            '\t' => write!(f, "\\t")?,
            '"' => write!(f, "\\\"")?,
            _ => write!(f, "{}", char)?,
        };
    }
    write!(f, "\"")
}

pub fn quote_str(s: &str) -> String {
    let mut quoted = String::with_capacity(s.len());
    fmt_quoted_str(&mut quoted, s).unwrap();
    quoted
}

/// A Write wrapper that allows up the `limit` bytes to be written through it to the inner `writer`.
/// If the limit is reached, an fmt::Error is raised. This is used as an optimization by PrettyDisplay.
pub struct LimitedWriter<'a, W: fmt::Write + ?Sized> {
    writer: &'a mut W,
    limit: usize,
    total: usize,
}
impl<'a, W: fmt::Write + ?Sized> LimitedWriter<'a, W> {
    pub fn new(writer: &'a mut W, limit: usize) -> Self {
        LimitedWriter {
            writer,
            limit,
            total: 0,
        }
    }
}
impl<W: fmt::Write + ?Sized> fmt::Write for LimitedWriter<'_, W> {
    fn write_str(&mut self, buf: &str) -> fmt::Result {
        self.total += buf.len();
        if self.total > self.limit {
            Err(fmt::Error)
        } else {
            self.writer.write_str(buf)
        }
    }
}

pub trait PeekableExt: Iterator {
    /// Like take_while(), but borrows checked items and doesn't consume the last non-matching one
    /// Similarly to https://docs.rs/itertools/latest/itertools/trait.Itertools.html#method.peeking_take_while
    fn peeking_take_while<F>(&mut self, accept: F) -> impl Iterator<Item = Self::Item>
    where
        F: FnMut(&Self::Item) -> bool + Copy;
}

impl<I: Iterator> PeekableExt for iter::Peekable<I> {
    fn peeking_take_while<F>(&mut self, accept: F) -> impl Iterator<Item = Self::Item>
    where
        F: FnMut(&Self::Item) -> bool + Copy,
    {
        // h/t https://www.reddit.com/r/rust/comments/f8ae6q/comment/jwuyzgo/
        iter::from_fn(move || self.next_if(accept))
    }
}

/// Display-like with custom formatting options, newlines/indentation handling and the ability to implement on foreign types
pub trait PrettyDisplay: Sized {
    const AUTOFMT_ENABLED: bool;
    const MAX_ONELINER_LENGTH: usize = 125;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result;

    /// Use multi-line indented formatting for long lines ove MAX_ONELINER_LENGTH,
    /// or the one-liner formatting otherwise
    fn auto_fmt<W: fmt::Write>(&self, w: &mut W, indent: Option<usize>) -> fmt::Result {
        if !Self::AUTOFMT_ENABLED || indent.is_none() || self.prefer_multiline_anyway() {
            return self.pretty_fmt(w, indent);
        }

        // Try formatting into a buffer with no newlines first, to determine whether it exceeds the length limit.
        // The LimitedWriter will reject writes once the limit is reached, terminating the process midway through.
        let mut one_liner = String::new();
        let mut lwriter = LimitedWriter::new(&mut one_liner, Self::MAX_ONELINER_LENGTH);
        if self.pretty_fmt(&mut lwriter, None).is_ok() {
            // Fits in MAX_ONELINER_LIMIT, forward the buffered string to the outer `w` formatter
            write!(w, "{}", one_liner)
        } else {
            // The one-liner was too long, use multi-line formatting with indentation instead
            self.pretty_fmt(w, indent)
        }
    }

    /// Don't try fitting into a one-liner if this test passes
    fn prefer_multiline_anyway(&self) -> bool {
        false
    }

    /// Get back a Display-able struct with pretty-formatting
    fn pretty(&self, indent: Option<usize>) -> PrettyDisplayer<Self> {
        PrettyDisplayer {
            inner: self,
            indent,
        }
    }
    fn pretty_multiline(&self) -> PrettyDisplayer<Self> {
        self.pretty(Some(0))
    }

    fn pretty_str(&self) -> String {
        self.pretty(None).to_string()
    }
    fn multiline_str(&self) -> String {
        self.pretty_multiline().to_string()
    }
}

/// A wrapper type implementing Display over PrettyDisplay::auto_fmt()
#[derive(Debug)]
pub struct PrettyDisplayer<'a, T: PrettyDisplay> {
    inner: &'a T,
    /// Setting this implies enabling new-lines
    indent: Option<usize>,
}
impl<'a, T: PrettyDisplay> fmt::Display for PrettyDisplayer<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.auto_fmt(f, self.indent)
    }
}

pub const LIST_INDENT_WIDTH: usize = 2;

pub fn fmt_list<T, F, W, I>(w: &mut W, iter: I, indent: Option<usize>, func: F) -> fmt::Result
where
    W: fmt::Write,
    I: Iterator<Item = T>,
    F: Fn(&mut W, T, Option<usize>) -> fmt::Result,
{
    let (newline_or_space, inner_indent, indent_w, inner_indent_w) = indentation_params(indent);

    write!(w, "[")?;
    for (i, item) in iter.enumerate() {
        if i > 0 {
            write!(w, ",")?;
        }
        write!(w, "{newline_or_space}{:inner_indent_w$}", "")?;
        func(w, item, inner_indent)?;
    }
    write!(w, "{newline_or_space}{:indent_w$}]", "")
}

impl<T: PrettyDisplay> PrettyDisplay for Vec<T> {
    const AUTOFMT_ENABLED: bool = true;
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        fmt_list(f, self.iter(), indent, |f, el, inner_indent| {
            write!(f, "{}", el.pretty(inner_indent))
        })
    }
}

impl_simple_pretty!(Vec<u8>, bytes, "0x{}", bytes.as_hex());

pub fn indentation_params(indent: Option<usize>) -> (&'static str, Option<usize>, usize, usize) {
    let newline_or_space = iif!(indent.is_some(), "\n", " ");
    let inner_indent = indent.map(|n| n + 1);
    let indent_w = indent.map_or(0, |n| n * LIST_INDENT_WIDTH);
    let inner_indent_w = inner_indent.map_or(0, |n| n * LIST_INDENT_WIDTH);

    (newline_or_space, inner_indent, indent_w, inner_indent_w)
}
