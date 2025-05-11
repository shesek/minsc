use std::convert::{TryFrom, TryInto};
use std::fmt;

use bitcoin::bip32::{self, ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{PublicKey, TweakedPublicKey, XOnlyPublicKey};
use bitcoin::secp256k1::rand::{thread_rng, Rng};
use bitcoin::{secp256k1, Network};
use miniscript::descriptor::{
    self, DescriptorPublicKey, DescriptorSecretKey, DescriptorXKey, SinglePriv, SinglePub,
    SinglePubKey, Wildcard,
};

use crate::ast::SlashRhs;
use crate::display::PrettyDisplay;
use crate::runtime::{Array, Error, Evaluate, FieldAccess, Mutable, Result, ScopeRef, Value};
use crate::util::{DeriveExt, DescriptorPubKeyExt, DescriptorSecretKeyExt, EC};
use crate::PolicyDpk as Policy;

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();
    scope.set_fn("pubkey", fns::pubkey).unwrap();
    scope.set_fn("seckey", fns::seckey).unwrap();
    scope.set_fn("seckey::rand", fns::seckey_rand).unwrap();
    scope.set_fn("xpriv::rand", fns::xpriv_rand).unwrap();
    scope
        .set_fn("xpriv::from_seed", fns::xpriv_from_seed)
        .unwrap();
    scope.set_fn("singles", fns::singles).unwrap();
    scope.set_fn("xonly", fns::xonly).unwrap(); // xonly is always derived  single
    scope.set_fn("derived", fns::derived).unwrap();
    scope.set_fn("xderived", fns::xderived).unwrap();
}

/// BIP32 key derivation using the Slash operator
pub fn eval_slash_bip32_derive(lhs: Value, rhs: &SlashRhs, scope: &ScopeRef) -> Result<Value> {
    match rhs {
        // RHS used for child key derivation with a child code number, hash or multi-path array
        SlashRhs::Expr(rhs_expr) | SlashRhs::HardenedDerivation(rhs_expr) => {
            let is_hardened = matches!(rhs, SlashRhs::HardenedDerivation(_));

            let derivation_path = |child_num| {
                // Create a DerivationPath with `child_num` as its single derivation step
                let child_num = if is_hardened {
                    ChildNumber::from_hardened_idx(child_num)?
                } else {
                    ChildNumber::from_normal_idx(child_num)?
                };
                Ok(DerivationPath::from(&[child_num][..]))
            };

            match rhs_expr.eval(scope)? {
                // Derive with a BIP 32 child code index number
                Value::Number(child_num) => {
                    lhs.derive_path(derivation_path(child_num.into_u32()?)?, Wildcard::None)
                }

                // Derive with a hash converted into a series of BIP32 non-hardened derivations using Sapio's hash_to_child_vec()
                Value::Bytes(bytes) => {
                    ensure!(!is_hardened, Error::InvalidArguments);
                    let hash = sha256::Hash::from_slice(&bytes)?;
                    lhs.derive_path(hash_to_child_vec(hash), Wildcard::None)
                }

                // Derive a BIP389 Multipath descriptor
                Value::Array(child_nums) => {
                    let child_paths = child_nums
                        .into_iter()
                        .map(|num| derivation_path(num.into_u32()?))
                        .collect::<Result<Vec<_>>>()?;

                    lhs.derive_multi(&child_paths, Wildcard::None)
                }

                _ => bail!(Error::InvalidDerivationCode),
            }
        }

        // RHS used to update wildcard modifier (*, *' and *h)
        SlashRhs::HardenedWildcard => lhs.derive_path(&[][..], Wildcard::Hardened),
        SlashRhs::UnhardenedWildcard => lhs.derive_path(&[][..], Wildcard::Unhardened),
    }
}

pub mod fns {
    use super::*;
    use miniscript::MiniscriptKey;

    /// Cast SecKey/Bytes into a PubKey
    /// pubkey(SecKey|Bytes|PubKey) -> PubKey
    pub fn pubkey(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::PubKey(args.arg_into()?))
    }

    /// seckey(Bytes|SecKey) -> SecKey
    pub fn seckey(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::SecKey(args.arg_into()?))
    }

    /// Generate a new random single SecKey
    /// seckey::rand(Network = testnet) -> SecKey<SingleKey>
    pub fn seckey_rand(args: Array, _: &ScopeRef) -> Result<Value> {
        let network = args.arg_into::<Option<_>>()?.unwrap_or(Network::Testnet);
        Ok(bitcoin::PrivateKey::generate(network).into())
    }

    /// Generate a new random Xpriv from a 256-bit seed
    /// xpriv::rand(Network = testnet) -> SecKey<Xpriv>
    pub fn xpriv_rand(args: Array, _: &ScopeRef) -> Result<Value> {
        let network = args.arg_into::<Option<_>>()?.unwrap_or(Network::Testnet);
        let seed: [u8; 32] = thread_rng().gen();
        Ok(Xpriv::new_master(network, &seed).unwrap().into())
    }

    /// Construct a master Xpriv from a seed value
    /// xpriv::from_seed(Bytes, Network = testnet) -> SecKey
    pub fn xpriv_from_seed(args: Array, _: &ScopeRef) -> Result<Value> {
        let (seed, network): (Vec<u8>, Option<_>) = args.args_into()?;
        let network = network.unwrap_or(Network::Testnet);
        Ok(Xpriv::new_master(network, &seed)?.into())
    }

    /// Convert a multi-path PubKey/SecKey/Descriptor into an array of singles
    ///
    /// singles(PubKey<Multi>|SecKey<Multi>|Descriptor<Multi>) -> Array<PubKey|SecKey|Descriptor>
    pub fn singles(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::PubKey(pk) => pk.into_single_keys().into(),
            Value::SecKey(sk) => sk.into_single_keys().into(),
            Value::Descriptor(desc) => desc.into_single_descriptors()?.into(),
            other => bail!(Error::InvalidValue(other.into())),
        })
    }

    /// Convert the pubkey into an x-only pubkey.
    /// Always returned as a single (non-Xpub) pubkey (x-only keys cannot be represented as a DescriptorPublicKey::XPub).
    ///
    /// xonly(PubKey<Xpub|Single>) -> PubKey<Single>
    pub fn xonly(args: Array, _: &ScopeRef) -> Result<Value> {
        let pk: DescriptorPublicKey = args.arg_into()?;

        Ok(if pk.is_x_only_key() {
            pk
        } else {
            let full_path = pk.full_derivation_path().ok_or(Error::InvalidMultiXpub)?;
            let master_fp = pk.master_fingerprint();
            let derived_pk = pk.derive_definite()?;

            DescriptorPublicKey::Single(SinglePub {
                key: SinglePubKey::XOnly(derived_pk.into()),
                origin: Some((master_fp, full_path)),
            })
        }
        .into())
    }

    /// Apply Xpub/Xpriv derivation steps to arrive at the final child as a single key
    ///
    /// derived(PubKey<Xpub>) -> PubKey<Single>
    /// derived(SecKey<Xpriv>) -> SecKey<Single>
    pub fn derived(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            // Derive Xpubs
            Value::PubKey(ref pk @ DescriptorPublicKey::XPub(ref xpub)) => {
                let derived_pk = xpub.xkey.derive_pub(&EC, &xpub.derivation_path)?.public_key;
                let full_path = pk
                    .full_derivation_path()
                    .expect("must exists for DPK::Xpub");
                DescriptorPublicKey::Single(SinglePub {
                    key: SinglePubKey::FullKey(derived_pk.into()),
                    origin: Some((pk.master_fingerprint(), full_path)),
                })
                .into()
            }
            // Derive Xprivs
            Value::SecKey(ref sk @ DescriptorSecretKey::XPrv(ref xpriv)) => {
                let derived_sk = xpriv
                    .xkey
                    .derive_priv(&EC, &xpriv.derivation_path)?
                    .private_key;
                let full_path = sk
                    .full_derivation_path()
                    .expect("must exists for DPK::Xprv");
                DescriptorSecretKey::Single(SinglePriv {
                    key: bitcoin::PrivateKey::new(derived_sk, Network::Testnet), // XXX always uses Testnet
                    origin: Some((sk.master_fingerprint(), full_path)),
                })
                .into()
            }
            // Return Single keys as-is
            single @ Value::PubKey(DescriptorPublicKey::Single(_))
            | single @ Value::SecKey(DescriptorSecretKey::Single(_)) => single,

            other => bail!(Error::InvalidValue(other.into())),
        })
    }

    /// Apply Xpub/Xpriv derivation steps to arrive at the final child Xpub/Xpriv
    ///
    /// xderived(PubKey<Xpub>) -> PubKey<Xpub>
    /// xderived(SecKey<Xpriv>) -> SecKey<Xpriv>
    pub fn xderived(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            // Derive Xpubs
            Value::PubKey(ref pk @ DescriptorPublicKey::XPub(ref xpub)) => {
                let derived_xpub = xpub.xkey.derive_pub(&EC, &xpub.derivation_path)?;
                let full_path = pk
                    .full_derivation_path()
                    .expect("must exists for DPK::Xpub");
                DescriptorPublicKey::XPub(DescriptorXKey {
                    xkey: derived_xpub,
                    derivation_path: DerivationPath::master(),
                    wildcard: xpub.wildcard,
                    origin: Some((pk.master_fingerprint(), full_path)),
                })
                .into()
            }
            // Derive Xprivs
            Value::SecKey(ref sk @ DescriptorSecretKey::XPrv(ref xprv)) => {
                let derived_xpriv = xprv.xkey.derive_priv(&EC, &xprv.derivation_path)?;
                let full_path = sk
                    .full_derivation_path()
                    .expect("must exists for DPK::Xprv");
                DescriptorSecretKey::XPrv(DescriptorXKey {
                    xkey: derived_xpriv,
                    derivation_path: DerivationPath::master(),
                    wildcard: xprv.wildcard,
                    origin: Some((sk.master_fingerprint(), full_path)),
                })
                .into()
            }
            other => bail!(Error::InvalidValue(other.into())),
        })
    }
}

// Field getters

impl FieldAccess for DescriptorPublicKey {
    fn get_field(self, field: &Value) -> Option<Value> {
        use {DescriptorPublicKey::*, SinglePubKey::XOnly};

        Some(match field.as_str()? {
            "master_fingerprint" => self.master_fingerprint().into(),

            // Only available for definite keys
            "fingerprint" => self.fingerprint().ok()?.into(),
            // Not available for multi-path keys
            "full_derivation_path" => self.full_derivation_path()?.into(),
            // Available for all keys
            "full_derivation_paths" => self.full_derivation_paths().into(),

            "is_xpub" => matches!(self, XPub(_) | MultiXPub(_)).into(),
            "is_single_key" => matches!(self, Single(_)).into(),
            "is_xonly" => matches!(self, Single(SinglePub { key: XOnly(_), .. })).into(),

            "is_wildcard" => self.has_wildcard().into(),
            "is_multipath" => self.is_multipath().into(),
            "is_definite" => (!self.has_wildcard() && !self.is_multipath()).into(),
            _ => {
                return None;
            }
        })
    }
}

impl FieldAccess for DescriptorSecretKey {
    fn get_field(self, field: &Value) -> Option<Value> {
        use DescriptorSecretKey::*;

        Some(match field.as_str()? {
            "master_fingerprint" => self.master_fingerprint().into(),
            "pubkey" => self.to_public_().ok()?.into(),

            // only available for definite keys
            "fingerprint" => self.to_public_().ok()?.fingerprint().ok()?.into(),
            // not available for multi-path keys
            "full_derivation_path" => self.full_derivation_path()?.into(),
            // available for all keys
            "full_derivation_paths" => self.full_derivation_paths().into(),

            "is_xpriv" => matches!(self, XPrv(_) | MultiXPrv(_)).into(),
            "is_single_key" => matches!(self, Single(_)).into(),

            "is_wildcard" => self.has_wildcards().into(),
            "is_multipath" => self.is_multipath().into(),
            "is_definite" => (!self.has_wildcards() && !self.is_multipath()).into(),
            _ => {
                return None;
            }
        })
    }
}

// Convert from bitcoin/secp256k1 keys to Value

impl_simple_to_value!(
    bitcoin::PublicKey,
    pk,
    DescriptorPublicKey::Single(SinglePub {
        key: SinglePubKey::FullKey(pk),
        origin: None,
    })
);
impl_simple_to_value!(
    XOnlyPublicKey,
    pk,
    DescriptorPublicKey::Single(SinglePub {
        key: SinglePubKey::XOnly(pk),
        origin: None,
    })
);
impl_simple_to_value!(TweakedPublicKey, pk, pk.to_inner());
impl_simple_to_value!(secp256k1::PublicKey, pk, bitcoin::PublicKey::from(pk));
impl_simple_to_value!(secp256k1::Parity, p, p.to_u8() as i64);
impl_simple_to_value!(
    Xpub,
    xpub,
    DescriptorPublicKey::XPub(DescriptorXKey {
        xkey: xpub,
        derivation_path: DerivationPath::master(),
        wildcard: descriptor::Wildcard::None,
        origin: if xpub.depth > 0 {
            Some((xpub.parent_fingerprint, [xpub.child_number][..].into()))
        } else {
            None
        },
    })
);
impl_simple_to_value!(
    bitcoin::PrivateKey,
    key,
    DescriptorSecretKey::Single(SinglePriv { key, origin: None })
);
impl_simple_to_value!(
    Xpriv,
    xprv,
    DescriptorSecretKey::XPrv(DescriptorXKey {
        xkey: xprv,
        derivation_path: DerivationPath::master(),
        wildcard: descriptor::Wildcard::None,
        origin: if xprv.depth > 0 {
            Some((xprv.parent_fingerprint, [xprv.child_number][..].into()))
        } else {
            None
        },
    })
);
impl_simple_to_value!(bip32::Fingerprint, fp, fp.to_bytes().to_vec());
impl_simple_to_value!(bip32::ChildNumber, cn, u32::from(cn));
impl_simple_to_value!(
    bip32::DerivationPath,
    path,
    path.into_iter().copied().collect::<Array>()
);

// Convert from Value to bitcoin/secp256k1 keys

impl TryFrom<Value> for secp256k1::SecretKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value.try_into()? {
            DescriptorSecretKey::Single(single_priv) => single_priv.key.inner,
            DescriptorSecretKey::XPrv(xprv) => {
                // TODO ensure no wildcards, similarly to DescriptorPubKeyExt::definite()
                xprv.xkey
                    .derive_priv(&EC, &xprv.derivation_path)?
                    .private_key
            }
            DescriptorSecretKey::MultiXPrv(_) => bail!(Error::InvalidMultiXprv),
        })
    }
}

impl TryFrom<Value> for secp256k1::PublicKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(bitcoin::PublicKey::try_from(val)?.inner)
    }
}

impl TryFrom<Value> for secp256k1::Keypair {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(secp256k1::SecretKey::try_from(value)?.keypair(&EC))
    }
}

impl TryFrom<Value> for bitcoin::PublicKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        DescriptorPublicKey::try_from(val)?.derive_definite()
    }
}

impl TryFrom<Value> for bitcoin::PrivateKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        // XXX always uses Testnet
        Ok(Self::new(val.try_into()?, Network::Testnet))
    }
}

impl TryFrom<Value> for DescriptorPublicKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::PubKey(pubkey) => pubkey,
            Value::SecKey(seckey) => seckey.to_public_()?,
            // Bytes are coerced into a single PubKey if they are 33 or 32 bytes long,
            // or to an Xpub if they're 78 bytes long
            Value::Bytes(bytes) => match bytes.len() {
                33 | 32 => DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: match bytes.len() {
                        33 => SinglePubKey::FullKey(PublicKey::from_slice(&bytes)?),
                        32 => SinglePubKey::XOnly(XOnlyPublicKey::from_slice(&bytes)?),
                        _ => unreachable!(),
                    },
                }),
                78 => Value::from(Xpub::decode(&bytes)?).try_into()?,
                len => bail!(Error::InvalidPubKeyLen(len)),
            },
            // A specialized error for misusing pk() policies as pubkeys
            Value::Policy(Policy::Key(_)) => {
                bail!(Error::UnexpectedPubKeyPolicy)
            }
            v => bail!(Error::NotPubKey(v.into())),
        })
    }
}

impl TryFrom<Value> for DescriptorSecretKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::SecKey(seckey) => Ok(seckey),
            Value::Bytes(bytes) => Ok(match bytes.len() {
                32 => DescriptorSecretKey::Single(SinglePriv {
                    // XXX not fully round-trip-able - the (un)compressed flag is lost (bitcoin::PrivateKey::to_bytes()
                    // does not encode it and PrivateKey::from_slice() always constructs compressed keys) and the
                    // network is always set to Testnet.
                    key: bitcoin::PrivateKey::from_slice(&bytes, Network::Testnet)?,
                    origin: None,
                }),
                78 => Value::from(Xpriv::decode(&bytes)?).try_into()?,
                len => bail!(Error::InvalidSecKeyLen(len)),
            }),
            v => Err(Error::NotSecKey(v.into())),
        }
    }
}

impl TryFrom<Value> for Xpub {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val.try_into()? {
            DescriptorPublicKey::XPub(dxpub) => {
                dxpub.xkey.derive_pub(&EC, &dxpub.derivation_path)?
            }
            other => bail!(Error::NotSingleXpub(other.into())),
        })
    }
}
impl TryFrom<Value> for Xpriv {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val.try_into()? {
            DescriptorSecretKey::XPrv(dxprv) => {
                dxprv.xkey.derive_priv(&EC, &dxprv.derivation_path)?
            }
            other => bail!(Error::NotSingleXpriv(other.into())),
        })
    }
}

/// Type wrapper for converting into the top-most master Xpriv that the DescriptorSecretKey points to,
/// without applying derivation steps like the Xpriv conversion (above). Also unlike it, this works
/// with multi-Xprivs too since all paths point to the same parent key.
#[derive(Debug, Clone)]
pub struct MasterXpriv(pub Xpriv);
impl TryFrom<Value> for MasterXpriv {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Self(match val.try_into()? {
            DescriptorSecretKey::XPrv(xprv) => xprv.xkey,
            DescriptorSecretKey::MultiXPrv(xprv) => xprv.xkey,
            sk @ DescriptorSecretKey::Single(_) => bail!(Error::NotXpriv(sk.into())),
        }))
    }
}

// Convert from Value to BIP32 types

impl TryFrom<Value> for bip32::Fingerprint {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val {
            Value::Bytes(ref bytes) => match bytes.len() {
                // Use 4 bytes long values as an explicit BIP32 fingerprint
                4 => bytes.as_slice().try_into()?,
                // Convert 32/33/78 bytes (ecdsa/xonly/xpub) into a PubKey first, then get their fingerprint
                32 | 33 | 78 => Value::PubKey(val.try_into()?).try_into()?,
                _ => bail!(Error::NotFingerprintLike(val.into())),
            },
            Value::PubKey(ref dpk) => dpk.fingerprint()?,
            // Convert SecKey to PubKey, then get its Fingerprint
            Value::SecKey(sk) => sk.to_public_()?.fingerprint()?,
            other => bail!(Error::NotFingerprintLike(other.into())),
        })
    }
}
impl TryFrom<Value> for DerivationPath {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(val.into_vec_of::<ChildNumber>()?.into())
    }
}
impl TryFrom<Value> for ChildNumber {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(val.into_u32()?.into())
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
fn hash_to_child_vec(h: sha256::Hash) -> Vec<ChildNumber> {
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

// Display

impl PrettyDisplay for DescriptorPublicKey {
    const AUTOFMT_ENABLED: bool = false;
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        use DescriptorPublicKey::{MultiXPub, Single, XPub};
        match self {
            XPub(_) | MultiXPub(_) => write!(f, "{}", self),
            // Wrap origin-less single pubkeys with a pubkey() call, so that the resulting string
            // may be used as an expression that produces a PubKey rather than Bytes
            Single(s) if s.origin.is_none() => write!(f, "pubkey({})", self),
            // When there is an origin, it can be detected as a PubKey at the parse stage
            // without an explicit pubkey()
            Single(_) => write!(f, "{}", self), // [aa00bb44/7/1'/0]0308f5d3c1...
        }
    }
}
impl PrettyDisplay for DescriptorSecretKey {
    const AUTOFMT_ENABLED: bool = false;
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        use DescriptorSecretKey::{MultiXPrv, Single, XPrv};
        match self {
            XPrv(_) | MultiXPrv(_) => write!(f, "{}", self),
            // Wrap WIF-encoded single secret keys with a seckey() call, for improved readability.
            // (the WIF string alone would also produce a SecKey, but is not easily recognizable.)
            Single(_) => write!(f, "seckey({})", self),
        }
    }
}
