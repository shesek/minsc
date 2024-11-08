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
use crate::runtime::{Array, Error, Evaluate, Mutable, Result, ScopeRef, Value};
use crate::util::{
    hash_to_child_vec, DeriveExt, DescriptorPubKeyExt, DescriptorSecretKeyExt, PrettyDisplay, EC,
};
use crate::PolicyDpk as Policy;

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();
    scope.set_fn("pubkey", fns::pubkey).unwrap();
    scope.set_fn("seckey", fns::seckey).unwrap();

    scope.set_fn("xpriv::rand", fns::xpriv_rand).unwrap();
    scope
        .set_fn("xpriv::from_seed", fns::xpriv_from_seed)
        .unwrap();

    scope.set_fn("xonly", fns::xonly).unwrap();

    scope.set_fn("singles", fns::singles).unwrap();
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

    /// Generate a new random Xpriv from a 256-bit seed
    /// xpriv::rand(Network = testnet) -> SecKey
    pub fn xpriv_rand(args: Array, _: &ScopeRef) -> Result<Value> {
        let network = args
            .arg_into::<Option<Network>>()?
            .unwrap_or(Network::Testnet);
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

    /// Convert the pubkey into an x-only pubkey.
    /// Always returned as a single (non-xpub) pubkey (x-only xpubs cannot be represented as an Xpub/DescriptorPublicKey).
    ///
    /// xonly(PubKey) -> PubKey
    pub fn xonly(args: Array, _: &ScopeRef) -> Result<Value> {
        let pk: DescriptorPublicKey = args.arg_into()?;

        Ok(if pk.is_x_only_key() {
            pk
        } else {
            // Convert into an x-only single pubkey with BIP32 origin information
            let pk = pk.definite()?;
            let derived_single_pk = pk.derive_public_key(&EC)?;
            let derived_path = pk.full_derivation_path().ok_or(Error::InvalidMultiXpub)?;

            DescriptorPublicKey::Single(SinglePub {
                key: SinglePubKey::XOnly(derived_single_pk.into()),
                origin: Some((pk.master_fingerprint(), derived_path)),
            })
        }
        .into())
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
            Value::PubKey(ref dpk) => match dpk {
                // For xpubs, get the fingerprint of the final derivation key (not the master_fingerprint()'s)
                DescriptorPublicKey::XPub(_) => Xpub::try_from(val)?.fingerprint(),
                // For single keys the master_fingerprint() is the same as the final fingerprint
                DescriptorPublicKey::Single(_) => dpk.master_fingerprint(),
                DescriptorPublicKey::MultiXPub(_) => bail!(Error::InvalidMultiXpub),
            },
            // Convert SecKey to PubKey, then get its Fingerprint
            Value::SecKey(sk) => Value::PubKey(sk.to_public_()?).try_into()?,
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

// Display

impl PrettyDisplay for DescriptorPublicKey {
    const AUTOFMT_ENABLED: bool = false;
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        use DescriptorPublicKey::{MultiXPub, Single, XPub};
        match self {
            XPub(_) | MultiXPub(_) => write!(f, "{}", self),
            // Wrap hex-encoded single pubkeys with a pubkey() call, so that the resulting string
            // may be used as an expression that produces a PubKey rather than Bytes.
            Single(_) => write!(f, "pubkey({})", self),
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
