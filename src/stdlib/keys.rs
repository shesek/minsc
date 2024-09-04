use std::convert::{TryFrom, TryInto};
use std::fmt;

use bitcoin::bip32::{self, ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{PublicKey, TweakedPublicKey, XOnlyPublicKey};
use bitcoin::secp256k1::rand::{thread_rng, Rng};
use bitcoin::{secp256k1, Network};
use miniscript::descriptor::{
    self, DescriptorPublicKey, DescriptorSecretKey, DescriptorXKey, SinglePriv,
    SinglePub, SinglePubKey,
};

use crate::ast;
use crate::runtime::scope::{Mutable, ScopeRef};
use crate::runtime::{Array, Error, Evaluate, Float, Int, Result, Value};
use crate::util::{self, DeriveExt, PrettyDisplay, EC};

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();

    scope.set_fn("pubkey", fns::pubkey).unwrap();
    scope.set_fn("seckey", fns::seckey).unwrap();
    scope.set_fn("genkey", fns::genkey).unwrap();
}

impl Evaluate for ast::ChildDerive {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let mut node = self.parent.eval(scope)?;

        // The `/` operator is overloaded for both BIP32 key derivation and number division, depending on the operands.
        // not the most elegant implementation, should ideally be refactored as an InfixOp.
        if node.is_number() {
            ensure!(!self.is_wildcard, Error::InvalidArguments);
            let mut result = node.into_number()?;
            for num in &self.path {
                result = match (result, num.eval(scope)?.into_number()?) {
                    (Int(a), Int(b)) => Int(a.checked_div(b).ok_or(Error::Overflow)?),
                    (Float(a), Float(b)) => Float(a / b),
                    (a, b) => bail!(Error::InfixOpMixedNum(
                        Box::new(a.into()),
                        Box::new(b.into())
                    )),
                };
            }
            return Ok(Value::Number(result));
        }

        for derivation_step in &self.path {
            node = match derivation_step.eval(scope)? {
                // Derive with a BIP 32 child code index number
                Value::Number(child_num) => {
                    let child_num = ChildNumber::from_normal_idx(child_num.into_u32()?)?;
                    node.derive_path(&[child_num][..], self.is_wildcard)?
                }

                // Derive with a hash converted into a series of BIP32 non-hardened derivations using hash_to_child_vec()
                Value::Bytes(bytes) => {
                    let hash = sha256::Hash::from_slice(&bytes)?;
                    node.derive_path(util::hash_to_child_vec(hash), self.is_wildcard)?
                }

                // Derive a BIP389 Multipath descriptor
                Value::Array(child_nums) => {
                    let child_paths = child_nums
                        .into_iter()
                        .map(|c| {
                            // XXX this doesn't support hashes
                            let child_num = ChildNumber::from_normal_idx(c.into_u32()?)?;
                            Ok(DerivationPath::from(&[child_num][..]))
                        })
                        .collect::<Result<Vec<_>>>()?;

                    node.derive_multi(&child_paths, self.is_wildcard)?
                }

                _ => bail!(Error::InvalidDerivationCode),
            }
        }
        if self.path.is_empty() {
            // If there was no path, derive once with an empty path so that is_wildcard is set.
            node = node.derive_path(&[][..], self.is_wildcard)?;
        }
        Ok(node)
    }
}

pub mod fns {
    use super::*;

    /// Cast SecKey/Bytes into a PubKey
    /// pubkey(SecKey|Bytes|PubKey) -> PubKey
    pub fn pubkey(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::PubKey(args.arg_into()?))
    }

    /// seckey(Bytes|SecKey) -> SecKey
    pub fn seckey(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::SecKey(args.arg_into()?))
    }

    /// Generate a new random Xpriv
    /// genkey(Network = Signet) -> SecKey
    pub fn genkey(args: Array, _: &ScopeRef) -> Result<Value> {
        let network = args
            .arg_into::<Option<Network>>()?
            .unwrap_or(Network::Signet);
        let seed: [u8; 32] = thread_rng().gen();

        Ok(Xpriv::new_master(network, &seed).unwrap().into())
    }
}

// Convert from bitcoin/secp256k1 keys to Value

impl From<XOnlyPublicKey> for Value {
    fn from(pk: XOnlyPublicKey) -> Self {
        Value::PubKey(DescriptorPublicKey::Single(SinglePub {
            key: SinglePubKey::XOnly(pk),
            origin: None,
        }))
    }
}
impl From<TweakedPublicKey> for Value {
    fn from(pk: TweakedPublicKey) -> Self {
        pk.to_inner().into()
    }
}

impl From<bitcoin::PublicKey> for Value {
    fn from(pk: bitcoin::PublicKey) -> Self {
        Value::PubKey(DescriptorPublicKey::Single(SinglePub {
            key: SinglePubKey::FullKey(pk),
            origin: None,
        }))
    }
}

impl From<Xpub> for Value {
    fn from(xpub: Xpub) -> Self {
        Value::PubKey(DescriptorPublicKey::XPub(DescriptorXKey {
            xkey: xpub,
            derivation_path: DerivationPath::master(),
            wildcard: descriptor::Wildcard::None,
            origin: if xpub.depth > 0 {
                Some((xpub.parent_fingerprint, [xpub.child_number][..].into()))
            } else {
                None
            },
        }))
    }
}

impl From<Xpriv> for Value {
    fn from(xprv: Xpriv) -> Self {
        Value::SecKey(DescriptorSecretKey::XPrv(DescriptorXKey {
            xkey: xprv,
            derivation_path: DerivationPath::master(),
            wildcard: descriptor::Wildcard::None,
            origin: if xprv.depth > 0 {
                Some((xprv.parent_fingerprint, [xprv.child_number][..].into()))
            } else {
                None
            },
        }))
    }
}

// Convert from Value to bitcoin/secp256k1 keys

impl TryFrom<Value> for secp256k1::SecretKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value.try_into()? {
            DescriptorSecretKey::Single(single_priv) => single_priv.key.inner,
            DescriptorSecretKey::XPrv(xprv) => {
                // TODO derive wildcards (similarly to pubkeys via at_derivation_index)
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

impl TryFrom<Value> for DescriptorPublicKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::PubKey(pubkey) => Ok(pubkey),
            Value::SecKey(seckey) => Ok(seckey.to_public(&EC)?),
            // Bytes are coerced into a single PubKey if they are 33 or 32 bytes long,
            // or to an Xpub if they're 78 bytes long
            Value::Bytes(bytes) => Ok(match bytes.len() {
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
            }),
            v => Err(Error::NotPubKey(v.into())),
        }
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
                    // network is always set to Signet.
                    key: bitcoin::PrivateKey::from_slice(&bytes, Network::Signet)?,
                    origin: None,
                }),
                78 => Value::from(Xpriv::decode(&bytes)?).try_into()?,
                len => bail!(Error::InvalidSecKeyLen(len)),
            }),
            v => Err(Error::NotSecKey(v.into())),
        }
    }
}

impl TryFrom<Value> for bitcoin::PublicKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(DescriptorPublicKey::try_from(val)?
            .at_derivation_index(0)?
            .derive_public_key(&EC)?)
    }
}

impl TryFrom<Value> for bitcoin::PrivateKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        // XXX always uses Signet
        Ok(Self::new(val.try_into()?, Network::Signet))
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

// Convert from Value to BIP32 fingerprint/path types

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
            Value::SecKey(_) => Value::PubKey(val.try_into()?).try_into()?,
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

impl PrettyDisplay for miniscript::DescriptorPublicKey {
    const AUTOFMT_ENABLED: bool = false;
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        use miniscript::DescriptorPublicKey::{MultiXPub, Single, XPub};
        match self {
            XPub(_) | MultiXPub(_) => write!(f, "{}", self),
            Single(_) => write!(f, "pubkey({})", self),
        }
    }
}