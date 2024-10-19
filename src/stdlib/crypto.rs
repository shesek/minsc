use std::convert::TryFrom;

use bitcoin::hashes::{self, Hash};
use bitcoin::secp256k1::{self, rand};
use rand::{random, thread_rng, RngCore};

use crate::runtime::scope::{Mutable, ScopeRef};
use crate::runtime::{Array, Error, Result, Value};
use crate::util::EC;

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();

    // Hashes
    scope.set_fn("hash::sha256", fns::hash_sha256).unwrap();
    scope.set_fn("hash::sha256d", fns::hash_sha256d).unwrap();
    scope
        .set_fn("hash::ripemd160", fns::hash_ripemd160)
        .unwrap();
    scope.set_fn("hash::hash160", fns::hash_hash160).unwrap();
    // Note: There are none-hash::-prefixed functions (e.g. sha256()) that also exists
    // but are different, returning a Miniscript Policy requiring the hash preimage

    // Signing & Verification
    scope.set_fn("ecdsa::sign", fns::ecdsa_sign).unwrap();
    scope.set_fn("ecdsa::verify", fns::ecdsa_verify).unwrap();
    scope.set_fn("schnorr::sign", fns::schnorr_sign).unwrap();
    scope
        .set_fn("schnorr::verify", fns::schnorr_verify)
        .unwrap();

    // Random
    scope.set_fn("rand::bytes", fns::rand_bytes).unwrap();
    scope.set_fn("rand::i64", fns::rand_i64).unwrap();
    scope.set_fn("rand::f64", fns::rand_f64).unwrap();
}

pub mod fns {
    use super::*;
    macro_rules! impl_hash_fn {
        ($fn_name:ident, $hash_mod:ident) => {
            pub fn $fn_name(args: Array, _: &ScopeRef) -> Result<Value> {
                let bytes: Vec<u8> = args.arg_into()?;
                Ok(hashes::$hash_mod::Hash::hash(&bytes).into())
            }
        };
    }

    // hash::sha256(Bytes preimage) -> Bytes hash
    impl_hash_fn!(hash_sha256, sha256);

    // hash::sha256d(Bytes preimage) -> Bytes hash
    impl_hash_fn!(hash_sha256d, sha256d);

    // hash::ripemd160(Bytes preimage) -> Bytes hash
    impl_hash_fn!(hash_ripemd160, ripemd160);

    // hash::hash160(Bytes preimage) -> Bytes hash
    impl_hash_fn!(hash_hash160, hash160);

    /// Sign the given message (hash) using ECDSA
    /// ecdsa::sign(SecKey, Bytes msg_hash, Bool compact_sig=false) -> Bytes signature
    pub fn ecdsa_sign(args: Array, _: &ScopeRef) -> Result<Value> {
        let (seckey, msg, compact_sig): (_, _, Option<bool>) = args.args_into()?;

        let sig = EC.sign_ecdsa(&msg, &seckey);

        Ok(if compact_sig.unwrap_or(false) {
            sig.serialize_compact().to_vec()
        } else {
            sig.serialize_der().to_vec()
        }
        .into())
    }

    /// Verify the given signature using ECDSA
    /// ecdsa::verify(PubKey, Bytes msg_hash, Bytes signature) -> Bool
    pub fn ecdsa_verify(args: Array, _: &ScopeRef) -> Result<Value> {
        let (pk, msg, sig) = args.args_into()?;
        Ok(EC.verify_ecdsa(&msg, &sig, &pk).is_ok().into())
    }

    /// Sign the given message (hash) using Schnorr
    /// schnorr::sign(SecKey, Bytes msg_hash, Bool aux_rand=false) -> Bytes signature
    pub fn schnorr_sign(args: Array, _: &ScopeRef) -> Result<Value> {
        let (keypair, msg, aux_rand): (_, _, Option<bool>) = args.args_into()?;

        Ok(if aux_rand.unwrap_or(false) {
            EC.sign_schnorr_with_rng(&msg, &keypair, &mut thread_rng())
        } else {
            EC.sign_schnorr_no_aux_rand(&msg, &keypair)
        }
        .serialize()
        .to_vec()
        .into())
    }

    /// Verify the given signature using Schnorr
    /// schnorr::verify(PubKey, Bytes msg_hash, Bytes signature) -> Bool
    pub fn schnorr_verify(args: Array, _: &ScopeRef) -> Result<Value> {
        let (pk, msg, sig) = args.args_into()?;
        Ok(EC.verify_schnorr(&sig, &msg, &pk).is_ok().into())
    }

    // Generate a random Bytes sequence
    /// rand::bytes(Int size) -> Bytes
    pub fn rand_bytes(args: Array, _: &ScopeRef) -> Result<Value> {
        let size = args.arg_into()?;
        let mut bytes = vec![0u8; size];
        thread_rng().fill_bytes(&mut bytes);
        Ok(bytes.into())
    }

    /// Generate a random signed 64-bit integer
    /// rand::i64() -> Int
    pub fn rand_i64(args: Array, _: &ScopeRef) -> Result<Value> {
        args.no_args()?;
        Ok(random::<i64>().into())
    }

    /// Generate a random 64-bit float in the [0, 1) range
    /// rand::f64() -> Float
    pub fn rand_f64(args: Array, _: &ScopeRef) -> Result<Value> {
        args.no_args()?;
        Ok(random::<f64>().into())
    }
}

// Convert from Value to signature/message types

impl TryFrom<Value> for secp256k1::Message {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(Self::from_digest_slice(&value.into_bytes()?)?)
    }
}

impl TryFrom<Value> for secp256k1::ecdsa::Signature {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        let bytes = value.into_bytes()?;
        Ok(if bytes.len() == 64 {
            Self::from_compact(&bytes)?
        } else {
            Self::from_der(&bytes)?
        })
    }
}

impl TryFrom<Value> for bitcoin::ecdsa::Signature {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Self::from_slice(&val.into_bytes()?)?)
    }
}

// Convert Value <-> Hash types
macro_rules! impl_hash_conv {
    ($name:path) => {
        impl TryFrom<Value> for $name {
            type Error = Error;
            fn try_from(value: Value) -> Result<Self> {
                match value {
                    Value::Bytes(b) => Ok(Self::from_slice(&b)?),
                    v => Err(Error::NotHashLike(v.into())),
                }
            }
        }
        impl From<$name> for Value {
            fn from(hash: $name) -> Self {
                Value::Bytes(hash.to_byte_array().to_vec())
            }
        }
    };
}
impl_hash_conv!(hashes::sha256::Hash);
impl_hash_conv!(hashes::sha256d::Hash);
impl_hash_conv!(hashes::ripemd160::Hash);
impl_hash_conv!(hashes::hash160::Hash);
impl_hash_conv!(miniscript::hash256::Hash);
impl_hash_conv!(bitcoin::TapNodeHash);
