use std::convert::TryFrom;

use bitcoin::hashes::{self, Hash};
use bitcoin::secp256k1::{self, rand};

use crate::runtime::scope::{Mutable, ScopeRef};
use crate::runtime::{Array, Error, Result, Value};
use crate::util::EC;

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();

    // Hash functions
    scope.set_fn("hash::sha256", fns::hash_sha256).unwrap();
    scope.set_fn("hash::sha256d", fns::hash_sha256d).unwrap();
    scope.set_fn("hash::ripemd160", fns::hash_sha256d).unwrap();
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
            EC.sign_schnorr_with_rng(&msg, &keypair, &mut rand::thread_rng())
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
}

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
