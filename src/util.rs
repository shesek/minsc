use std::fmt::Debug;
use std::str::FromStr;

use bitcoin::secp256k1;
use miniscript::{bitcoin, DescriptorTrait, TranslatePk2};

use crate::Result;

lazy_static! {
    pub static ref EC: secp256k1::Secp256k1<secp256k1::VerifyOnly> =
        secp256k1::Secp256k1::verification_only();
}

pub trait DescriptorExt {
    fn to_script_pubkey(&self) -> Result<bitcoin::Script>;
    fn to_explicit_script(&self) -> Result<bitcoin::Script>;
    fn to_address(&self, network: bitcoin::Network) -> Result<bitcoin::Address>;
}

impl DescriptorExt for crate::Descriptor {
    fn to_script_pubkey(&self) -> Result<bitcoin::Script> {
        Ok(self
            .translate_pk2(|xpk| xpk.derive_public_key(&EC))?
            .script_pubkey())
    }
    fn to_explicit_script(&self) -> Result<bitcoin::Script> {
        Ok(self
            .translate_pk2(|xpk| xpk.derive_public_key(&EC))?
            .explicit_script()?)
    }

    fn to_address(&self, network: bitcoin::Network) -> Result<bitcoin::Address> {
        Ok(self
            .translate_pk2(|xpk| xpk.derive_public_key(&EC))?
            .address(network)?)
    }
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
