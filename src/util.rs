use std::fmt::Debug;
use std::str::FromStr;

use miniscript::{bitcoin::secp256k1, descriptor};

lazy_static! {
    static ref EC: secp256k1::Secp256k1<secp256k1::VerifyOnly> =
        secp256k1::Secp256k1::verification_only();
}

pub fn get_descriptor_ctx(
    child_code: u32,
) -> descriptor::DescriptorPublicKeyCtx<'static, secp256k1::VerifyOnly> {
    descriptor::DescriptorPublicKeyCtx::new(&EC, child_code.into())
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
