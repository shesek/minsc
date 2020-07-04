/// A simplified, crude description of the Miniscript policy language syntax
#[derive(Debug, Clone)]
pub enum Policy {
    Fragment(String, Vec<Policy>),
    TermWord(String),
}

pub const BUILTINS: &'static [&'static str] = &[
    "pk",
    "after",
    "older",
    "sha256",
    "hash256",
    "ripemd160",
    "hash160",
    "and",
    "or",
    "thresh",
];
