/// A simplified crude description of the Miniscript policy language
#[derive(Debug, Clone)]
pub enum Policy {
    FnCall(String, Vec<Policy>),
    Value(String),
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
