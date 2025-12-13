use std::convert::TryFrom;

use bip39::Mnemonic;

use crate::parser::Library;
use crate::runtime::{Array, Error, Execute, Mutable, Result, ScopeRef, Value};

const DEFAULT_WORD_COUNT: usize = 12;

lazy_static! {
    static ref BIP39_MINSC_LIB: Library = include_str!("bip39.minsc").parse().unwrap();
}

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    {
        let mut scope = scope.borrow_mut();
        scope.set_fn("bip39::rand", fns::rand).unwrap();
        scope.set_fn("bip39::to_seed", fns::to_seed).unwrap();
        scope.set_fn("bip39::to_entropy", fns::to_entropy).unwrap();
        scope
            .set_fn("bip39::from_entropy", fns::from_entropy)
            .unwrap();
    }
    BIP39_MINSC_LIB.exec(scope).unwrap();
}

pub mod fns {
    use super::*;

    /// bip39::rand(word_count: Int = 12, language: String = "english") -> String
    pub fn rand(args: Array, _: &ScopeRef) -> Result<Value> {
        let (word_count, language): (Option<_>, Option<_>) = args.args_into()?;
        let word_count = word_count.unwrap_or(DEFAULT_WORD_COUNT);
        let language = language.unwrap_or_default();

        Ok(Mnemonic::generate_in(language, word_count)?.into())
    }

    /// bip39::from_entropy(entropy: Bytes, language: String = "english") -> String
    pub fn from_entropy(args: Array, _: &ScopeRef) -> Result<Value> {
        let (entropy, language): (Vec<u8>, Option<_>) = args.args_into()?;
        let language = language.unwrap_or_default();

        Ok(Mnemonic::from_entropy_in(language, &entropy)?.into())
    }

    /// bip39::to_entropy(mnemonic: String, language: String = "english") -> Bytes
    pub fn to_entropy(args: Array, _: &ScopeRef) -> Result<Value> {
        let (mnemonic_str, language): (String, Option<_>) = args.args_into()?;
        let language = language.unwrap_or_default();

        let mnemonic = Mnemonic::parse_in(language, &mnemonic_str)?;
        Ok(mnemonic.to_entropy().into())
    }

    /// bip39::to_seed(mnemonic: String, passphrase: String = "", language: String = "english") -> Bytes
    pub fn to_seed(args: Array, _: &ScopeRef) -> Result<Value> {
        let (mnemonic_str, passphrase, language): (String, Option<String>, Option<_>) =
            args.args_into()?;
        let passphrase = passphrase.as_deref().unwrap_or("");
        let language = language.unwrap_or_default();

        let mnemonic = Mnemonic::parse_in(language, &mnemonic_str)?;
        Ok(mnemonic.to_seed(passphrase).to_vec().into())
    }
}

impl_simple_to_value!(Mnemonic, m, m.to_string());

impl TryFrom<Value> for bip39::Language {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value.into_string()?.as_str() {
            "english" => Ok(bip39::Language::English),
            #[cfg(feature = "bip39-all-languages")]
            "chinese_simplified" => Ok(bip39::Language::SimplifiedChinese),
            #[cfg(feature = "bip39-all-languages")]
            "chinese_traditional" => Ok(bip39::Language::TraditionalChinese),
            #[cfg(feature = "bip39-all-languages")]
            "czech" => Ok(bip39::Language::Czech),
            #[cfg(feature = "bip39-all-languages")]
            "french" => Ok(bip39::Language::French),
            #[cfg(feature = "bip39-all-languages")]
            "italian" => Ok(bip39::Language::Italian),
            #[cfg(feature = "bip39-all-languages")]
            "japanese" => Ok(bip39::Language::Japanese),
            #[cfg(feature = "bip39-all-languages")]
            "korean" => Ok(bip39::Language::Korean),
            #[cfg(feature = "bip39-all-languages")]
            "portuguese" => Ok(bip39::Language::Portuguese),
            #[cfg(feature = "bip39-all-languages")]
            "spanish" => Ok(bip39::Language::Spanish),
            other => bail!(Error::Bip39InvalidLanguage(other.to_string())),
        }
    }
}
