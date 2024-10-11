use std::str::FromStr;

use serde::Serialize;
use wasm_bindgen::prelude::*;

use miniscript::bitcoin::{Address, Network, ScriptBuf};
use miniscript::{Descriptor, MiniscriptKey};

use crate::util::DescriptorExt;
use crate::{parse, Error, Evaluate, Execute, Library, PrettyDisplay, Scope, ScopeRef, Value};

#[derive(Serialize)]
pub struct PlaygroundResult {
    policy: Option<String>,
    //script_hex: Option<String>,
    script_asm: Option<String>,
    descriptor: Option<String>,
    address: Option<String>,
    tapinfo: Option<String>,
    key: Option<String>,
    other: Option<String>,
}

#[wasm_bindgen]
pub fn run_playground(code: &str, network: &str) -> std::result::Result<JsValue, JsValue> {
    let _run_playground = || -> Result<PlaygroundResult, Error> {
        let network = Network::from_str(network)?;

        let value = run(code)?;

        let (mut policy, mut desc, mut script, mut addr, mut key, mut tapinfo, mut other) =
            (None, None, None, None, None, None, None);

        match value {
            Value::Policy(policy_) => {
                // Convert policies into a wsh() descriptor
                desc = Some(Descriptor::new_wsh(policy_.compile()?)?);
                policy = Some(policy_);
            }
            Value::Descriptor(desc_) => desc = Some(desc_),
            Value::PubKey(key_) => {
                // Convert pubkeys into wpkh()/tr() descriptors
                desc = Some(if key_.is_x_only_key() {
                    Descriptor::new_tr(key_.clone(), None)?
                } else {
                    Descriptor::new_wpkh(key_.clone())?
                });
                key = Some(key_);
            }
            Value::Script(script_) => {
                addr = Address::from_script(&script_, network).ok();
                script = Some(script_)
            }
            tapinfo_ @ Value::TapInfo(_) => {
                // Display the address of TaprootSpendInfo
                let spk = tapinfo_.clone().into_spk()?;
                addr = Some(Address::from_script(&spk, network).unwrap());
                tapinfo = Some(tapinfo_);
            }

            Value::Address(addr_) => addr = Some(addr_),
            other_ => other = Some(other_),
        };

        // Display the explicitScript/scriptPubKey and address of descriptors
        if let (Some(desc), None, None) = (&desc, &script, &addr) {
            // Multi-path and wildcards descriptors cannot be used to derive scripts/addresses
            if !desc.is_multipath() && !desc.has_wildcard() {
                // may fail if the descriptor pubkey has unresolved hardened derivation steps
                addr = desc.to_address(network).ok();
                script = match desc {
                    // Use the scriptPubKey for Taproot descriptor (it has no explicitScript)
                    Descriptor::Tr(_) => desc.to_script_pubkey().ok(),
                    _ => desc.to_explicit_script().ok(),
                }
            }
        }

        Ok(PlaygroundResult {
            policy: policy.map(|p| p.to_string()),
            descriptor: desc.map(|d| format!("{:#}", d)),
            script_asm: script.as_ref().map(script_asm),
            address: addr.map(|a| a.to_string()),
            tapinfo: tapinfo.map(|t| t.multiline_str()),
            key: key.map(|a| a.to_string()),
            other: other.map(|o| o.multiline_str()),
        })
    };
    let result = _run_playground().map_err(|e| e.to_string())?;
    Ok(JsValue::from_serde(&result).unwrap())
}

fn run(code: &str) -> Result<Value, Error> {
    PLAYGROUND_SCOPE.with(|scope| Ok(parse(code)?.eval(scope)?))
}

fn script_asm(script: &ScriptBuf) -> String {
    use crate::stdlib::btc::{fmt_script, ScriptFmt};
    let mut asm = String::new();
    fmt_script(&mut asm, script, ScriptFmt::Minsc(false), Some(0)).unwrap();
    asm
}

lazy_static! {
    static ref PLAYGROUND_LIB: Library = r#"
        __DEFAULT_SCOPE__ = true; // see Scope::is_default()

        // Add a default `main` function displaying all environment variables,
        // or a welcome message if there aren't any.
        dyn fn main() = symbol({
            $env = str(env::pretty());
            if !isEmpty($env) then "// Environment variables:\n\n" + $env
            else "// Welcome! Put some variables in your environment and they will show up here."
        });

        // Wrap some String-returning functions to return a Symbol instead, to have them displayed in
        // multi-line with syntax highlighting. This works because the playground displays Symbols as
        // their raw internal name, with no string quoting/escaping.
        _symbolify = |$fn| |$arg| symbol($fn($arg));
        debug = _symbolify(debug), script::wiz=_symbolify(script::wiz), script::bitide=_symbolify(script::bitide);

        // Provide some built-in example pubkeys and hashes for the demo env
        $alice = tpubD6NzVbkrYhZ4Y1jchg1nEfquYkdrh9oY5WXwxweo1zYevL9PHMVY9DzJWU5dxhr4v9E2Vp4XKSnztCRkv87LJJZekwYPofCBVh25bnuMsza;
        $bob = tpubD6NzVbkrYhZ4XJ4wfKpkuKAe6t5151uF1Hq4cvivWNbuRai6XsSCHfUo8FWPMnpj9etDWJmGrGqFhExmyVUfogq87vfi6R1PjP5eF8TTPef;
        $charlie = tpubD6NzVbkrYhZ4WgopbX4W8gekmVedWGcN6LbbPyHTUh2SsUYosMKxyh5jag4ipYpKhYyrxKENeBDsC3WtzSoayt8xjBps5sAvCTtnq74WWAh;
        $alice_sk = tprv8ZgxMBicQKsPeYhpp2MBqGBnyj7vXpcdWCwAgRcVbikG5qtcexfwxjNSLKjWGJMCyxBdznejsBgcxMsvKkX7HKJHN25vUPN2szNSc9v7dEp;
        $bob_sk = tprv8ZgxMBicQKsPdq39mgAAVuWXXrZ4ugiLRzEHLQgd66oWb6TKuUcc7ArvxA8R29Cp65WwChKFq1ELbjCTucZvoe3qn1VjBmGWkiHFq3Fmfiu;
        $charlie_sk = tprv8ZgxMBicQKsPdDn2hsPujGzeCU8hLwRTX2zp7TFA4RE42zJ3ExWNoCTsQXC2BHVGgEfCdZP9YoV3XHDuDhzCPuw29i74osGgYRxLZ6jfUuh;
        $H256 = 0x01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b;
        $H160 = 0x4355a46b19d348dc2f57c046f8ef63d4538ebb93;
    "#
    .parse()
    .unwrap();
}

thread_local! {
    // Create a scope beneath the root with additional playground utilities, used to evaluate playground code
    static PLAYGROUND_SCOPE: ScopeRef = {
        console_error_panic_hook::set_once();

        let scope = Scope::root().child().into_ref();
        PLAYGROUND_LIB.exec(&scope).unwrap();
        scope.into_readonly()
    };
}
