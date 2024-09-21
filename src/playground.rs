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
            // Multi-path descriptors cannot be used to derive scripts/addresses
            if !desc.is_multipath() {
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
        dyn fn main() = Symbol({
            $env = str(env::pretty());
            if !isEmpty($env) then "// Environment variables:\n\n" + $env
            else "// Welcome! Put some variables in your environment and they will show up here."
        });

        // Get the env with the argument displayed on top as `$`
        dyn fn with_env($) = env::pretty();

        // Provide some built-in example pubkeys and hashes for the demo env

        A = pubkey(0x029ffbe722b147f3035c87cb1c60b9a5947dd49c774cc31e94773478711a929ac0);
        B = pubkey(0x025f05815e3a1a8a83bfbb03ce016c9a2ee31066b98f567f6227df1d76ec4bd143),
        C = pubkey(0x025625f41e4a065efc06d5019cbbd56fe8c07595af1231e7cbc03fafb87ebb71ec),
        D = pubkey(0x02a27c8b850a00f67da3499b60562673dcf5fdfb82b7e17652a7ac54416812aefd);
        E = pubkey(0x03e618ec5f384d6e19ca9ebdb8e2119e5bef978285076828ce054e55c4daf473e2);
        F = pubkey(0x03deae92101c790b12653231439f27b8897264125ecb2f46f48278603102573165);
        G = pubkey(0x033841045a531e1adf9910a6ec279589a90b3b8a904ee64ffd692bd08a8996c1aa);
        I = pubkey(0x02aebf2d10b040eb936a6f02f44ee82f8b34f5c1ccb20ff3949c2b28206b7c1068);
        J = pubkey(0x03d2810d442a784e93133760af5ac05e4eb72364a3257e5a5eafc618ccb15e580a);
        K = pubkey(0x03a81dca4cde2edf3d193e2b2446b40aa04f33dd11a4599c7fa55415fc274f0f70);
        L = pubkey(0x029e5de3f2391700fdb5f45aa5db40b953de8bd4a147663b1cd89aa0703a0c2fcf);

        $alice = xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/0;
        $bob = xpub69tT6QWuMwV9bppMzxDX39hz6vcwsgK6YE4gR5cA4auaHsX6dR7uCu566h2WXEGjQe8B89PUJEwsaTJZiDTmLbGVPDDz9JjohA46jUEPvtb;
        $charlie = xpub6BCmnsYVHYpxh4gPrwWXbYZwGsDHoGP69rQR7EQkWDNKJDuCqhSJXBRsTxiap6fsCmG2YNUVjn3WhpqvtRcwuMX5HyFdvuEwghKjmWMaGrA/3/*;

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
