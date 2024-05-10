use miniscript::bitcoin::{Address, Network, ScriptBuf};
use miniscript::descriptor::Descriptor;
use serde::Serialize;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use crate::util::DescriptorExt;
use crate::{parse, Error, Evaluate, Execute, Library, PrettyDisplay, Scope, Value};

#[derive(Serialize)]
pub struct PlaygroundResult {
    policy: Option<String>,
    //script_hex: Option<String>,
    script_asm: Option<String>,
    descriptor: Option<String>,
    address: Option<String>,
    other: Option<String>,
}

#[wasm_bindgen]
pub fn run_playground(code: &str, network: &str) -> std::result::Result<JsValue, JsValue> {
    let _run_playground = || -> Result<PlaygroundResult, Error> {
        let network = Network::from_str(network)?;

        let value = run(code)?;

        let (policy, desc, script, addr, other) = match value {
            Value::Policy(policy) => {
                let ms = policy.compile()?;
                let desc = Descriptor::new_wsh(ms)?;
                let script = desc.to_explicit_script()?;
                let addr = desc.to_address(network)?;
                (Some(policy), Some(desc), Some(script), Some(addr), None)
            }
            Value::Descriptor(desc) => {
                let (addr, script, tapinfo) = if desc.is_multipath() {
                    (None, None, None)
                } else if let Descriptor::Tr(_) = desc {
                    // For Taproot descriptors, also show the TaprootSpendInfo as the 'other' result
                    let tapinfo = match desc.clone().at_derivation_index(0)? {
                        Descriptor::Tr(tr) => (*tr.spend_info()).clone(),
                        _ => unreachable!(),
                    };
                    (Some(desc.to_address(network)?), None, Some(tapinfo.into()))
                } else {
                    // Explicit script is only available for non-Taproot descriptors
                    (
                        Some(desc.to_address(network)?),
                        Some(desc.to_explicit_script()?),
                        None,
                    )
                };
                (None, Some(desc), script, addr, tapinfo)
            }
            Value::PubKey(key) => {
                let desc = Descriptor::new_wpkh(key.clone())?;
                let (addr, script) = if desc.is_multipath() {
                    (None, None)
                } else {
                    let addr = desc.to_address(network)?;
                    let script = desc.to_explicit_script()?;
                    (Some(addr), Some(script))
                };
                (None, Some(desc), script, addr, Some(key.into()))
            }
            Value::Script(script) => {
                let addr = Address::from_script(&script, network).ok();
                (None, None, Some(script), addr, None)
            }
            tapinfo @ Value::TapInfo(_) => {
                let spk = tapinfo.clone().into_spk()?;
                let addr = Address::from_script(&spk, network).unwrap();
                (None, None, None, Some(addr), Some(tapinfo))
            }

            Value::Address(addr) => (None, None, None, Some(addr), None),
            other => (None, None, None, None, Some(other)),
        };

        Ok(PlaygroundResult {
            policy: policy.map(|p| p.to_string()),
            descriptor: desc.map(|d| d.to_string()),
            //script_hex: script.as_ref().map(|s| s.to_hex()),
            script_asm: script.as_ref().map(get_script_asm),
            address: addr.map(|a| a.to_string()),
            other: other.map(|o| o.multiline_str()),
        })
    };
    let result = _run_playground().map_err(|e| e.to_string())?;
    Ok(JsValue::from_serde(&result).unwrap())
}

fn run(code: &str) -> Result<Value, Error> {
    Ok(parse(code)?.eval(&DEMO_SCOPE)?)
}

fn get_script_asm(script: &ScriptBuf) -> String {
    let s = script.pretty_str();
    // Remove the wrapping backticks
    s[1..s.len() - 1].to_string()
}

lazy_static! {
    static ref PLAYGROUND_LIB: Library = r#"
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
        user_pk = pubkey(0x03c620141755e90c86ec35fe57594e0b4b1a32f09f15bc0a43b06f9feb71c1b06c);
        service_pk = pubkey(0x02f8b2c15f9e301d7e46169a35088724cbcb264f678d628d615c38ee964f836245);
        buyer_pk = pubkey(0x03829e91bb8d4df87fea147f98ef5d3e71c7c26204a5ed5de2d1d966938d017ac2);
        seller_pk = pubkey(0x0215152236dd9f518dd2bba50487857b98bdb4778c3618780a25a0cbc660092185);
        arbiter_pk = pubkey(0x0203bc5458e2b77b5f5a68a738a57bee0271a27e603100c4110533bf8811c19e2e);
        ceo_pk = pubkey(0x03e9035b99913ea072be74032489f7d20725ae496f8809b1c1924dbeacf590c5ed);
        desktop_pk = pubkey(0x02e0e913c8e67ee002ed4a877a54722b0483f999ad49111081318f204f1a470c58);
        mobile_pk = pubkey(0x02065bf89fb085e06188a885fc191e25469ebd2868b160bd525778eedbe2f987cf);
        $alice = xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/9/0;

        XPUB = xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw/9/0;
        H = 0x01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b;
        H1 = 0x4355a46b19d348dc2f57c046f8ef63d4538ebb93;
        H2 = 0x53c234e5e8472b6ac51c1ae1cab3fe06fad053be;
    "#
    .parse()
    .unwrap();
    // Provide some built-in example pubkeys and hashes in the web demo env
    static ref DEMO_SCOPE: Scope<'static> = {
        console_error_panic_hook::set_once();

        // The root is cloned to make the playground library part of the root
        // and to have it excluded from `env()`
        let mut scope = Scope::root().clone();
        PLAYGROUND_LIB.exec(&mut scope).unwrap();
        scope
    };
}
