#[macro_use]
extern crate lalrpop_util;

lalrpop_mod!(
    #[allow(clippy::all)]
    grammar
);

#[macro_use]
mod macros;
pub mod ast;
pub mod error;
pub mod function;
pub mod miniscript;
pub mod runtime;
pub mod scope;
pub mod time;
pub mod util;

pub use crate::miniscript::Policy;
pub use ast::{Expr, Ident};
pub use error::{Error, Result};
pub use runtime::{Evaluate, Value};
pub use scope::Scope;

pub fn parse(s: &str) -> Result<Expr> {
    let parser = grammar::ProgramParser::new();
    Ok(parser.parse(s)?)
}

pub fn run(expr: Expr) -> Result<Value> {
    expr.eval(&Scope::root())
}

pub fn compile(s: &str) -> Result<Policy> {
    run(parse(s)?)?.into_policy()
}

// WASM

use ::miniscript::bitcoin::hashes::hex::ToHex;
use ::miniscript::bitcoin::{Network, Script};
use ::miniscript::{descriptor::Descriptor, Legacy, Miniscript, Segwitv0};
use serde::Serialize;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[derive(Serialize)]
pub struct JsResult {
    policy: String,
    miniscript: String,
    script_hex: String,
    script_asm: String,
    descriptor: String,
    spk: String,
    address: String,
}

#[wasm_bindgen(js_name = compile)]
pub fn js_compile(
    code: &str,
    desc_type: &str,
    network: &str,
    child_code: u32,
) -> std::result::Result<JsValue, JsValue> {
    let network = Network::from_str(network).map_err(|e| e.to_string())?;

    let policy = compile(code).map_err(|e| e.to_string())?;
    let miniscript: Miniscript<_, Segwitv0> = policy.compile().map_err(|e| e.to_string())?;
    let script = miniscript.encode();

    let descriptor = match desc_type {
        "wsh" => Descriptor::Wsh(miniscript.clone()),
        "shwsh" => Descriptor::ShWsh(miniscript.clone()),
        _ => bail!("Unsupported descriptor type"),
    }
    .derive(child_code.into());

    let spk = descriptor.script_pubkey();
    let address = descriptor.address(network).unwrap();

    Ok(JsValue::from_serde(&JsResult {
        policy: policy.to_string(),
        miniscript: miniscript.to_string(),
        script_hex: script.to_hex(),
        script_asm: get_script_asm(&script),
        descriptor: descriptor.to_string(),
        spk: spk.to_string(),
        address: address.to_string(),
    })
    .unwrap())
}

fn get_script_asm(script: &Script) -> String {
    let s = format!("{:?}", script);
    s[7..s.len() - 1].into()
}
