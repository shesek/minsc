#[macro_use]
extern crate lalrpop_util;

lalrpop_mod!(grammar);

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

pub use ast::{Expr, Ident};
pub use error::{Error, Result};
pub use miniscript::Policy;
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
    let policy = run(parse(s)?)?.into_policy()?;
    policy.as_top_level()
}

// WASM

use wasm_bindgen::prelude::*;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(js_name = compile)]
pub fn js_compile(s: &str) -> std::result::Result<String, JsValue> {
    let policy = compile(s).map_err(|e| e.to_string())?;

    Ok(policy.to_string())
}
