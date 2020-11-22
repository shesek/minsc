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

#[cfg(feature = "wasm")]
pub mod wasm;

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
