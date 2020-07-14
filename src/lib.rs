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
    run(parse(s)?)?.into_policy()
}
