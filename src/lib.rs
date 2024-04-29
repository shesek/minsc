#[macro_use]
extern crate lalrpop_util;
#[cfg(feature = "lazy_static")]
#[macro_use]
extern crate lazy_static;

lalrpop_mod!(
    #[allow(clippy::all)]
    grammar
);

#[macro_use]
mod macros;
pub mod ast;
pub mod error;
pub mod function;
pub mod runtime;
pub mod scope;
pub mod stdlib;
pub mod time;
pub mod util;

#[cfg(feature = "playground")]
pub mod playground;
#[cfg(feature = "wasm")]
pub mod wasm;

use std::convert::TryInto;
use std::str::FromStr;

pub use ast::{Expr, Ident, Stmt, Stmts};
pub use error::{Error, Result};
pub use runtime::{Evaluate, Number::*, Value};
pub use scope::Scope;

use miniscript::{descriptor, policy};

pub type PolicyDpk = policy::concrete::Policy<descriptor::DescriptorPublicKey>;
pub type DescriptorDpk = descriptor::Descriptor<descriptor::DescriptorPublicKey>;
pub type MiniscriptDpk<Ctx> = miniscript::Miniscript<descriptor::DescriptorPublicKey, Ctx>;

/// Evaluate the given expression in the default global scope
/// `expr` can be provided as the string code or as a parsed Expr tree
pub fn eval<T: TryInto<Expr>>(expr: T) -> Result<Value>
where
    Error: From<T::Error>,
{
    expr.try_into()?.eval(&Scope::root())
}

/// Parse program code into an Expr AST
pub fn parse(s: &str) -> Result<Expr> {
    Expr::from_str(s)
}

// Parse library code into an Stmts AST
pub fn parse_lib(s: &str) -> Result<Stmts> {
    Stmts::from_str(s)
}

#[deprecated = "use eval() instead"]
pub fn run(s: &str) -> Result<Value> {
    eval(s)
}
