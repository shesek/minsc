#[macro_use]
extern crate lalrpop_util;
#[macro_use]
extern crate lazy_static;

#[macro_use]
mod macros;
pub mod error;
pub mod parser;
pub mod runtime;
pub mod stdlib;
pub mod time;
pub mod util;

#[cfg(feature = "playground")]
pub mod playground;
#[cfg(feature = "wasm")]
pub mod wasm;

use std::convert::TryInto;
use std::str::FromStr;

pub use error::{Error, ParseError, RuntimeError};
pub use parser::{ast, Expr, Ident, Library, Stmt, Stmts};
pub use runtime::{Evaluate, Execute, Number, Scope, ScopeRef, Value};
pub use util::PrettyDisplay;

use miniscript::{descriptor, policy};

pub type PolicyDpk = policy::concrete::Policy<descriptor::DescriptorPublicKey>;
pub type DescriptorDpk = descriptor::Descriptor<descriptor::DescriptorPublicKey>;
pub type DescriptorDef = descriptor::Descriptor<descriptor::DefiniteDescriptorKey>;
pub type MiniscriptDpk<Ctx> = miniscript::Miniscript<descriptor::DescriptorPublicKey, Ctx>;

/// Evaluate the given expression in the default global scope
/// `expr` can be provided as the string code or as a parsed Expr tree
pub fn eval<T: TryInto<Expr>>(expr: T) -> Result<Value, Error>
where
    Error: From<T::Error>,
{
    Ok(expr.try_into()?.eval(&Scope::root())?)
}

/// Parse program code into an Expr AST
pub fn parse(s: &str) -> Result<Expr, ParseError> {
    Expr::from_str(s)
}

// Parse library code into an Stmts AST
pub fn parse_lib(s: &str) -> Result<Stmts, ParseError> {
    Stmts::from_str(s)
}

#[deprecated = "use eval() instead"]
pub fn run(s: &str) -> Result<Value, Error> {
    eval(s)
}
