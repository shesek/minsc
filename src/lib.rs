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

pub use error::{Error, ParseError, RuntimeError};
pub use parser::{ast, Expr, Ident, Library, Stmt};
pub use runtime::display::{self, PrettyDisplay};
pub use runtime::{Evaluate, Execute, ExprRepr, Scope, ScopeRef, Value};

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

/// Parse expression/program code into an Expr AST
pub fn parse(s: &str) -> Result<Expr, ParseError> {
    s.parse()
}

/// Parse library code (collection of statements with no return value)
pub fn parse_lib(s: &str) -> Result<Library, ParseError> {
    s.parse()
}

#[deprecated = "use eval() instead"]
pub fn run(s: &str) -> Result<Value, Error> {
    eval(s)
}
