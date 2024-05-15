use std::convert::TryFrom;
use std::str::FromStr;

pub use crate::error::ParseError;

pub mod ast;
pub use ast::{Expr, Ident, Stmt, Stmts};

lalrpop_mod!(
    #[allow(clippy::all)]
    pub grammar,
    "/parser/grammar.rs"
);

pub type Library = Stmts;

impl FromStr for Expr {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parser = grammar::ProgramParser::new();
        Ok(parser.parse(s)?)
    }
}
impl_tryfrom_fromstr!(Expr);

impl FromStr for Stmts {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parser = grammar::StmtsParser::new();
        Ok(parser.parse(s)?)
    }
}
impl_tryfrom_fromstr!(Stmts);

// Utility functions used by the grammar

pub fn concat<T>(mut list: Vec<T>, val: Option<T>) -> Vec<T> {
    if let Some(val) = val {
        list.push(val);
    }
    list
}

pub fn prepend<T>(mut list: Vec<T>, val: T) -> Vec<T> {
    list.insert(0, val);
    list
}
