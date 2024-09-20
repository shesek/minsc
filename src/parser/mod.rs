use std::convert::TryFrom;
use std::str::FromStr;

pub use crate::error::ParseError;

pub mod ast;
pub use ast::{Expr, Ident, Library, Stmt};

lalrpop_mod!(
    #[allow(clippy::all)]
    pub grammar,
    "/parser/grammar.rs"
);

impl FromStr for Expr {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parser = grammar::ProgramParser::new();
        Ok(parser.parse(s)?)
    }
}
impl_tryfrom_fromstr!(Expr);

impl FromStr for Library {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parser = grammar::LibraryParser::new();
        Ok(parser.parse(s)?)
    }
}
impl_tryfrom_fromstr!(Library);

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

pub fn call(func: &str, args: Vec<Expr>) -> Expr {
    ast::Call {
        func: Expr::Ident(func.to_string().into()).into(),
        args,
    }
    .into()
}

pub fn bytes_from_hex(s: &str) -> Result<Expr, ParseError> {
    use bitcoin::hashes::hex::FromHex;
    Ok(Expr::Bytes(Vec::from_hex(s)?))
}

/// Expand escape characters in string literals (\", \\, \n, \r and \t)
pub fn string_from_escaped_str(s: &str) -> Expr {
    Expr::String(if !s.contains('\\') {
        s.to_owned()
    } else {
        let mut iter = s.chars();
        let mut s_new = String::new();
        while let Some(mut ch) = iter.next() {
            if ch == '\\' {
                let next_ch = iter.next().expect("well formed string guaranteed by regex");
                ch = match next_ch {
                    '\\' | '\"' => next_ch,
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => unreachable!("only valid escape sequences accepted by the regex"),
                };
            }
            s_new.push(ch);
        }
        s_new
    })
}
