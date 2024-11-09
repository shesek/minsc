use std::convert::TryFrom;
use std::str::FromStr;

use crate::util::PeekableExt;

pub use crate::error::ParseError;

pub mod ast;
pub use ast::{AssignTarget, Expr, FnParams, Ident, Library, Stmt};

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

// The grammar reuses the Expr Array/Ident types as an AssignTarget to play nicely with LR(1) grammar.
// This converts them into an AssignTarget, or reject ones that are invalid.
// See https://github.com/lalrpop/lalrpop/issues/552#issuecomment-778923903
impl TryFrom<Expr> for AssignTarget {
    type Error = ParseError;
    fn try_from(expr: Expr) -> Result<Self, ParseError> {
        use ast::{Infix, InfixOp::Colon};
        Ok(match expr {
            Expr::Ident(ident) => Self::Ident(ident),
            Expr::Array(ast::Array(mut items)) => {
                // Colon tuple syntax is supported within Array brackets, as e.g. `[$txid:$vout]` (it cannot be
                // supported without it due to grammar conflicts). Must peek to check prior to taking ownership.
                if items.len() == 1 && matches!(items[0], Expr::Infix(Infix { op: Colon, .. })) {
                    let Expr::Infix(ast::Infix { lhs, rhs, .. }) = items.remove(0) else {
                        unreachable!()
                    };
                    Self::List(vec![Self::try_from(*lhs)?, Self::try_from(*rhs)?])
                } else {
                    let targets = items.into_iter().map(Self::try_from);
                    Self::List(targets.collect::<Result<_, _>>()?)
                }
            }
            _ => bail!(ParseError::InvalidAssignTarget),
        })
    }
}

// The grammar accepts optional function parameters in any position. This splits up the required
// and optional ones, and ensures there aren't any optional parameters in an invalid position.
impl TryFrom<Vec<(AssignTarget, Option<Expr>)>> for FnParams {
    type Error = ParseError;
    fn try_from(params: Vec<(AssignTarget, Option<Expr>)>) -> Result<Self, ParseError> {
        let mut params = params.into_iter().peekable();
        // Take all required, then all optional, then ensure there are none left
        let required = params
            .by_ref()
            .peeking_take_while(|(_, default)| default.is_none())
            .map(|(target, _)| target)
            .collect();
        let optional = params
            .by_ref()
            .peeking_take_while(|(_, default)| default.is_some())
            .map(|(target, default)| (target.clone(), default.unwrap()))
            .collect();
        ensure!(
            params.next().is_none(),
            ParseError::InvalidOptionalParamPosition
        );
        Ok(Self { required, optional })
    }
}

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

pub fn bytes_from_base64(s: &str) -> Result<Expr, ParseError> {
    use base64::alphabet;
    use base64::engine::{DecodePaddingMode, Engine, GeneralPurpose, GeneralPurposeConfig};
    // Support base64 strings with or without padding characters
    const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    Ok(Expr::Bytes(ENGINE.decode(s)?))
}

/// Expand escape characters in string literals (\", \\, \n, \r and \t)
pub fn string_from_escaped_str(s: &str) -> Expr {
    Expr::String(if !s.contains('\\') {
        s.to_owned()
    } else {
        let mut iter = s.chars();
        let mut s_new = String::with_capacity(s.len());
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
