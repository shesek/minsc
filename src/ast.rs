use std::convert::TryFrom;
use std::str::FromStr;

use lalrpop_util::ParseError;
use miniscript::bitcoin;

use crate::{grammar, Error};

/// Expressions have no side-effects and produce a value
#[derive(Debug, Clone)]
pub enum Expr {
    Block(Block),
    Call(Call),
    If(IfExpr),
    Or(Or),
    And(And),
    Thresh(Thresh),
    Ident(Ident),
    Array(Array),
    ArrayAccess(ArrayAccess),
    ChildDerive(ChildDerive),
    ScriptFrag(ScriptFrag),
    FnExpr(FnExpr),
    Infix(Infix),
    Not(Not),
    BtcAmount(BtcAmount),

    PubKey(String),
    Bytes(Vec<u8>),
    String(String),
    Int(i64),
    Float(f64),
    Duration(Duration),
    DateTime(DateTime),
}

impl_from_variant!(i64, Expr, Int);
impl_from_variant!(f64, Expr, Float);

/// Statements have side-effects and don't produce a value
#[derive(Debug, Clone)]
pub enum Stmt {
    FnDef(FnDef),
    Assign(Assign),
    If(IfStmt),
}

/// A collection of statements and a final expression used as the return value.
/// Represents the main program, function bodies and block expressions
#[derive(Debug, Clone)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub return_value: Option<Box<Expr>>,
}
impl_from_variant!(Block, Expr);

/// A function call expression
#[derive(Debug, Clone)]
pub struct Call {
    pub ident: Ident,
    pub args: Vec<Expr>,
}
impl_from_variant!(Call, Expr);

#[derive(Debug, Clone)]
pub struct IfExpr {
    pub condition: Box<Expr>,
    pub then_val: Box<Expr>,
    pub else_val: Box<Expr>,
}
impl_from_variant!(IfExpr, Expr, If);

/// Logical OR expression
#[derive(Debug, Clone)]
pub struct Or(pub Vec<Expr>);
impl_from_variant!(Or, Expr);

/// Logical AND expression
#[derive(Debug, Clone)]
pub struct And(pub Vec<Expr>);
impl_from_variant!(And, Expr);

/// Threshold expression
#[derive(Debug, Clone)]
pub struct Thresh {
    pub thresh: Box<Expr>,
    pub policies: Box<Expr>,
}
impl_from_variant!(Thresh, Expr);

/// A terminal word expression
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Ident(pub String);
impl_from_variant!(Ident, Expr);
impl From<&str> for Ident {
    fn from(s: &str) -> Self {
        Ident(s.into())
    }
}
impl std::fmt::Display for Ident {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An array expression
#[derive(Debug, Clone)]
pub struct Array(pub Vec<Expr>);
impl_from_variant!(Array, Expr);

#[derive(Debug, Clone)]
pub struct ArrayAccess {
    pub array: Box<Expr>,
    pub index: Box<Expr>,
}
impl_from_variant!(ArrayAccess, Expr);

#[derive(Debug, Clone)]
pub struct ChildDerive {
    pub parent: Box<Expr>,
    pub path: Vec<Expr>,
    pub is_wildcard: bool,
}
impl_from_variant!(ChildDerive, Expr);

#[derive(Debug, Clone)]
pub struct ScriptFrag {
    pub fragments: Vec<Expr>,
}
impl_from_variant!(ScriptFrag, Expr);

/// An anonymous function expression
#[derive(Debug, Clone)]
pub struct FnExpr {
    pub signature: Vec<Ident>,
    pub body: Box<Expr>,
}
impl_from_variant!(FnExpr, Expr);

// An infix operator call with exactly two operands
// The && || operators which can have any number of operands are handled separately.
#[derive(Debug, Clone)]
pub struct Infix {
    pub op: InfixOp,
    pub lhs: Box<Expr>,
    pub rhs: Box<Expr>,
}
impl_from_variant!(Infix, Expr);

#[derive(Debug, Clone, Copy)]
pub enum InfixOp {
    Add,
    Subtract,
    Multiply,
    Eq,
    NotEq,
    Gt,
    Lt,
    Gte,
    Lte,
    Prob,
}

#[derive(Debug, Clone)]
pub struct Not(pub Box<Expr>);
impl_from_variant!(Not, Expr);

// Duration (relative block height or time)
#[derive(Debug, Clone, PartialEq)]
pub enum Duration {
    BlockHeight(u32),
    BlockTime {
        parts: Vec<DurationPart>,
        heightwise: bool,
    },
}
impl_from_variant!(Duration, Expr);

#[derive(Debug, Clone, PartialEq)]
pub enum DurationPart {
    Years(u32),
    Months(u32),
    Weeks(u32),
    Days(u32),
    Hours(u32),
    Minutes(u32),
    Seconds(u32),
}
// DateTime (YYYY-MM-DD with optional HH:MM)
#[derive(Debug, Clone, PartialEq)]
pub struct DateTime(pub String);
impl_from_variant!(DateTime, Expr);

// BTC amounts with denomination
#[derive(Debug, Clone)]
pub struct BtcAmount(pub Box<Expr>, pub bitcoin::Denomination);
impl_from_variant!(BtcAmount, Expr);

/// A function definition statement
#[derive(Debug, Clone)]
pub struct FnDef {
    pub ident: Ident,
    pub signature: Vec<Ident>,
    pub body: Expr,
}
impl_from_variant!(FnDef, Stmt);

/// An assignment statement
#[derive(Debug, Clone)]
pub struct Assign(pub Vec<Assignment>);
impl_from_variant!(Assign, Stmt);

#[derive(Debug, Clone)]
pub struct Assignment {
    pub lhs: Ident,
    pub rhs: Expr,
}

#[derive(Debug, Clone)]
pub struct IfStmt {
    pub condition: Expr,
    pub then_body: Box<Stmts>,
    pub else_body: Box<Option<Stmts>>,
}
impl_from_variant!(IfStmt, Stmt, If);

/// A collection of statements with no return value
/// Used for library files and as the body of if statements
#[derive(Debug, Clone)]
pub struct Stmts {
    pub stmts: Vec<Stmt>,
}

pub type Library = Stmts;

impl FromStr for Expr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parser = grammar::ProgramParser::new();
        Ok(parser.parse(s)?)
    }
}
impl_tryfrom_fromstr!(Expr);

impl FromStr for Stmts {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parser = grammar::StmtsParser::new();
        Ok(parser.parse(s)?)
    }
}
impl_tryfrom_fromstr!(Stmts);

type LalrError = ParseError<usize, lalrpop_util::lexer::Token<'static>, String>;

impl Expr {
    pub fn bytes_from_hex(s: &str) -> Result<Expr, LalrError> {
        use miniscript::bitcoin::hashes::hex::FromHex;

        Ok(Expr::Bytes(Vec::from_hex(s).map_err(|e| {
            ParseError::User {
                error: format!("Invalid bytes hex string {}: {}", s, e),
            }
        })?))
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
}
