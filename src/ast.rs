/// Expressions have no side-effects and produce a value
#[derive(Debug, Clone)]
pub enum Expr {
    Block(Block),
    Call(Call),
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

    PubKey(String),
    Bytes(Vec<u8>),
    Number(i64),
    Duration(Duration),
    DateTime(DateTime),
    BtcAmount(BtcAmount),
}

impl_from_variant!(i64, Expr, Number);

/// Statements have side-effects and don't produce a value
#[derive(Debug, Clone)]
pub enum Stmt {
    FnDef(FnDef),
    Assign(Assign),
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
    Years(f64),
    Months(f64),
    Weeks(f64),
    Days(f64),
    Hours(f64),
    Minutes(f64),
    Seconds(f64),
}
// DateTime (YYYY-MM-DD with optional HH:MM)
#[derive(Debug, Clone, PartialEq)]
pub struct DateTime(pub String);
impl_from_variant!(DateTime, Expr);

#[derive(Debug, Clone, PartialEq)]
pub struct BtcAmount(pub String);
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

/// A library is collection of statements with no return value
/// This is always parsed at the top-level and is never contained within an Expr/Stmt.
#[derive(Debug, Clone)]
pub struct Library {
    pub stmts: Vec<Stmt>,
}

use lalrpop_util::ParseError;
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
    /// and return the string as Bytes.
    pub fn bytes_from_escaped_str(s: &str) -> Expr {
        Expr::Bytes(if !s.contains('\\') {
            s.as_bytes().to_owned()
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
            s_new.into_bytes()
        })
    }
}
