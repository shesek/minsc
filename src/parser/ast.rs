use miniscript::{bitcoin, descriptor};

use bitcoin::address::{self, Address};
use descriptor::{DescriptorPublicKey, DescriptorSecretKey};

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
    SlashOp(SlashOp),
    ScriptFrag(ScriptFrag),
    FnExpr(FnExpr),
    Infix(Infix),
    Not(Not),

    BtcAmount(BtcAmount),
    Address(Address<address::NetworkUnchecked>),
    PubKey(DescriptorPublicKey),
    SecKey(DescriptorSecretKey),

    Bytes(Vec<u8>),
    String(String),
    Int(i64),
    Float(f64),
    Duration(Duration),
    DateTime(chrono::NaiveDateTime),
}

impl_from_variant!(i64, Expr, Int);
impl_from_variant!(f64, Expr, Float);
impl_from_variant!(String, Expr, String);

/// Statements have side-effects and don't produce a value
#[derive(Debug, Clone)]
pub enum Stmt {
    FnDef(FnDef),
    Assign(Assign),
    If(IfStmt),

    // An expression used in a statement position. The evaluated return value is
    // discarded, but this can be useful for expressions that produce non-scope
    // side effects (i.e. logging and exceptions).
    ExprStmt(ExprStmt),
}

/// A collection of statements with a return value
/// Represents the main program, function bodies and block expressions
#[derive(Debug, Clone)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    /// may be None for top-level Programs where the evaluation of `main()` is returned instead
    pub return_value: Option<Box<Expr>>,
}
impl_from_variant!(Block, Expr);

/// A function call expression
#[derive(Debug, Clone)]
pub struct Call {
    pub func: Box<Expr>,
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
#[derive(Debug, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct Ident(pub String);
impl_from_variant!(Ident, Expr);
impl From<&str> for Ident {
    fn from(s: &str) -> Self {
        Ident(s.into())
    }
}
impl From<String> for Ident {
    fn from(s: String) -> Self {
        Ident(s)
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
pub struct ScriptFrag {
    pub fragments: Vec<Expr>,
}
impl_from_variant!(ScriptFrag, Expr);

/// An anonymous function expression
#[derive(Debug, Clone)]
pub struct FnExpr {
    pub params: Vec<Ident>,
    pub body: Box<Expr>,
    pub dynamic_scoping: bool,
}
impl_from_variant!(FnExpr, Expr);

// Binary infix operators
// The And (&&), Or (||) and Slash (/) operators are overloaded (for policies/derivation) and handled separately
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
    Mod,
    Eq,
    NotEq,
    Gt,
    Lt,
    Gte,
    Lte,
    Prob,
    Colon,
    // Division is handled by the Slash operator and not through Infix, but was made part of this
    // enum for unified error reporting and so that it can be implemented as part of InfixOp::apply()
    Divide,
}

#[derive(Debug, Clone)]
pub struct Not(pub Box<Expr>);
impl_from_variant!(Not, Expr);

/// Slash operator. Used for number division and BIP32 derivation.
#[derive(Debug, Clone)]
pub struct SlashOp {
    pub lhs: Box<Expr>,
    pub rhs: SlashRhs,
}
impl_from_variant!(SlashOp, Expr);

#[derive(Debug, Clone)]
pub enum SlashRhs {
    Expr(Box<Expr>), // any standard Expr - for number division or BIP32 non-hardened derivation
    HardenedDerivation(Box<Expr>), // Expr followed by ' or h - for BIP32 hardened derivation
    UnhardenedWildcard, // * - BIP32 non-hardened wildcard
    HardenedWildcard, // *h or *' - BIP32 hardened wildcard
}

// Duration (relative block height or time)
#[derive(Debug, Clone)]
pub enum Duration {
    BlockHeight(Box<Expr>),
    BlockTime {
        parts: Vec<DurationPart>,
        heightwise: bool,
    },
}
impl_from_variant!(Duration, Expr);

pub type DurationPart = (Box<Expr>, DurationUnit);

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DurationUnit {
    Years,
    Months,
    Weeks,
    Days,
    Hours,
    Minutes,
    Seconds,
}

// BTC amounts with denomination
#[derive(Debug, Clone)]
pub struct BtcAmount(pub Box<Expr>, pub bitcoin::Denomination);
impl_from_variant!(BtcAmount, Expr);

/// A function definition statement
#[derive(Debug, Clone)]
pub struct FnDef {
    pub ident: Ident,
    pub params: Vec<Ident>,
    pub body: Expr,
    pub dynamic_scoping: bool,
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

/// A call statement whose return value is discarded
#[derive(Debug, Clone)]
pub struct ExprStmt(pub Expr);
impl_from_variant!(ExprStmt, Stmt, ExprStmt);

#[derive(Debug, Clone)]
pub struct IfStmt {
    pub condition: Expr,
    pub then_body: Vec<Stmt>,
    pub else_body: Option<Vec<Stmt>>,
}
impl_from_variant!(IfStmt, Stmt, If);

/// A collection of statements with no return value
// Thin wrapper over a Vec<Stmt> used for library files
#[derive(Debug, Clone)]
pub struct Library(pub Vec<Stmt>);

impl Expr {
    pub fn as_ident(&self) -> Option<&Ident> {
        match self {
            Expr::Ident(ident) => Some(ident),
            _ => None,
        }
    }
}
