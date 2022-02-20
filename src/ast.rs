/// Expressions have no side-effects and produce a value
#[derive(Debug, Clone)]
pub enum Expr {
    Block(Block),
    Call(Call),
    Or(Or),
    And(And),
    Thresh(Thresh),
    Ident(Ident),
    WithProb(WithProb),
    Array(Array),
    ArrayAccess(ArrayAccess),
    ChildDerive(ChildDerive),
    FnExpr(FnExpr),

    // Atoms
    PubKey(String),
    Hash(String),
    Number(usize),
    Duration(Duration),
    DateTime(String),
}

impl_from_variant!(usize, Expr, Number);

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

/// A terminal word expression. This can either be a variable name or a plain value passed-through to miniscript.
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

/// An expression with a probability. Valid as an argument to or().
#[derive(Debug, Clone)]
pub struct WithProb {
    pub prob: Box<Expr>,
    pub expr: Box<Expr>,
}
impl_from_variant!(WithProb, Expr);

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

/// An anonymous function expression
#[derive(Debug, Clone)]
pub struct FnExpr {
    pub signature: Vec<Ident>,
    pub body: Box<Expr>,
}
impl_from_variant!(FnExpr, Expr);

// Duration (relative block height or time)
#[derive(Debug, Clone)]
pub enum Duration {
    BlockHeight(u32),
    BlockTime {
        parts: Vec<DurationPart>,
        heightwise: bool,
    },
}
impl_from_variant!(Duration, Expr);

#[derive(Debug, Clone)]
pub enum DurationPart {
    Years(f64),
    Months(f64),
    Weeks(f64),
    Days(f64),
    Hours(f64),
    Minutes(f64),
    Seconds(f64),
}

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
