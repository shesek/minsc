pub type Ident = String;

/// A collection of statements and a final expression used as the return value.
/// Represents the main program, function bodies and block expressions
#[derive(Debug, Clone)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub return_value: Box<Expr>,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    FnDef(FnDef),
    Assign(Assign),
}

#[derive(Debug, Clone)]
pub enum Expr {
    FnCall(FnCall),
    FnDef(FnDef),
    Or(Or),
    And(And),
    Block(Block),
    Value(Value),
    FnNative(FnNative),
}

// A native Miniscript policy function. This is used to initialize the root
// scope and cannot be parsed from AST.
#[derive(Debug, Clone)]
pub struct FnNative(pub Ident);

/// A function call (expression)
#[derive(Debug, Clone)]
pub struct FnCall {
    pub name: Ident,
    pub args: Vec<Expr>,
}

/// A function definition (statement or expression)
#[derive(Debug, Clone)]
pub struct FnDef {
    pub name: Ident,
    pub args: Vec<Ident>,
    pub body: Block,
}

/// An assignment (statement)
#[derive(Debug, Clone)]
pub struct Assign {
    pub name: Ident,
    pub value: Box<Expr>,
}

/// Logical OR
#[derive(Debug, Clone)]
pub struct Or(pub Vec<Expr>);

/// Logical AND
#[derive(Debug, Clone)]
pub struct And(pub Vec<Expr>);

// A plain value (hex pubkeys, xpubs, locktimes, etc) or a variable name
#[derive(Debug, Clone)]
pub struct Value(pub String);

impl From<Expr> for Block {
    fn from(return_value: Expr) -> Self {
        Block {
            stmts: Vec::new(),
            return_value: return_value.into(),
        }
    }
}

impl_from!(FnDef, Stmt);
impl_from!(Assign, Stmt);
impl_from!(FnCall, Expr);
impl_from!(Or, Expr);
impl_from!(And, Expr);
impl_from!(Block, Expr);
impl_from!(Value, Expr);
impl_from!(FnDef, Expr);
impl_from!(FnNative, Expr);
