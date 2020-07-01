pub type Ident = String;

/// A collection of statements and a final expression used as the return value.
/// Represents the main program, function bodies and block expressions
#[derive(Debug)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub return_value: Box<Expr>,
}

#[derive(Debug)]
pub enum Stmt {
    FnDef(FnDef),
    Assign(Assign),
}

#[derive(Debug)]
pub enum Expr {
    FnCall(FnCall),
    Or(Or),
    And(And),
    Block(Block),
    Value(Value),
}

/// A function call
#[derive(Debug)]
pub struct FnCall {
    pub name: Ident,
    pub args: Vec<Expr>,
}

/// A function definition
#[derive(Debug)]
pub struct FnDef {
    pub name: Ident,
    pub args: Vec<Ident>,
    pub body: Block,
}

/// An assignment
#[derive(Debug)]
pub struct Assign {
    pub name: Ident,
    pub value: Box<Expr>,
}

/// Logical OR
#[derive(Debug)]
pub struct Or(pub Vec<Expr>);

/// Logical AND
#[derive(Debug)]
pub struct And(pub Vec<Expr>);

// A plain value (hex pubkeys, xpubs, locktimes, etc) or a variable name
#[derive(Debug)]
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
