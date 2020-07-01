pub type Ident = String;

#[derive(Debug)]
pub enum Expr {
    FnCall(FnCall),
    FnDef(FnDef),
    Assign(Assign),
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
    pub body: Box<Expr>,
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

/// A block of expressions (main program, function bodies or block expressions)
#[derive(Debug)]
pub struct Block(pub Vec<Expr>);

// A plain value (hex pubkeys, xpubs, locktimes, etc) or a variable name
#[derive(Debug)]
pub struct Value(pub String);

impl_from!(FnCall, Expr);
impl_from!(FnDef, Expr);
impl_from!(Assign, Expr);
impl_from!(Or, Expr);
impl_from!(And, Expr);
impl_from!(Block, Expr);
impl_from!(Value, Expr);
