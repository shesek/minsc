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
    Or(Or),
    And(And),
    Block(Block),
    TermWord(TermWord),
}

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
    pub body: Expr,
}

/// An assignment (statement)
#[derive(Debug, Clone)]
pub struct Assign {
    pub name: Ident,
    pub value: Expr,
}

/// Logical OR
#[derive(Debug, Clone)]
pub struct Or(pub Vec<Expr>);

/// Logical AND
#[derive(Debug, Clone)]
pub struct And(pub Vec<Expr>);

/// A terminal word. This can either be a variable name or a plain value passed-through to miniscript.
#[derive(Debug, Clone)]
pub struct TermWord(pub String);

impl_from_variant!(FnDef, Stmt);
impl_from_variant!(Assign, Stmt);

impl_from_variant!(FnCall, Expr);
impl_from_variant!(Or, Expr);
impl_from_variant!(And, Expr);
impl_from_variant!(Block, Expr);
impl_from_variant!(TermWord, Expr);
