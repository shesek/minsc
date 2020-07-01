
pub type Identifier = String;

#[derive(Debug)]
pub enum Expr {
  FnCall(Identifier, Vec<Expr>),
  FnDef(Identifier, Vec<Identifier>, Box<Expr>),
  Assign(Identifier, Box<Expr>),
  Or(Vec<Expr>),
  And(Vec<Expr>),
  Block(Vec<Expr>, Box<Expr>),
  Value(String), // plain value (hex pubkeys, xpubs, locktimes, etc)
  Var(Identifier),
}
