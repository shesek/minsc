
pub type Ident = String;

#[derive(Debug)]
pub enum Expr {
  FnCall(Ident, Vec<Expr>),
  FnDef(Ident, Vec<String>, Box<Expr>),
  Assign(Ident, Box<Expr>),
  Or(Vec<Expr>),
  And(Vec<Expr>),
  Block(Vec<Expr>),
  Value(String), // plain value (hex pubkeys, xpubs, locktimes, etc)
  Var(Ident), // plain value (hex pubkeys, xpubs, locktimes, etc)
}
