use std::borrow::Borrow;
use std::convert::TryInto;

use crate::parser::{ast, Expr, Stmt};
use crate::stdlib;

pub use crate::error::{ResultExt, RuntimeError as Error};
pub type Result<T> = std::result::Result<T, Error>;

pub mod array;
pub mod function;
pub mod scope;
pub mod value;

pub use array::Array;
pub use function::{Call, Function};
pub use scope::{Mutable, ReadOnly, Scope, ScopeRef};
pub use value::{ExprRepr, FromValue, Number, Number::*, Symbol, Value};

/// Evaluate an expression. Expressions have no side-effects and return a value.
pub trait Evaluate {
    fn eval(&self, scope: &ScopeRef<ReadOnly>) -> Result<Value>;
}

/// Execute a statement. Statements have side-effects and don't have a return value.
pub trait Execute {
    fn exec(&self, scope: &ScopeRef<Mutable>) -> Result<()>;
}

//
// Execution
//

impl Execute for ast::Assign {
    fn exec(&self, scope: &ScopeRef<Mutable>) -> Result<()> {
        let readonly = scope.as_readonly();
        for assignment in &self.0 {
            let value = assignment.rhs.eval(&readonly)?;
            scope.borrow_mut().set(assignment.lhs.clone(), value)?;
        }
        Ok(())
    }
}

impl Execute for ast::FnDef {
    fn exec(&self, scope: &ScopeRef<Mutable>) -> Result<()> {
        let func = Function::from_def(self.clone(), scope.as_readonly());
        scope.borrow_mut().set(self.ident.clone(), func)
    }
}

// Evaluate the Stmt's inner Expr, discarding its return value.
// The Expr may produce side-effects like logging and exceptions.
impl Execute for ast::ExprStmt {
    fn exec(&self, scope: &ScopeRef<Mutable>) -> Result<()> {
        self.0.eval(&scope.as_readonly()).map(|_| ())
    }
}

impl Execute for ast::IfStmt {
    fn exec(&self, scope: &ScopeRef<Mutable>) -> Result<()> {
        if self.condition.eval(&scope.as_readonly())?.into_bool()? {
            self.then_body.exec(scope)
        } else if let Some(else_body) = &self.else_body {
            else_body.exec(scope)
        } else {
            Ok(())
        }
    }
}

impl Execute for ast::Stmt {
    fn exec(&self, scope: &ScopeRef<Mutable>) -> Result<()> {
        match self {
            Stmt::FnDef(x) => x.exec(scope),
            Stmt::Assign(x) => x.exec(scope),
            Stmt::If(x) => x.exec(scope),
            Stmt::ExprStmt(x) => x.exec(scope),
        }
    }
}

impl Execute for ast::Library {
    fn exec(&self, scope: &ScopeRef<Mutable>) -> Result<()> {
        self.0.exec(scope)
    }
}

impl Execute for Vec<ast::Stmt> {
    fn exec(&self, scope: &ScopeRef<Mutable>) -> Result<()> {
        for stmt in self {
            stmt.exec(scope)?;
        }
        Ok(())
    }
}

//
// Evaluation
//

impl Evaluate for ast::Call {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let func = self.func.eval(scope)?.into_fn()?;
        let args = eval_exprs(scope, &self.args)?;

        match (func.call(args, scope), self.func.as_ident()) {
            (Err(Error::CallError(None, e)), Some(caller_ident)) => {
                // If the function originating the error is unnamed but the caller called it using an identifier,
                // use the caller name for the CallError message. A name may not be available on the caller side
                // either if the function was not accessed through a simple identifier, for example `([a].0)()`
                Err(Error::CallError(Some(caller_ident.clone()), e))
            }
            (other, _) => other,
        }
    }
}

impl Evaluate for ast::IfExpr {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        if self.condition.eval(scope)?.into_bool()? {
            self.then_val.eval(scope)
        } else {
            self.else_val.eval(scope)
        }
    }
}

impl Evaluate for ast::Or {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        eval_andor(&self.0, scope, AndOr::Or)
    }
}
impl Evaluate for ast::And {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        eval_andor(&self.0, scope, AndOr::And)
    }
}

pub enum AndOr {
    And,
    Or,
}

fn eval_andor(operands: &[Expr], scope: &ScopeRef, andor: AndOr) -> Result<Value> {
    // Peek at the first operand to determine if its an operation between booleans or between policies.
    // All the other operands are expected to be of the same type. We don't pre-evaluate all of them
    // so that eval_bool_andor() may do so lazily.
    let first_operand = operands[0].eval(scope)?;
    match first_operand {
        Value::Bool(first_bool) => eval_bool_andor(first_bool, &operands[1..], scope, andor),
        Value::Policy(_) | Value::WithProb(_, _) | Value::PubKey(_) | Value::SecKey(_) => {
            let policies = [&[first_operand], &eval_exprs(scope, &operands[1..])?[..]].concat();
            stdlib::miniscript::multi_andor(andor, policies).map(Into::into)
        }
        _ => Err(Error::InvalidArguments),
    }
}

// Evaluate && / || for booleans (lazily evaluated)
fn eval_bool_andor(
    first_operand: bool,
    other_operands_exprs: &[Expr],
    scope: &ScopeRef,
    andor: AndOr,
) -> Result<Value> {
    let stop_on = match andor {
        AndOr::Or => true,
        AndOr::And => false,
    };
    if first_operand == stop_on {
        return Ok(stop_on.into());
    }
    for expr in other_operands_exprs {
        let operand = expr.eval(scope)?;
        if operand.into_bool()? == stop_on {
            return Ok(stop_on.into());
        }
    }
    Ok((!stop_on).into())
}

impl Evaluate for ast::Ident {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        scope
            .borrow()
            .get(self)
            .ok_or_else(|| Error::VarNotFound(self.clone()))
    }
}

impl Evaluate for ast::Array {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let elements = eval_exprs(scope, &self.0)?;
        Ok(elements.into())
    }
}

impl Evaluate for ast::ArrayAccess {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let value = self.array.eval(scope)?;
        let index = self.index.eval(scope)?.into_usize()?;
        Ok(match value {
            Value::Array(mut array) => {
                ensure!(index < array.len(), Error::ArrayIndexOutOfRange);
                array.remove(index)
            }
            Value::Bytes(mut bytes) => {
                ensure!(index < bytes.len(), Error::ArrayIndexOutOfRange);
                (bytes.remove(index) as i64).into()
            }
            Value::Descriptor(desc) if desc.is_multipath() => {
                let mut single_descs = desc.into_single_descriptors()?;
                ensure!(index < single_descs.len(), Error::ArrayIndexOutOfRange);
                single_descs.remove(index).into()
            }
            Value::PubKey(pk) if pk.is_multipath() => {
                let mut single_pks = pk.into_single_keys();
                ensure!(index < single_pks.len(), Error::ArrayIndexOutOfRange);
                single_pks.remove(index).into()
            }
            Value::SecKey(sk) if sk.is_multipath() => {
                let mut single_sks = sk.into_single_keys();
                ensure!(index < single_sks.len(), Error::ArrayIndexOutOfRange);
                single_sks.remove(index).into()
            }
            other => bail!(Error::NoArrayAccess(other.into())),
        })
    }
}

impl Evaluate for ast::FnExpr {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let func = Function::from_expr(self.clone(), scope.make_ref());
        Ok(func.into())
    }
}

impl Evaluate for ast::Not {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        Ok((!self.0.eval(scope)?.into_bool()?).into())
    }
}

impl Evaluate for ast::Negate {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        Ok(match self.0.eval(scope)?.try_into()? {
            Number::Int(n) => (-n).into(),
            Number::Float(n) => (-n).into(),
        })
    }
}

impl Evaluate for ast::Infix {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        self.op
            .apply(self.lhs.eval(scope)?, self.rhs.eval(scope)?, scope)
            .map_err(|e| Error::InfixOpError(self.op, e.into()))
    }
}

impl ast::InfixOp {
    fn apply(&self, lhs: Value, rhs: Value, scope: &ScopeRef) -> Result<Value> {
        use ast::InfixOp::*;
        use Value::{
            Array, Bytes, Number as Num, Policy, Psbt, PubKey, Script, SecKey, String, WithProb,
        };

        Ok(match (self, lhs, rhs) {
            // == != for all types
            (Eq, a, b) => (a == b).into(),
            (NotEq, a, b) => (a != b).into(),

            // < > <= >= for numbers (integers and floats cannot be mixed)
            (Gt, Num(Int(a)), Num(Int(b))) => (a > b).into(),
            (Lt, Num(Int(a)), Num(Int(b))) => (a < b).into(),
            (Gte, Num(Int(a)), Num(Int(b))) => (a >= b).into(),
            (Lte, Num(Int(a)), Num(Int(b))) => (a <= b).into(),

            (Gt, Num(Float(a)), Num(Float(b))) => (a > b).into(),
            (Lt, Num(Float(a)), Num(Float(b))) => (a < b).into(),
            (Gte, Num(Float(a)), Num(Float(b))) => (a >= b).into(),
            (Lte, Num(Float(a)), Num(Float(b))) => (a <= b).into(),

            // + - * / % for numbers (integers and floats cannot be mixed)
            (Add, Num(Int(a)), Num(Int(b))) => a.checked_add(b).ok_or(Error::Overflow)?.into(),
            (Subtract, Num(Int(a)), Num(Int(b))) => a.checked_sub(b).ok_or(Error::Overflow)?.into(),
            (Multiply, Num(Int(a)), Num(Int(b))) => a.checked_mul(b).ok_or(Error::Overflow)?.into(),
            (Divide, Num(Int(a)), Num(Int(b))) => a.checked_div(b).ok_or(Error::Overflow)?.into(),
            (Mod, Num(Int(a)), Num(Int(b))) => (a % b).into(),

            (Add, Num(Float(a)), Num(Float(b))) => (a + b).into(),
            (Subtract, Num(Float(a)), Num(Float(b))) => (a - b).into(),
            (Multiply, Num(Float(a)), Num(Float(b))) => (a * b).into(),
            (Divide, Num(Float(a)), Num(Float(b))) => (a / b).into(),
            (Mod, Num(Float(a)), Num(Float(b))) => (a % b).into(),

            // + for arrays, bytes and strings
            (Add, Array(a), Array(b)) => [a.0, b.0].concat().into(),
            (Add, Bytes(a), Bytes(b)) => [a, b].concat().into(),
            (Add, String(a), String(b)) => [a, b].concat().into(),
            // + for LHS string and any RHS
            (Add, String(a), b) => [a, b.to_string()].concat().into(),

            // A:B array tuple construction
            (Colon, a, b) => vec![a, b].into(),

            // + for taproot construction (internal_key+script_tree)
            (Add, key @ PubKey(_) | key @ SecKey(_), script_tree) => {
                stdlib::taproot::tr(key, Some(script_tree), &scope.borrow())?
            }

            // + to combine PSBTs
            (Add, Psbt(mut a), Psbt(b)) => {
                a.combine(b)?;
                a.into()
            }

            // * to repeat script fragments
            (Multiply, Script(s), Num(Int(n))) | (Multiply, Num(Int(n)), Script(s)) => {
                stdlib::btc::repeat_script(s, n.try_into()?).into()
            }

            // @ to assign execution probabilities (Script/Policy, or a PubKey/SecKey coerced into a pk() Policy)
            (Prob, Num(prob), v @ Policy(_) | v @ Script(_) | v @ PubKey(_) | v @ SecKey(_)) => {
                WithProb(prob.into_usize()?, v.into())
            }

            // Specialized error for mixed-up number types
            (_, lhs @ Num(Int(_)), rhs @ Num(Float(_)))
            | (_, lhs @ Num(Float(_)), rhs @ Num(Int(_))) => {
                bail!(Error::InfixOpMixedNum(lhs.into(), rhs.into()))
            }

            // Generic error for all other unmatched invocations
            (_, lhs, rhs) => bail!(Error::InfixOpArgs(lhs.into(), rhs.into())),
        })
    }
}

impl Evaluate for ast::SlashOp {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        use ast::{InfixOp, SlashRhs};

        // Overloaded for number division and BIP32 derivation, depending on the LHS
        match self.lhs.eval(scope)? {
            Value::Number(lhs) => {
                let rhs = match &self.rhs {
                    SlashRhs::Expr(expr) => expr.eval(scope)?,
                    _ => bail!(Error::SlashUnexpectedBip32Mod), // BIP32 modifiers (', h and *) cannot be used with number division
                };
                InfixOp::Divide
                    .apply(lhs.into(), rhs, scope)
                    .map_err(|e| Error::InfixOpError(InfixOp::Divide, e.into()))
            }
            lhs => {
                // Any non-number is assumed to be a BIP32-derivable type (PubKey, SecKey, Policy, Descriptor or arrays of them)
                stdlib::keys::eval_slash_bip32_derive(lhs, &self.rhs, scope)
                    .box_err(Error::SlashBip32Derive)
            }
        }
    }
}

lazy_static! {
    static ref MAIN: ast::Ident = "main".into();
}

impl Evaluate for ast::Block {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        // Execute the Block's stmts under a new child scope, with no visible side-effects
        let scope = scope.child().into_ref();
        self.stmts.exec(&scope)?;
        let scope = scope.into_readonly();

        if let Some(return_value) = &self.return_value {
            // Use the Block's final expression as its return value. Required for BlockExpr.
            return_value.eval(&scope)
        } else if let Some(main_fn) = self.use_main.then(|| scope.borrow().get(&MAIN)).flatten() {
            // Use main() as the return value. Only enabled for top-level programs.
            main_fn.call(vec![], &scope)
        } else {
            // Return an implicit true by default. Only allowed by the grammar for Blocks representing function bodies or programs.
            Ok(true.into())
        }
    }
}

impl Evaluate for Expr {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        Ok(match self {
            Expr::Ident(x) => x.eval(scope)?, // dedicated error type
            Expr::Call(x) => x.eval(scope)?,  // dedicated error type
            Expr::If(x) => x.eval(scope)?,
            Expr::Or(x) => x.eval(scope)?,
            Expr::And(x) => x.eval(scope)?,
            Expr::Thresh(x) => x.eval(scope).ctx("of")?,
            Expr::Block(x) => x.eval(scope)?,
            Expr::Array(x) => x.eval(scope)?, // .ctx("[]")?,
            Expr::ArrayAccess(x) => x.eval(scope).ctx("dot access")?,
            Expr::ScriptFrag(x) => x.eval(scope).ctx("`` script")?,
            Expr::FnExpr(x) => x.eval(scope)?, // cannot fail
            Expr::Infix(x) => x.eval(scope)?,  // dedicated error type
            Expr::SlashOp(x) => x.eval(scope)?,
            Expr::Not(x) => x.eval(scope)?,
            Expr::Negate(x) => x.eval(scope)?,
            Expr::BtcAmount(x) => x.eval(scope).ctx("BTC amount")?, // eval'd into a Number
            Expr::Duration(x) => x.eval(scope).ctx("time duration")?, // eval'd into a Number

            Expr::Address(x) => Value::Address(x.clone().assume_checked()),
            Expr::PubKey(x) => Value::PubKey(x.clone()),
            Expr::SecKey(x) => Value::SecKey(x.clone()),
            Expr::Bytes(x) => Value::Bytes(x.clone()),
            Expr::String(x) => Value::String(x.clone()),
            Expr::Int(x) => Value::Number(Number::Int(*x)),
            Expr::Float(x) => Value::Number(Number::Float(*x)),
            Expr::DateTime(x) => Value::Number(x.timestamp().into()), // eval's as number
        })
    }
}
trait RuntimeResultExt<T> {
    fn ctx(self, context_str: &'static str) -> Result<T>;
}
impl<T> RuntimeResultExt<T> for Result<T> {
    fn ctx(self, context_str: &'static str) -> Result<T> {
        self.map_err(|e| Error::ContextStr(context_str, Box::new(e)))
    }
}

/// Evaluate a list of expressions to produce a list of values
pub fn eval_exprs<T: Borrow<Expr>>(scope: &ScopeRef, exprs: &[T]) -> Result<Vec<Value>> {
    exprs.iter().map(|arg| arg.borrow().eval(scope)).collect()
}
