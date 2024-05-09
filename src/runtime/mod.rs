use std::borrow::Borrow;
use std::convert::TryInto;

use crate::parser::{ast, Expr, Stmt};
use crate::stdlib;

pub use crate::error::RuntimeError as Error;
pub type Result<T> = std::result::Result<T, Error>;

pub mod array;
pub mod function;
pub mod scope;
pub mod value;
pub use array::Array;
pub use function::{Call, Function};
pub use scope::Scope;
pub use value::{FromValue, Number, Number::*, Symbol, Value};

/// Evaluate an expression. Expressions have no side-effects and return a value.
pub trait Evaluate {
    fn eval(&self, scope: &Scope) -> Result<Value>;
}

/// Execute a statement. Statements have side-effects and don't have a return value.
pub trait Execute {
    fn exec(&self, scope: &mut Scope) -> Result<()>;
}

//
// Execution
//

impl Execute for ast::Assign {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        for assignment in &self.0 {
            let value = assignment.rhs.eval(scope)?;
            scope.set(assignment.lhs.clone(), value)?;
        }
        Ok(())
    }
}

impl Execute for ast::FnDef {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        let func = Function::from(self.clone());
        scope.set(self.ident.clone(), func)
    }
}

impl Execute for ast::IfStmt {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        if self.condition.eval(scope)?.into_bool()? {
            self.then_body.exec(scope)
        } else if let Some(else_body) = &*self.else_body {
            else_body.exec(scope)
        } else {
            Ok(())
        }
    }
}

impl Execute for ast::Stmt {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        match self {
            Stmt::FnDef(x) => x.exec(scope),
            Stmt::Assign(x) => x.exec(scope),
            Stmt::If(x) => x.exec(scope),
        }
    }
}

impl Execute for ast::Stmts {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        for stmt in &self.0 {
            stmt.exec(scope)?;
        }
        Ok(())
    }
}

//
// Evaluation
//

impl Evaluate for ast::Call {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let func = self.func.eval(scope)?.into_fn()?;
        let args = eval_exprs(scope, &self.args)?;

        match (func.call(args, scope), self.func.as_ident()) {
            (Err(Error::CallError(None, e)), Some(caller_ident)) => {
                // If the function originating the error is unnamed but the caller called it using an identifier,
                // use the caller name for the CallError message. A name may not be available on the caller side
                // either if the function was not accessed through a simple identifier, for example `([a].0)()`
                Err(Error::CallError(Some(caller_ident.clone()), e.into()))
            }
            (other, _) => other,
        }
    }
}

impl Evaluate for ast::IfExpr {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        if self.condition.eval(scope)?.into_bool()? {
            self.then_val.eval(scope)
        } else {
            self.else_val.eval(scope)
        }
    }
}

impl Evaluate for ast::Or {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        eval_andor(&self.0, scope, AndOr::Or)
    }
}
impl Evaluate for ast::And {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        eval_andor(&self.0, scope, AndOr::And)
    }
}

pub enum AndOr {
    And,
    Or,
}

fn eval_andor(operands: &[Expr], scope: &Scope, andor: AndOr) -> Result<Value> {
    // Peek at the first operand to determine if its an operation between booleans or between policies.
    // All the other operands are expected to be of the same type. We don't pre-evaluate all of them
    // so that eval_bool_andor() may do so lazily.
    let first_operand = operands[0].eval(scope)?;
    match first_operand {
        Value::Bool(first_bool) => eval_bool_andor(first_bool, &operands[1..], scope, andor),
        Value::Policy(_) | Value::WithProb(_, _) | Value::PubKey(_) => {
            let policies = [&[first_operand], &eval_exprs(scope, &operands[1..])?[..]].concat();
            stdlib::miniscript::multi_andor(andor, policies)
        }
        _ => Err(Error::InvalidArguments),
    }
}

// Evaluate && / || for booleans (lazily evaluated)
fn eval_bool_andor(
    first_operand: bool,
    other_operands_exprs: &[Expr],
    scope: &Scope,
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
    fn eval(&self, scope: &Scope) -> Result<Value> {
        scope
            .get(&self)
            .cloned()
            .ok_or_else(|| Error::VarNotFound(self.clone()))
    }
}

impl Evaluate for ast::Array {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let elements = eval_exprs(scope, &self.0)?;
        Ok(elements.into())
    }
}

impl Evaluate for ast::ArrayAccess {
    fn eval(&self, scope: &Scope) -> Result<Value> {
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
            other => bail!(Error::NoArrayAccess(other)),
        })
    }
}

impl Evaluate for ast::FnExpr {
    fn eval(&self, _scope: &Scope) -> Result<Value> {
        Ok(Function::from(self.clone()).into())
    }
}

impl Evaluate for ast::Not {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        Ok((!self.0.eval(scope)?.into_bool()?).into())
    }
}

impl Evaluate for ast::Infix {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        self.op
            .apply(self.lhs.eval(scope)?, self.rhs.eval(scope)?, scope)
            .map_err(|e| Error::InfixOpError(self.op, e.into()))
    }
}

impl ast::InfixOp {
    fn apply(&self, lhs: Value, rhs: Value, scope: &Scope) -> Result<Value> {
        use ast::InfixOp::*;
        use Value::{Array, Bytes, Number as Num, Policy, PubKey, Script, String, WithProb};

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

            // + - * for numbers (integers and floats cannot be mixed)
            (Add, Num(Int(a)), Num(Int(b))) => a.checked_add(b).ok_or(Error::Overflow)?.into(),
            (Subtract, Num(Int(a)), Num(Int(b))) => a.checked_sub(b).ok_or(Error::Overflow)?.into(),
            (Multiply, Num(Int(a)), Num(Int(b))) => a.checked_mul(b).ok_or(Error::Overflow)?.into(),

            (Add, Num(Float(a)), Num(Float(b))) => (a + b).into(),
            (Subtract, Num(Float(a)), Num(Float(b))) => (a - b).into(),
            (Multiply, Num(Float(a)), Num(Float(b))) => (a * b).into(),

            // + for arrays, bytes and strings
            (Add, Array(a), Array(b)) => [a.0, b.0].concat().into(),
            (Add, Bytes(a), Bytes(b)) => [a, b].concat().into(),
            (Add, String(a), String(b)) => [a, b].concat().into(),

            // + for taproot construction (internal_key+script_tree)
            (Add, k @ PubKey(_), s)
            | (Add, k @ Bytes(_), s @ Script(_) | s @ Policy(_) | s @ Array(_)) => {
                stdlib::taproot::tr(k, Some(s), scope)?
            }

            // * to repeat script fragments
            (Multiply, s @ Script(_), Num(Int(n))) | (Multiply, Num(Int(n)), s @ Script(_)) => {
                vec![s; n.try_into()?].into()
            }

            // @ to assign execution probabilities (to Script/Policy only)
            (Prob, Num(prob), v @ Policy(_) | v @ Script(_)) => {
                WithProb(prob.into_usize()?, v.into())
            }

            // A:B array tuple construction
            (Colon, a, b) => vec![a, b].into(),

            // Specialized error for mixed-up number types
            (_, lhs @ Num(Int(_)), rhs @ Num(Float(_)))
            | (_, lhs @ Num(Float(_)), rhs @ Num(Int(_))) => {
                bail!(Error::InfixOpMixedNum(lhs, rhs))
            }

            // Generic error for all other unmatched invocations
            (_, lhs, rhs) => bail!(Error::InfixOpArgs(lhs, rhs)),
        })
    }
}

impl Evaluate for ast::Block {
    // Execute the block in a new child scope, with no visible side-effects.
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let mut scope = scope.child();
        for stmt in &self.stmts {
            stmt.exec(&mut scope)?;
        }
        if let Some(return_value) = &self.return_value {
            // The return value is the final expression within the function body,
            // optionally prefixed with the `return` keyword
            return_value.eval(&scope)
        } else if let Some(Value::Function(func)) = scope.get(&"main".into()) {
            // The return value is the evaluation of main()
            func.call(vec![], &scope)
        } else {
            Err(Error::NoReturnValue)
        }
    }
}

impl Evaluate for Expr {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        Ok(match self {
            Expr::Ident(x) => x.eval(scope)?, // dedicated error type
            Expr::Call(x) => x.eval(scope)?,  // dedicated error type
            Expr::If(x) => x.eval(scope).ctx("if")?,
            Expr::Or(x) => x.eval(scope).ctx("||")?,
            Expr::And(x) => x.eval(scope).ctx("&&")?,
            Expr::Thresh(x) => x.eval(scope).ctx("of")?,
            Expr::Block(x) => x.eval(scope)?,
            Expr::Array(x) => x.eval(scope).ctx("array construction")?,
            Expr::ArrayAccess(x) => x.eval(scope).ctx("dot access")?,
            Expr::ChildDerive(x) => x.eval(scope).ctx("xpub derivation")?,
            Expr::ScriptFrag(x) => x.eval(scope).ctx("`` script")?,
            Expr::FnExpr(x) => x.eval(scope)?, // cannot fail
            Expr::Infix(x) => x.eval(scope)?,  // dedicated error type
            Expr::Not(x) => x.eval(scope).ctx("! operator")?,
            Expr::BtcAmount(x) => x.eval(scope).ctx("BTC amount")?, // eval'd into a Number
            Expr::Duration(x) => x.eval(scope).ctx("time duration")?, // eval'd into a Number

            Expr::Address(x) => Value::Address(x.clone().assume_checked()),
            Expr::PubKey(x) => Value::PubKey(x.clone()),
            Expr::Bytes(x) => Value::Bytes(x.clone()),
            Expr::String(x) => Value::String(x.clone()),
            Expr::Int(x) => Value::Number(Number::Int(*x)),
            Expr::Float(x) => Value::Number(Number::Float(*x)),
            Expr::DateTime(x) => Value::Number(x.timestamp().into()), // eval's as number
        })
    }
}
trait ResultExt<T> {
    fn ctx(self, context_str: &'static str) -> Result<T>;
}
impl<T> ResultExt<T> for Result<T> {
    fn ctx(self, context_str: &'static str) -> Result<T> {
        self.map_err(|e| Error::ContextStr(context_str, e.into()))
    }
}

/// Evaluate a list of expressions to produce a list of values
pub fn eval_exprs<T: Borrow<Expr>>(scope: &Scope, exprs: &[T]) -> Result<Vec<Value>> {
    exprs.iter().map(|arg| arg.borrow().eval(scope)).collect()
}
