use std::borrow::Borrow;
use std::convert::TryInto;

use crate::parser::{ast, Expr, Stmt};
use crate::stdlib;
pub use ast::AssignTarget;

pub use crate::error::{ResultExt, RuntimeError as Error};
pub type Result<T> = std::result::Result<T, Error>;

pub mod array;
pub mod display;
pub mod function;
pub mod scope;
pub mod value;

pub use array::Array;
pub use display::PrettyDisplay;
pub use function::{Call, Function};
pub use scope::{Mutable, ReadOnly, Scope, ScopeRef};
pub use value::{ExprRepr, FromValue, Symbol, Value};

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
            assignment.lhs.unpack(value, &mut scope.borrow_mut())?;
        }
        Ok(())
    }
}

impl Execute for ast::FnDef {
    fn exec(&self, scope: &ScopeRef<Mutable>) -> Result<()> {
        let func = Function::from_def(self.clone(), scope.as_readonly());
        scope
            .borrow_mut()
            .set(self.ident.clone(), Value::function(func))
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

#[derive(Debug)]
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
        other => Err(Error::InvalidAndOrOperand(andor, other.into())),
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

impl std::fmt::Display for AndOr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::And => write!(f, "&&"),
            Self::Or => write!(f, "||"),
        }
    }
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
            Value::String(string) => {
                ensure!(index < string.len(), Error::ArrayIndexOutOfRange);
                string[index..=index].into()
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

impl Evaluate for ast::FieldAccess {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let target = self.target.eval(scope)?;
        let field = self.field.eval(scope)?;
        let result = target.get_field(&field);
        if self.check_exists {
            Ok(result.is_some().into())
        } else {
            result.ok_or_else(|| Error::FieldNotFound(field.into()))
        }
    }
}
pub trait FieldAccess: Sized {
    fn get_field(self, _field: &Value) -> Option<Value>;
}

impl Evaluate for ast::FnExpr {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let func = Function::from_expr(self.clone(), scope.clone_ref());
        Ok(Value::function(func))
    }
}

impl Evaluate for ast::Not {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        Ok((!self.0.eval(scope)?.into_bool()?).into())
    }
}

impl Evaluate for ast::Negate {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        Ok(match self.0.eval(scope)? {
            Value::Int(n) => (-n).into(),
            Value::Float(n) => (-n).into(),
            other => bail!(Error::NotNumber(other.into())),
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
            Array, Bytes, Float, Int, Policy, Psbt, PubKey, Script, SecKey, String, WithProb,
        };

        Ok(match (self, lhs, rhs) {
            // == != for all types
            (Eq, a, b) => (a == b).into(),
            (NotEq, a, b) => (a != b).into(),

            // < > <= >= for numbers (integers and floats cannot be mixed)
            (Gt, Int(a), Int(b)) => (a > b).into(),
            (Lt, Int(a), Int(b)) => (a < b).into(),
            (Gte, Int(a), Int(b)) => (a >= b).into(),
            (Lte, Int(a), Int(b)) => (a <= b).into(),

            (Gt, Float(a), Float(b)) => (a > b).into(),
            (Lt, Float(a), Float(b)) => (a < b).into(),
            (Gte, Float(a), Float(b)) => (a >= b).into(),
            (Lte, Float(a), Float(b)) => (a <= b).into(),

            // + - * / % ** for numbers (integers and floats cannot be mixed)
            (Add, Int(a), Int(b)) => a.checked_add(b).ok_or(Error::Overflow)?.into(),
            (Subtract, Int(a), Int(b)) => a.checked_sub(b).ok_or(Error::Overflow)?.into(),
            (Multiply, Int(a), Int(b)) => a.checked_mul(b).ok_or(Error::Overflow)?.into(),
            (Divide, Int(a), Int(b)) => a.checked_div(b).ok_or(Error::Overflow)?.into(),
            (Mod, Int(a), Int(b)) => a.checked_rem(b).ok_or(Error::Overflow)?.into(),
            (Power, Int(a), Int(b)) => a.checked_pow(b.try_into()?).ok_or(Error::Overflow)?.into(),

            (Add, Float(a), Float(b)) => (a + b).into(),
            (Subtract, Float(a), Float(b)) => (a - b).into(),
            (Multiply, Float(a), Float(b)) => (a * b).into(),
            (Divide, Float(a), Float(b)) => (a / b).into(),
            (Mod, Float(a), Float(b)) => (a % b).into(),
            (Power, Float(a), Float(b)) => a.powf(b).into(),

            // + for arrays, bytes and strings
            (Add, Array(a), Array(b)) => [a.0, b.0].concat().into(),
            (Add, Bytes(a), Bytes(b)) => [a, b].concat().into(),
            (Add, String(a), String(b)) => [a, b].concat().into(),
            // + for LHS String and any RHS
            (Add, String(a), b) => [a, b.to_string()].concat().into(),
            // + for LHS Bytes and any Bytes-coercible RHS
            (Add, Bytes(a), b) => [a, b.into_bytes()?].concat().into(),

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
            (Multiply, Script(s), Int(n)) | (Multiply, Int(n), Script(s)) => {
                stdlib::btc::repeat_script(s, n.try_into()?).into()
            }

            // @ to assign execution probabilities (Script/Policy, or a PubKey/SecKey coerced into a pk() Policy)
            (Prob, Int(prob), v @ Policy(_) | v @ Script(_) | v @ PubKey(_) | v @ SecKey(_)) => {
                WithProb(prob.try_into()?, v.into())
            }

            // Specialized error for mixed-up number types
            (_, lhs @ Int(_), rhs @ Float(_)) | (_, lhs @ Float(_), rhs @ Int(_)) => {
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
            lhs @ Value::Int(_) | lhs @ Value::Float(_) => {
                let rhs = match &self.rhs {
                    SlashRhs::Expr(expr) => expr.eval(scope)?,
                    _ => bail!(Error::SlashUnexpectedBip32Mod), // BIP32 modifiers (', h and *) cannot be used with number division
                };
                InfixOp::Divide
                    .apply(lhs, rhs, scope)
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
        let scope = if self.stmts.is_empty() {
            // If there aren't any statements, we can evaluate the Block's return value directly under its parent scope
            scope.clone_ref()
        } else {
            // Execute the Block's statements under a new child scope, with no visible side-effects in the parent scope
            let child_scope = scope.child().into_ref();
            self.stmts.exec(&child_scope)?;
            child_scope.into_readonly()
        };

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

impl ast::AssignTarget {
    pub fn unpack(&self, value: Value, scope: &mut Scope) -> Result<()> {
        match self {
            AssignTarget::Ident(ident) if ident.0 == "_" => Ok(()),
            AssignTarget::Ident(ident) => scope.set(ident.clone(), value),
            AssignTarget::List(targets) => {
                let array = match value {
                    Value::Array(array) => array,
                    Value::Descriptor(d) if d.is_multipath() => d.into_single_descriptors()?.into(),
                    Value::PubKey(pk) if pk.is_multipath() => pk.into_single_keys().into(),
                    Value::SecKey(sk) if sk.is_multipath() => sk.into_single_keys().into(),
                    other => bail!(Error::UnpackArrayExpected(
                        self.clone().into(),
                        other.into()
                    )),
                };
                ensure!(
                    targets.len() == array.len(),
                    Error::UnpackInvalidArrayLen(array.len(), targets.len(), self.clone().into())
                );
                for (target, array_el) in targets.iter().zip(array) {
                    target.unpack(array_el, scope)?;
                }
                Ok(())
            }
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
            Expr::Array(x) => x.eval(scope)?,
            Expr::ArrayAccess(x) => x.eval(scope)?,
            Expr::FieldAccess(x) => x.eval(scope)?,
            Expr::ScriptFrag(x) => x.eval(scope).ctx("`` script")?,
            Expr::FnExpr(x) => x.eval(scope)?, // cannot fail
            Expr::Infix(x) => x.eval(scope)?,  // dedicated error type
            Expr::SlashOp(x) => x.eval(scope)?,
            Expr::Not(x) => x.eval(scope)?,
            Expr::Negate(x) => x.eval(scope)?,
            Expr::BtcAmount(x) => x.eval(scope)?, // eval'd into an Int
            Expr::Duration(x) => x.eval(scope)?,  // eval'd into an Int

            Expr::Address(x) => Value::Address(x.clone().assume_checked()),
            Expr::PubKey(x) => Value::PubKey(x.clone()),
            Expr::SecKey(x) => Value::SecKey(x.clone()),
            Expr::Bytes(x) => Value::Bytes(x.clone()),
            Expr::String(x) => Value::String(x.clone()),
            Expr::Int(x) => Value::Int(*x),
            Expr::Float(x) => Value::Float(*x),
            Expr::DateTime(x) => Value::Int(x.timestamp()),
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
