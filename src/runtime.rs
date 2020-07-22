use std::borrow::Borrow;
use std::convert::{TryFrom, TryInto};

use crate::ast::{self, Expr, Stmt};
use crate::error::{Error, Result};
use crate::function::{Call, Function};
use crate::miniscript::Policy;
use crate::scope::Scope;

/// A runtime value. This is what gets passed around as function arguments, returned from functions,
/// and assigned to variables.
#[derive(Debug, Clone)]
pub enum Value {
    Policy(Policy),
    Function(Function),
    Array(Array),
    Duration(Duration),
    DateTime(DateTime),
}

impl_from_variant!(Policy, Value);
impl_from_variant!(Function, Value);
impl_from_variant!(Array, Value);
impl_from_variant!(Duration, Value);
impl_from_variant!(DateTime, Value);

#[derive(Debug, Clone)]
pub struct Array(pub Vec<Value>);

#[derive(Debug, Clone)]
pub struct Duration(pub ast::Duration);

#[derive(Debug, Clone)]
pub struct DateTime(pub String);

/// Evaluate an expression. Expressions have no side-effects and return a value.
pub trait Evaluate {
    fn eval(&self, scope: &Scope) -> Result<Value>;
}

/// Execute a statement. Statements have side-effects and don't have a return value.
pub trait Execute {
    fn exec(&self, scope: &mut Scope) -> Result<()>;
}

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
        scope.set(self.ident.clone(), func.into())
    }
}

impl Execute for Stmt {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        match self {
            Stmt::FnDef(x) => x.exec(scope),
            Stmt::Assign(x) => x.exec(scope),
        }
    }
}

impl Evaluate for ast::Call {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        call(scope, &self.ident, &self.args)
    }
}

impl Evaluate for ast::Or {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        eval_andor("or", 1, &self.0, scope)
    }
}

impl Evaluate for ast::And {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        eval_andor("and", self.0.len(), &self.0, scope)
    }
}

// convert and/or calls with more than two args into thresh()
fn eval_andor(name: &str, thresh_n: usize, policies: &[Expr], scope: &Scope) -> Result<Value> {
    if policies.len() == 2 {
        // delegate to or()/and() when there are exactly 2 subpolicies
        call(scope, name, policies)
    } else {
        // delegate to thresh() when there are more
        let thresh_n = ast::TermWord(thresh_n.to_string()).into();
        let mut args = vec![&thresh_n];
        args.extend(policies);
        call(scope, "thresh", &args)
    }
}

impl Evaluate for ast::Thresh {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        call(scope, "thresh", &[&*self.thresh, &*self.policies])
    }
}

impl Evaluate for ast::TermWord {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        Ok(match scope.get(&self.0) {
            Some(binding) => binding.clone(),
            None if !self.0.starts_with('$') => Policy::word(&self.0).into(),
            None => bail!(Error::VarNotFound(self.0.clone())),
        })
    }
}

impl Evaluate for ast::Array {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let elements = eval_exprs(scope, &self.0)?;
        Ok(Array(elements).into())
    }
}

impl Evaluate for ast::Duration {
    fn eval(&self, _scope: &Scope) -> Result<Value> {
        Ok(Duration(self.clone()).into())
    }
}

impl Evaluate for ast::DateTime {
    fn eval(&self, _scope: &Scope) -> Result<Value> {
        Ok(DateTime(self.0.clone()).into())
    }
}

impl Evaluate for ast::ArrayAccess {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let elements = match self.array.eval(scope)? {
            Value::Array(Array(elements)) => Ok(elements),
            v => Err(Error::NotArray(v.clone())),
        }?;
        let index = self.index.eval(scope)?.into_usize()?;
        elements
            .get(index)
            .cloned()
            .ok_or_else(|| Error::ArrayIndexOutOfRange)
    }
}

impl Evaluate for ast::WithProb {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        call(scope, "prob", &[&*self.prob, &*self.expr])
    }
}

impl Evaluate for ast::Block {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let mut scope = scope.child();
        for stmt in &self.stmts {
            stmt.exec(&mut scope)?;
        }
        self.return_value.eval(&scope)
    }
}

impl Evaluate for Expr {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        match self {
            Expr::Call(x) => x.eval(scope),
            Expr::Or(x) => x.eval(scope),
            Expr::And(x) => x.eval(scope),
            Expr::Thresh(x) => x.eval(scope),
            Expr::Block(x) => x.eval(scope),
            Expr::TermWord(x) => x.eval(scope),
            Expr::WithProb(x) => x.eval(scope),
            Expr::Array(x) => x.eval(scope),
            Expr::ArrayAccess(x) => x.eval(scope),
            Expr::Duration(x) => x.eval(scope),
            Expr::DateTime(x) => x.eval(scope),
        }
    }
}

/// Call the function with the given expressions evaluated into values
fn call<T: Borrow<Expr>>(scope: &Scope, ident: &str, exprs: &[T]) -> Result<Value> {
    let func = scope
        .get(ident)
        .ok_or_else(|| Error::FnNotFound(ident.into()))?;

    let args = eval_exprs(scope, exprs)?;

    func.call(args, scope)
}

/// Evaluate a list of expressions to produce a list of values
fn eval_exprs<T: Borrow<Expr>>(scope: &Scope, exprs: &[T]) -> Result<Vec<Value>> {
    exprs.iter().map(|arg| arg.borrow().eval(scope)).collect()
}

impl TryFrom<Value> for Policy {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Policy(policy) => Ok(policy),
            v => Err(Error::NotMiniscriptRepresentable(v)),
        }
    }
}

impl TryFrom<Value> for usize {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match &value {
            Value::Policy(Policy::TermWord(n)) => {
                n.parse().map_err(|_| Error::NotNumber(value.clone()))
            }
            v => Err(Error::NotNumber(v.clone())),
        }
        // TODO add a real Value::Number type?
    }
}

impl Value {
    pub fn into_policy(self) -> Result<Policy> {
        self.try_into()
    }
    pub fn into_usize(self) -> Result<usize> {
        self.try_into()
    }
}
