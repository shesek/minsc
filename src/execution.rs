use std::ops::Deref;

use crate::ast::{self, Expr, FnDef, Ident, Stmt};
use crate::error::{Error, Result};
use crate::miniscript::{self, Policy};
use crate::scope::Scope;

/// A runtime value. This is what gets passed around as function arguments, returned from functions,
/// and assigned to variables.
///
/// This can either be an evaluated miniscript `Policy` or a function.
#[derive(Debug, Clone)]
pub enum Value {
    Policy(miniscript::Policy),
    FnDef(ast::FnDef),
    FnNative(Ident),
}

impl_from_variant!(Policy, Value);
impl_from_variant!(FnDef, Value);

/// Evaluate an expression. Expressions have no side-effects and return a value.
pub trait Evaluate {
    fn eval(&self, scope: &Scope) -> Result<Value>;
}

/// Run a statement. Statements have side-effects and don't have a return value.
pub trait Run {
    fn run(&self, scope: &mut Scope) -> Result<()>;
}

impl Run for ast::Assign {
    fn run(&self, scope: &mut Scope) -> Result<()> {
        let value = self.value.deref().eval(scope)?;
        scope.set(self.name.clone(), value)
    }
}

impl Run for ast::FnDef {
    fn run(&self, scope: &mut Scope) -> Result<()> {
        scope.set(self.name.clone(), self.clone().into())
    }
}

impl Run for Stmt {
    fn run(&self, scope: &mut Scope) -> Result<()> {
        match self {
            Stmt::FnDef(x) => x.run(scope),
            Stmt::Assign(x) => x.run(scope),
        }
    }
}

impl Evaluate for ast::FnCall {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let func = scope
            .get(&self.name)
            .ok_or_else(|| Error::FnNotFound(self.name.clone()))?;

        let args = eval_exprs(scope, &self.args)?;
        Ok(match func {
            Value::FnDef(fn_def) => fn_def.call(args, scope)?,
            Value::FnNative(name) => {
                miniscript::Policy::FnCall(name.clone(), map_policy(args)?).into()
            }
            _ => return Err(Error::NotFn(self.name.clone())),
        })
    }
}

impl Evaluate for ast::Or {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        ast::FnCall {
            name: "or".into(),
            args: self.0.clone(),
        }
        .eval(scope)
    }
}

impl Evaluate for ast::And {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        ast::FnCall {
            name: "and".into(),
            args: self.0.clone(),
        }
        .eval(scope)
    }
}

impl Evaluate for ast::TermWord {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        Ok(match scope.get(&self.0) {
            Some(binding) => binding.clone(),
            None => miniscript::Policy::Value(self.0.clone()).into(),
            // TODO error if a $ binding is passed through
        })
    }
}

impl Evaluate for ast::Block {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let mut scope = Scope::derive(scope);
        for stmt in &self.stmts {
            stmt.run(&mut scope)?;
        }
        self.return_value.eval(&scope)
    }
}

impl ast::FnDef {
    fn call(&self, args: Vec<Value>, scope: &Scope) -> Result<Value> {
        if self.args.len() != args.len() {
            return Err(Error::ArgumentMismatch(
                self.name.clone(),
                self.args.len(),
                args.len(),
            ));
        }
        let mut scope = scope.child();
        for (index, value) in args.into_iter().enumerate() {
            let ident = self.args.get(index).unwrap();
            scope.set(ident.clone(), value)?;
        }
        self.body.eval(&scope)
    }
}

impl Evaluate for Expr {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        match self {
            Expr::FnCall(x) => x.eval(scope),
            Expr::Or(x) => x.eval(scope),
            Expr::And(x) => x.eval(scope),
            Expr::Block(x) => x.eval(scope),
            Expr::TermWord(x) => x.eval(scope),
        }
    }
}

impl std::convert::TryFrom<Value> for miniscript::Policy {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Policy(policy) => Ok(policy),
            _ => Err(Error::NotMiniscriptRepresentable),
        }
    }
}

impl Value {
    pub fn into_policy(self) -> Result<miniscript::Policy> {
        std::convert::TryInto::try_into(self)
    }
}

fn eval_exprs(scope: &Scope, list: &Vec<Expr>) -> Result<Vec<Value>> {
    list.iter().map(|arg| arg.eval(scope)).collect()
}

fn map_policy(list: Vec<Value>) -> Result<Vec<Policy>> {
    list.into_iter().map(Value::into_policy).collect()
}
