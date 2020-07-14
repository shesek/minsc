use std::convert::{TryFrom, TryInto};
use std::ops::Deref;

use crate::ast::{self, Expr, Stmt};
use crate::error::{Error, Result};
use crate::function::{Call, Function};
use crate::miniscript::Policy;
use crate::scope::Scope;

/// A runtime value. This is what gets passed around as function arguments, returned from functions,
/// and assigned to variables.
///
/// This can either be an evaluated miniscript `Policy`, a function or an array.
#[derive(Debug, Clone)]
pub enum Value {
    Policy(Policy),
    Function(Function),
    Array(Array),
}

impl_from_variant!(Policy, Value);
impl_from_variant!(Function, Value);
impl_from_variant!(Array, Value);

#[derive(Debug, Clone)]
pub struct Array(pub Vec<Value>);

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
        let func = scope
            .get(&self.ident)
            .ok_or_else(|| Error::FnNotFound(self.ident.clone()))?;
        let args = eval_exprs(scope, &self.args)?;

        func.call(args, scope)
    }
}

impl Evaluate for ast::Or {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        eval_andor("or", 1, self.0.clone(), scope)
    }
}

impl Evaluate for ast::And {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        eval_andor("and", self.0.len(), self.0.clone(), scope)
    }
}

// convert and/or calls with more than two args into thresh()
fn eval_andor(frag: &str, n: usize, args: Vec<Expr>, scope: &Scope) -> Result<Value> {
    if args.len() == 2 {
        ast::Call {
            ident: frag.into(),
            args,
        }
        .eval(scope)
    } else {
        let thresh: Expr = ast::TermWord(n.to_string()).into();
        ast::Thresh {
            thresh: thresh.into(),
            exprs: args,
        }
        .eval(scope)
    }
}

impl Evaluate for ast::Thresh {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let mut args = self.exprs.clone();
        args.insert(0, self.thresh.deref().clone());
        ast::Call {
            ident: "thresh".into(),
            args,
        }
        .eval(scope)
    }
}

impl Evaluate for ast::TermWord {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        Ok(match scope.get(&self.0) {
            Some(binding) => binding.clone(),
            None => Policy::TermWord(self.0.clone()).into(),
            // TODO error if a $ binding is passed through
        })
    }
}

impl Evaluate for ast::Array {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let elements = eval_exprs(scope, &self.0)?;
        Ok(Array(elements).into())
    }
}

impl Evaluate for ast::ArrayAccess {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let elements = match self.array.eval(scope)? {
            Value::Array(Array(elements)) => Ok(elements),
            v => Err(Error::NotArray(v.clone())),
        }?;
        // XXX supports literal indexes only
        let index: usize = match &*self.index {
            Expr::TermWord(ast::TermWord(w)) => w.parse().map_err(|_| Error::InvalidArrayIndex),
            _ => Err(Error::InvalidArrayIndex),
        }?;
        elements
            .get(index)
            .cloned()
            .ok_or_else(|| Error::ArrayIndexOutOfRange)
    }
}

impl Evaluate for ast::WithProb {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let prob = self.prob.eval(scope)?.into_policy()?;
        let prob = match prob {
            Policy::TermWord(n) => n.parse().map_err(|_| Error::InvalidProb(n)),
            _ => Err(Error::InvalidProb(format!("{:?}", prob))),
        }?;
        let policy = self.expr.eval(scope)?.into_policy()?;
        Ok(Policy::WithProb(prob, policy.into()).into())
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
        }
    }
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

impl Value {
    pub fn into_policy(self) -> Result<Policy> {
        self.try_into()
    }
}

fn eval_exprs(scope: &Scope, exprs: &Vec<Expr>) -> Result<Vec<Value>> {
    exprs.iter().map(|arg| arg.eval(scope)).collect()
}
