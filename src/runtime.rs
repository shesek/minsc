use std::borrow::Borrow;
use std::convert::{TryFrom, TryInto};

use miniscript::bitcoin::hashes::{self, hex::FromHex, Hash};
use miniscript::descriptor::DescriptorPublicKey;

use crate::ast::{self, Expr, Stmt};
use crate::error::{Error, Result};
use crate::function::{Call, Function};
use crate::miniscript::{fns, Policy};
use crate::scope::Scope;

/// A runtime value. This is what gets passed around as function arguments, returned from functions,
/// and assigned to variables.
#[derive(Debug, Clone)]
pub enum Value {
    PubKey(DescriptorPublicKey),
    Hash(Vec<u8>),
    Number(usize),
    DateTime(String),
    Duration(ast::Duration),

    Policy(Policy),
    WithProb(usize, Policy),

    Function(Function),
    Array(Array),
}

impl_from_variant!(Policy, Value);
impl_from_variant!(Function, Value);
impl_from_variant!(Array, Value);
impl_from_variant!(usize, Value, Number);

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
        call(scope, &name.into(), policies)
    } else {
        // delegate to thresh() when there are more
        let thresh_n = ast::Expr::Number(thresh_n).into();
        let mut args = vec![&thresh_n];
        args.extend(policies);
        call(scope, &"thresh".into(), &args)
    }
}

impl Evaluate for ast::Thresh {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        call(scope, &"thresh".into(), &[&*self.thresh, &*self.policies])
    }
}

impl Evaluate for ast::Ident {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        Ok(match scope.get(&self) {
            Some(binding) => binding.clone(),
            None => bail!(Error::VarNotFound(self.clone())),
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
            v => Err(Error::NotArray(v)),
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
        call(scope, &"prob".into(), &[&*self.prob, &*self.expr])
    }
}

impl Evaluate for ast::Block {
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
            Expr::Ident(x) => x.eval(scope)?,
            Expr::Call(x) => x.eval(scope)?,
            Expr::Or(x) => x.eval(scope)?,
            Expr::And(x) => x.eval(scope)?,
            Expr::Thresh(x) => x.eval(scope)?,
            Expr::Block(x) => x.eval(scope)?,
            Expr::WithProb(x) => x.eval(scope)?,
            Expr::Array(x) => x.eval(scope)?,
            Expr::ArrayAccess(x) => x.eval(scope)?,

            // Atoms
            Expr::PubKey(x) => Value::PubKey(x.parse()?),
            Expr::Hash(x) => Value::Hash(Vec::from_hex(&x)?),
            Expr::Number(x) => Value::Number(*x),
            Expr::Duration(x) => Value::Duration(x.clone()),
            Expr::DateTime(x) => Value::DateTime(x.clone()),
        })
    }
}

/// Call the function with the given expressions evaluated into values
fn call<T: Borrow<Expr>>(scope: &Scope, ident: &ast::Ident, exprs: &[T]) -> Result<Value> {
    let func = scope
        .get(ident)
        .ok_or_else(|| Error::FnNotFound(ident.clone()))?;

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
            arr @ Value::Array(Array(_)) => fns::all(vec![arr])?.try_into(),
            v => Err(Error::NotMiniscriptRepresentable(v)),
        }
    }
}

impl TryFrom<Value> for usize {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Number(n) => Ok(n),
            v => Err(Error::NotNumber(v)),
        }
    }
}

impl TryFrom<Value> for DescriptorPublicKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::PubKey(x) => Ok(x),
            v => Err(Error::NotPubKey(v)),
        }
    }
}

macro_rules! impl_hash_conv {
    ($name:path) => {
        impl TryFrom<Value> for $name {
            type Error = Error;
            fn try_from(value: Value) -> Result<Self> {
                match value {
                    Value::Hash(h) => Ok(Self::from_slice(&h)?),
                    v => Err(Error::NotHash(v)),
                }
            }
        }
    };
}

impl_hash_conv!(hashes::sha256::Hash);
impl_hash_conv!(hashes::sha256d::Hash);
impl_hash_conv!(hashes::ripemd160::Hash);
impl_hash_conv!(hashes::hash160::Hash);

impl Value {
    pub fn is_array(&self) -> bool {
        match self {
            Value::Array(_) => true,
            _ => false,
        }
    }
    pub fn into_policy(self) -> Result<Policy> {
        self.try_into()
    }
    pub fn into_usize(self) -> Result<usize> {
        self.try_into()
    }
}
