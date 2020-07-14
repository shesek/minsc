use crate::ast::{self, Expr, Ident};
use crate::error::{Error, Result};
use crate::miniscript::Policy;
use crate::runtime::{Evaluate, Value};
use crate::scope::Scope;

#[derive(Debug, Clone)]
pub enum Function {
    User(UserFunction),
    Native(NativeFunction),
    Miniscript(MiniscriptFunction),
}

/// A user-defined function implemented in Minis
#[derive(Debug, Clone)]
pub struct UserFunction {
    pub ident: Ident,
    pub signature: Vec<Ident>,
    pub body: Expr,
}
impl_from_variant!(UserFunction, Function, User);

/// A native function implemented in Rust
#[derive(Debug, Clone)]
pub struct NativeFunction {
    pub ident: Ident,
    pub body: fn(Vec<Value>) -> Result<Value>,
}
impl_from_variant!(NativeFunction, Function, Native);

/// A function that yields Miniscript Policy fragments
#[derive(Debug, Clone)]
pub struct MiniscriptFunction {
    pub ident: Ident,
}
impl_from_variant!(MiniscriptFunction, Function, Miniscript);

pub trait Call {
    fn call(&self, args: Vec<Value>, scope: &Scope) -> Result<Value>;
}

impl Call for Function {
    fn call(&self, args: Vec<Value>, scope: &Scope) -> Result<Value> {
        match self {
            Function::User(x) => x.call(args, scope),
            Function::Native(x) => x.call(args, scope),
            Function::Miniscript(x) => x.call(args, scope),
        }
    }
}

impl Call for UserFunction {
    fn call(&self, args: Vec<Value>, scope: &Scope) -> Result<Value> {
        if self.signature.len() != args.len() {
            return Err(Error::ArgumentMismatch(
                self.ident.clone(),
                self.signature.len(),
                args.len(),
            ));
        }
        let mut scope = scope.child();
        for (index, value) in args.into_iter().enumerate() {
            let ident = self.signature.get(index).unwrap();
            scope.set(ident.clone(), value)?;
        }
        self.body.eval(&scope)
    }
}

impl Call for NativeFunction {
    fn call(&self, args: Vec<Value>, _scope: &Scope) -> Result<Value> {
        (self.body)(args)
    }
}

impl Call for MiniscriptFunction {
    fn call(&self, args: Vec<Value>, _scope: &Scope) -> Result<Value> {
        let args = args
            .into_iter()
            .map(Value::into_policy)
            .collect::<Result<_>>()?;
        let frag = Policy::Fragment(self.ident.clone(), args);
        Ok(frag.into())
    }
}

impl Call for Value {
    fn call(&self, args: Vec<Value>, scope: &Scope) -> Result<Value> {
        match self {
            Value::Function(func) => func.call(args, scope),
            v => Err(Error::NotFn(v.clone())),
        }
    }
}

impl From<ast::FnDef> for Function {
    fn from(fn_def: ast::FnDef) -> Self {
        UserFunction {
            ident: fn_def.ident,
            signature: fn_def.signature,
            body: fn_def.body,
        }
        .into()
    }
}
