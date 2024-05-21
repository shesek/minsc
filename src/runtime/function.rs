use std::fmt;

use crate::parser::{ast, Expr, Ident};
use crate::runtime::{Array, Error, Evaluate, Result, ScopeRef, Value};
use crate::stdlib::fns::throw as stdlib_throw;

#[derive(Debug, Clone)]
pub enum Function {
    User(UserFunction),
    Native(NativeFunction),
}

/// A user-defined function implemented in Minsc
#[derive(Clone)]
pub struct UserFunction {
    pub ident: Option<Ident>,
    pub signature: Vec<Ident>,
    pub body: Expr,
    pub scope: ScopeRef,
}
impl_from_variant!(UserFunction, Function, User);

/// A native function implemented in Rust
#[derive(Debug, Clone)]
pub struct NativeFunction {
    ident: Option<Ident>,
    pt: NativeFunctionPt,
}

pub type NativeFunctionPt = fn(Array, &ScopeRef) -> Result<Value>;

impl_from_variant!(NativeFunction, Function, Native);

pub trait Call {
    fn call(&self, args: Vec<Value>, caller_scope: &ScopeRef) -> Result<Value>;
}

impl Call for Function {
    fn call(&self, args: Vec<Value>, caller_scope: &ScopeRef) -> Result<Value> {
        match self {
            Function::User(f) => f.call(args, caller_scope),
            Function::Native(f) => f.call(args, caller_scope), // wraps with CallError context internally
        }
    }
}

impl Call for UserFunction {
    fn call(&self, args: Vec<Value>, _caller_scope: &ScopeRef) -> Result<Value> {
        let _call = || {
            ensure!(
                self.signature.len() == args.len(),
                Error::InvalidArgumentsError(
                    Error::InvalidLength(args.len(), self.signature.len()).into(),
                )
            );
            let scope = self.scope.child();
            {
                let mut scope = scope.borrow_mut();
                for (index, value) in args.into_iter().enumerate() {
                    let ident = self.signature.get(index).unwrap();
                    scope.set(ident.clone(), value)?;
                }
            }
            self.body.eval(&scope.into_readonly())
        };
        _call().map_err(|e| Error::CallError(self.ident.clone(), e.into()))
    }
}

impl Call for NativeFunction {
    fn call(&self, args: Vec<Value>, caller_scope: &ScopeRef) -> Result<Value> {
        (self.pt)(Array(args), caller_scope).map_err(|e| {
            if self.pt == stdlib_throw {
                e // Don't include the `throw()` function in the CallError stack context.
            } else {
                Error::CallError(self.ident.clone(), e.into())
            }
        })
    }
}

impl Call for Value {
    fn call(&self, args: Vec<Value>, caller_scope: &ScopeRef) -> Result<Value> {
        match self {
            Value::Function(func) => func.call(args, caller_scope),
            v => Err(Error::NotFn(v.clone().into())),
        }
    }
}

impl NativeFunction {
    pub fn new(pt: NativeFunctionPt, ident: Option<Ident>) -> Self {
        Self { pt, ident }
    }
}

impl From<NativeFunctionPt> for Function {
    fn from(pt: NativeFunctionPt) -> Self {
        NativeFunction { pt, ident: None }.into()
    }
}

impl Function {
    /// From a named function definition statement
    pub fn from_def(fn_def: ast::FnDef, scope: ScopeRef) -> Self {
        UserFunction {
            ident: Some(fn_def.ident),
            signature: fn_def.signature,
            body: fn_def.body,
            scope,
        }
        .into()
    }

    /// From an anonymous function expression
    pub fn from_expr(fn_expr: ast::FnExpr, scope: ScopeRef) -> Self {
        UserFunction {
            ident: None,
            signature: fn_expr.signature,
            body: *fn_expr.body,
            scope,
        }
        .into()
    }
}

impl PartialEq for Function {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Function::Native(a), Function::Native(b)) => a.pt as usize == b.pt as usize,
            (Function::Native(_), Function::User(_)) | (Function::User(_), Function::Native(_)) => {
                false
            }
            (Function::User(_), Function::User(_)) => {
                // TODO this requires implementing PartialEq for ast::Expr
                false
            }
        }
    }
}

impl fmt::Debug for UserFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UserFunction")
            .field("ident", &self.ident)
            .field("signature", &self.signature)
            .field("body", &self.body)
            .field("scoping", &iif!(self.scope.is_some(), "lexical", "dynamic"))
            .finish()
    }
}

impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Function::User(func) => write!(f, "{}", func),
            Function::Native(func) => write!(f, "{}", func),
        }
    }
}
impl fmt::Display for UserFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "fn ")?;
        if let Some(ident) = &self.ident {
            write!(f, "{}", ident)?;
        }
        write!(f, "(")?;
        for (i, arg_name) in self.signature.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", arg_name)?;
        }
        write!(f, ")")
    }
}
impl fmt::Display for NativeFunction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "fn ")?;
        if let Some(ident) = &self.ident {
            write!(f, "{}", ident)?;
        }
        write!(f, "([native])")
    }
}
