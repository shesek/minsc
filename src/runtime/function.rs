use std::fmt;

use crate::parser::{ast, Expr, FnParams, Ident};
use crate::runtime::{Array, Error, Evaluate, Result, ScopeRef, Value};

#[derive(Debug, Clone)]
pub enum Function {
    User(UserFunction),
    Native(NativeFunction),
}

/// A user-defined function implemented in Minsc
#[derive(Clone)]
pub struct UserFunction {
    pub ident: Option<Ident>,
    pub params: FnParams,
    pub body: Expr,
    pub scope: Option<ScopeRef>,
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
        let (res, ident) = match self {
            Function::User(f) => (f.call(args, caller_scope), &f.ident),
            Function::Native(f) => (f.call(args, caller_scope), &f.ident),
        };
        // Wrap errors with a CallError stack context, except for throw() which is excluded
        if !ident.as_ref().is_some_and(|ident| ident.0 == "throw") {
            res.map_err(|e| Error::CallError(ident.clone(), e.into()))
        } else {
            res
        }
    }
}

impl Call for UserFunction {
    fn call(&self, args: Vec<Value>, caller_scope: &ScopeRef) -> Result<Value> {
        let min_args = self.params.required.len();
        let max_args = min_args + self.params.optional.len();
        ensure!(
            args.len() >= min_args && args.len() <= max_args,
            Error::InvalidArgumentsError(
                Error::invalid_length(args.len(), min_args, max_args).into()
            )
        );
        let mut args = args.into_iter();

        // For lexically-scoped functions, create a child scope of the scope where the function was defined.
        // For dynamically-scoped function, create a child of the caller scope.
        let mut scope = self.scope.as_ref().unwrap_or(caller_scope).child();

        for param_target in self.params.required.iter() {
            let arg_value = args.next().expect("checked");
            param_target.unpack(arg_value, &mut scope)?;
        }

        // A shared ScopeRef is needed for optional parameters, to evaluate their default value (which may refer previous parameters)
        let scope = scope.into_ref();
        for (param_target, default_value) in self.params.optional.iter() {
            let arg_value = match args.next() {
                Some(val) => val,
                None => default_value.eval(&scope.as_readonly())?,
            };
            param_target.unpack(arg_value, &mut scope.borrow_mut())?;
        }

        self.body.eval(&scope.into_readonly())
    }
}

impl Call for NativeFunction {
    fn call(&self, args: Vec<Value>, caller_scope: &ScopeRef) -> Result<Value> {
        (self.pt)(Array(args), caller_scope)
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
            params: fn_def.params,
            body: fn_def.body,
            scope: iif!(!fn_def.dynamic_scoping, Some(scope), None),
        }
        .into()
    }

    /// From an anonymous function expression
    pub fn from_expr(fn_expr: ast::FnExpr, scope: ScopeRef) -> Self {
        UserFunction {
            ident: None,
            params: fn_expr.params,
            body: *fn_expr.body,
            scope: iif!(!fn_expr.dynamic_scoping, Some(scope), None),
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
        let mut fd = f.debug_struct("UserFunction");
        fd.field("ident", &self.ident)
            .field("params", &self.params)
            .field("body", &self.body);
        if self.scope.is_none() {
            fd.field("dynamic_scope", &true);
        }
        fd.finish()
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
        if self.scope.is_none() {
            write!(f, "dyn ")?;
        }
        write!(f, "fn ")?;
        if let Some(ident) = &self.ident {
            write!(f, "{}", ident)?;
        }
        write!(f, "(")?;
        for (i, param_name) in self.params.required.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", param_name)?;
        }
        for (i, (param_name, _default)) in self.params.optional.iter().enumerate() {
            if !self.params.required.is_empty() || i > 0 {
                write!(f, ", ")?;
            }
            // _default Expr is not Display-able, just show a '?' to indicate its optional
            write!(f, "{}?", param_name)?;
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
