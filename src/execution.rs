use std::ops::Deref;

use crate::ast::{self, Expr, Stmt};
use crate::miniscript::Policy;
use crate::{Error, Scope};

/// Evaluate an expression. Expressions have no side-effects and return a value.
pub trait Evaluate {
    fn eval(&self, scope: &Scope) -> Result<Expr, Error>;
}

/// Run a statement. Statements have side-effects and don't have a return value.
pub trait Run {
    fn run(&self, scope: &mut Scope) -> Result<(), Error>;
}

/// Transpilte a minis expression into miniscript policy
pub trait Transpile {
    fn transpile(&self) -> Policy;
}

impl Run for ast::Assign {
    fn run(&self, scope: &mut Scope) -> Result<(), Error> {
        let value = self.value.deref().eval(scope)?;
        scope.set(self.name.clone(), value)
    }
}

impl Run for ast::FnDef {
    fn run(&self, scope: &mut Scope) -> Result<(), Error> {
        scope.set(self.name.clone(), self.clone().into())
    }
}

impl Run for Stmt {
    fn run(&self, scope: &mut Scope) -> Result<(), Error> {
        match self {
            Stmt::FnDef(x) => x.run(scope),
            Stmt::Assign(x) => x.run(scope),
        }
    }
}

impl Evaluate for ast::FnCall {
    fn eval(&self, scope: &Scope) -> Result<Expr, Error> {
        let func = scope
            .get(&self.name)
            .ok_or_else(|| Error::FnNotFound(self.name.clone()))?;
        let args = eval_exprs(scope, &self.args)?;

        Ok(match func {
            Expr::FnDef(fn_def) => fn_def.call(args, scope)?,
            Expr::FnNative(ast::FnNative(name)) => ast::FnCall {
                name: name.clone(),
                args,
            }
            .into(),
            _ => return Err(Error::NotFn(self.name.clone())),
        })
    }
}

impl Evaluate for ast::Or {
    fn eval(&self, scope: &Scope) -> Result<Expr, Error> {
        ast::FnCall {
            name: "or".into(),
            args: eval_exprs(scope, &self.0)?,
        }
        .eval(scope)
    }
}

impl Evaluate for ast::And {
    fn eval(&self, scope: &Scope) -> Result<Expr, Error> {
        ast::FnCall {
            name: "and".into(),
            args: eval_exprs(scope, &self.0)?,
        }
        .eval(scope)
    }
}

impl Evaluate for ast::Value {
    fn eval(&self, scope: &Scope) -> Result<Expr, Error> {
        match scope.get(&self.0) {
            Some(binding) => binding.eval(scope),
            None => Ok(self.clone().into()),
            // TODO error if a $ binding is passed through
        }
    }
}

impl Evaluate for ast::Block {
    fn eval(&self, scope: &Scope) -> Result<Expr, Error> {
        let mut scope = Scope::derive(scope);
        for stmt in &self.stmts {
            stmt.run(&mut scope)?;
        }
        self.return_value.eval(&scope)
    }
}

impl ast::FnDef {
    fn call(&self, args: Vec<Expr>, scope: &Scope) -> Result<Expr, Error> {
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
    fn eval(&self, scope: &Scope) -> Result<Expr, Error> {
        match self {
            Expr::FnCall(x) => x.eval(scope),
            //Expr::FnDef(x) => x.eval(scope),
            Expr::Or(x) => x.eval(scope),
            Expr::And(x) => x.eval(scope),
            //Expr::Block(x) => x.eval(scope),
            Expr::Value(x) => x.eval(scope),
            _ => unimplemented!(),
        }
    }
}

impl Transpile for ast::FnCall {
    fn transpile(&self) -> Policy {
        let args = transpile_exprs(&self.args);
        Policy::FnCall(self.name.clone(), args)
    }
}

impl Transpile for ast::Value {
    fn transpile(&self) -> Policy {
        Policy::Value(self.0.clone())
    }
}

impl Transpile for Expr {
    fn transpile(&self) -> Policy {
        match self {
            Expr::FnCall(x) => x.transpile(),
            Expr::Value(x) => x.transpile(),
            _ => unreachable!(),
        }
    }
}

fn eval_exprs(scope: &Scope, list: &Vec<Expr>) -> Result<Vec<Expr>, Error> {
    list.iter().map(|arg| arg.eval(scope)).collect()
}

fn transpile_exprs(list: &Vec<Expr>) -> Vec<Policy> {
    list.iter().map(Transpile::transpile).collect()
}
