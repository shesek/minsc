use std::collections::HashMap;

use crate::ast::{self, Expr, Ident};
use crate::Error;

#[derive(Default, Debug)]
pub struct Scope<'a> {
    parent: Option<&'a Scope<'a>>,
    local: HashMap<Ident, Expr>,
}

impl<'a> Scope<'a> {
    pub fn root() -> Self {
        let mut scope = Self::default();
        scope
            .set("sha256".into(), ast::FnNative("sha256".into()).into())
            .unwrap();
        scope
    }

    pub fn derive(parent: &'a Scope) -> Self {
        Scope {
            parent: Some(parent),
            local: HashMap::new(),
        }
    }

    pub fn get(&self, key: &Ident) -> Option<&Expr> {
        self.local
            .get(key)
            .or_else(|| self.parent.as_ref().and_then(|p| p.get(key)))
    }

    pub fn set(&mut self, key: Ident, value: Expr) -> Result<(), Error> {
        if self.local.contains_key(&key) {
            // cannot be set if already exists in this scope, but could shadow over a definition from a parent scope
            Err(Error::AssignedVariableExists(key))
        } else {
            self.local.insert(key, value);
            Ok(())
        }
    }

    pub fn child(&'a self) -> Self {
        Scope {
            parent: Some(&self),
            local: HashMap::new(),
        }
    }
}
