use std::collections::HashMap;
use std::rc::Rc;

use crate::ast::{Expr, Ident};
use crate::Error;

#[derive(Default, Debug)]
pub struct Scope {
    parent: Option<Rc<Scope>>,
    local: HashMap<Ident, Expr>,
}

impl Scope {
    pub fn new() -> Rc<Self> {
        Self::default().into()
    }

    pub fn derive(parent: Rc<Scope>) -> Rc<Self> {
        Scope {
            parent: Some(parent),
            local: HashMap::new(),
        }
        .into()
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
}
