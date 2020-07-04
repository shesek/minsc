use std::collections::HashMap;

use crate::ast::Ident;
use crate::error::{Error, Result};
use crate::miniscript::BUILTINS;
use crate::runtime::Value;

#[derive(Default, Debug)]
pub struct Scope<'a> {
    parent: Option<&'a Scope<'a>>,
    local: HashMap<Ident, Value>,
}

impl<'a> Scope<'a> {
    pub fn root() -> Self {
        let mut scope = Self::default();
        attach_builtins(&mut scope);
        scope
    }

    pub fn derive(parent: &'a Scope) -> Self {
        Scope {
            parent: Some(parent),
            local: HashMap::new(),
        }
    }

    pub fn get(&self, key: &Ident) -> Option<&Value> {
        self.local
            .get(key)
            .or_else(|| self.parent.as_ref().and_then(|p| p.get(key)))
    }

    pub fn set(&mut self, key: Ident, value: Value) -> Result<()> {
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

fn attach_builtins(scope: &mut Scope) {
    for name in BUILTINS {
        let name = *name;
        scope
            .set(name.into(), Value::FnNative(name.into()))
            .unwrap();
    }
}
