use std::collections::HashMap;

use crate::ast::Ident;
use crate::error::{Error, Result};
use crate::function::NativeFunctionPt;
use crate::runtime::Value;
use crate::stdlib::attach_stdlib;

#[derive(Default, Debug)]
pub struct Scope<'a> {
    parent: Option<&'a Scope<'a>>,
    local: HashMap<Ident, Value>,
}

impl<'a> Scope<'a> {
    pub fn root() -> Self {
        let mut scope = Self::default();
        attach_stdlib(&mut scope);
        scope
    }

    pub fn get(&self, key: &Ident) -> Option<&Value> {
        self.local
            .get(key)
            .or_else(|| self.parent.as_ref().and_then(|p| p.get(key)))
    }

    pub fn set<K: Into<Ident>, V: Into<Value>>(&mut self, key: K, value: V) -> Result<()> {
        let key = key.into();

        #[allow(clippy::map_entry)]
        if self.local.contains_key(&key) {
            // cannot be set if already exists in this scope, but could shadow over a definition from a parent scope
            Err(Error::AssignedVariableExists(key))
        } else {
            self.local.insert(key, value.into());
            Ok(())
        }
    }

    // NativeFunctionPt should work directly with set() as it implements Into<Value>,
    // but for some reason it fails with due to mismatched lifetimes
    pub fn set_fn<K: Into<Ident>>(&mut self, key: K, f: NativeFunctionPt) -> Result<()> {
        self.set(key, f)
    }

    pub fn child(&'a self) -> Self {
        Scope {
            parent: Some(&self),
            local: HashMap::new(),
        }
    }
}
