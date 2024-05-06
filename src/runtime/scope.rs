use std::collections::{HashMap, HashSet};

use crate::parser::Ident;
use crate::runtime::{function::NativeFunctionPt, Error, Result, Value};
use crate::stdlib::attach_stdlib;

#[derive(Default, Debug)]
pub struct Scope<'a> {
    parent: Option<&'a Scope<'a>>,
    local: HashMap<Ident, Value>,
}

impl<'a> Scope<'a> {
    pub fn root() -> Self {
        // TODO cache
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

    /// Get a builtin variable, which must be available in scope
    pub fn builtin(&self, key: &str) -> &Value {
        self.get(&key.into()).expect("built-in must exists")
    }

    pub fn child(&'a self) -> Self {
        Scope {
            parent: Some(&self),
            local: HashMap::new(),
        }
    }

    /// Get variables from the local scope
    pub fn locals(&self) -> &HashMap<Ident, Value> {
        &self.local
    }

    /// Get the entire env from the local and parent scopes
    pub fn env(&self, include_root: bool) -> Vec<(&Ident, &Value)> {
        // env returned as a Vec to retain order, with variables from inner scopes appearing first
        let mut env = vec![];
        let mut seen_keys = HashSet::new();
        let mut scope = self;
        loop {
            env.extend(scope.local.iter().filter(|(i, _)| seen_keys.insert(*i)));

            scope = match scope.parent {
                None => break,
                Some(scope) if !include_root && scope.parent.is_none() => break,
                Some(scope) => scope,
            };
        }
        env
    }
}
