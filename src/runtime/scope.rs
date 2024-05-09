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

    /// Search the local and parent scope recursively for `key`
    pub fn get(&self, key: &Ident) -> Option<&Value> {
        self.local
            .get(key)
            .or_else(|| self.parent.as_ref().and_then(|p| p.get(key)))
    }

    /// Set a local variable
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

    /// Get the entire env from the local and parent scopes
    ///
    /// max_depth can be set to limit the number of scopes included. It may be set to 0
    /// to return everything or to -1 to return everything but the top-level global scope.
    pub fn env(&self, max_depth: isize) -> Vec<(&Ident, &Value)> {
        // env returned as a Vec to retain order, with variables from inner scopes appearing first,
        // then sorted by key name to retain deterministic order
        let mut env = vec![];
        let mut depth = 0;
        let mut seen_keys = HashSet::new();
        let mut scope = self;
        loop {
            // Collect new vars from the current scope
            let locals = scope.local.iter();
            let mut new_vars: Vec<_> = locals.filter(|(key, _)| seen_keys.insert(*key)).collect();
            new_vars.sort_unstable_by_key(|&(key, _)| key);
            env.append(&mut new_vars);

            // Continue to the parent scope, unless the max_depth limit was reached
            depth += 1;
            scope = match scope.parent {
                None => break,
                Some(_) if depth == max_depth => break,
                // skip the top-level root scope when max_depth==-1
                Some(scope) if max_depth == -1 && scope.parent.is_none() => break,
                Some(scope) => scope,
            };
        }
        env
    }
}
