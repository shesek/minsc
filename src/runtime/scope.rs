use std::collections::{HashMap, HashSet};

use crate::runtime::function::{NativeFunction, NativeFunctionPt};
use crate::runtime::{Error, Result, Value};
use crate::{stdlib, Ident};

#[derive(Default, Debug, Clone)]
pub struct Scope<'a> {
    parent: Option<&'a Scope<'a>>,
    local: HashMap<Ident, Value>,
}

lazy_static! {
    static ref ROOT: Scope<'static> = {
        let mut scope = Scope::default();
        stdlib::attach_stdlib(&mut scope);
        scope
    };
}

impl<'a> Scope<'a> {
    /// Get a real-only reference to the cached global root scope
    pub fn root() -> &'static Self {
        &ROOT
    }

    /// Create a new writable child scope under the global root scope
    /// To create a blank root scope with no stdlib, use Scope::default()
    /// To get an owned root scope with stdlib, use Scope::root().clone()
    pub fn new() -> Scope<'a> {
        Scope::root().child()
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
    pub fn set_fn<K: Into<Ident>>(&mut self, key: K, pt: NativeFunctionPt) -> Result<()> {
        let key = key.into();
        let func = NativeFunction::new(pt, Some(key.clone()));
        self.set(key, func)
    }

    /// Get a builtin variable, which must be available in scope
    pub fn builtin(&self, key: &str) -> &Value {
        self.get(&key.into()).expect("built-in must exists")
    }

    /// Create a child scope of this scope
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
