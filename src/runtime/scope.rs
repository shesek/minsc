use std::cell::{Ref, RefCell, RefMut};
use std::collections::{HashMap, HashSet};
use std::{marker::PhantomData, rc::Rc};

use crate::runtime::function::{NativeFunction, NativeFunctionPt};
use crate::runtime::{Error, Result, Value};
use crate::{stdlib, Ident};

#[derive(Default, Debug, Clone)]
pub struct Scope {
    parent: Option<ScopeRef<ReadOnly>>,
    local: HashMap<Ident, Value>,

    // same keys as in `local`, in insertion order. used for env().
    ordered_keys: Vec<Ident>,
}

impl Scope {
    /// Search the local and parent scopes recursively for `key`, returning a copy of its value
    pub fn get(&self, key: &Ident) -> Option<Value> {
        self.local
            .get(key)
            .cloned()
            .or_else(|| self.parent.as_ref().and_then(|p| p.borrow().get(key)))
    }

    /// Set a local variable
    pub fn set<K: Into<Ident>, V: Into<Value>>(&mut self, key: K, value: V) -> Result<()> {
        let key = key.into();

        #[allow(clippy::map_entry)]
        if self.local.contains_key(&key) {
            // cannot be set if already exists in this scope, but could shadow over a definition from a parent scope
            Err(Error::AssignedVariableExists(key))
        } else {
            self.ordered_keys.push(key.clone());
            self.local.insert(key, value.into());
            Ok(())
        }
    }

    /// Add a native Rust function to the scope
    pub fn set_fn<K: Into<Ident>>(&mut self, key: K, pt: NativeFunctionPt) -> Result<()> {
        let key = key.into();
        let func = NativeFunction::new(pt, Some(key.clone()));
        self.set(key, func)
    }

    /// Get a builtin variable, which must be available in scope
    pub fn builtin(&self, key: &str) -> Value {
        self.get(&key.into()).expect("built-in must exists")
    }

    /// Get the entire env from the local and parent scopes
    ///
    /// max_depth can be set to the number of parent scopes to include, to 0 to include
    /// all scopes, or to -1 to includes everything below the default (typically root) scope.
    pub fn env(&self, max_depth: isize) -> Vec<(Ident, Value)> {
        let mut depth = 0;
        let mut seen_keys = HashSet::new();
        // env returned as a Vec to retain order, with variables from inner scopes appearing first,
        // then sorted by key name to retain deterministic order
        let mut env = self.local_env(&mut seen_keys);

        let mut next_parent = self.parent.as_ref().map(ScopeRef::make_ref);
        while let Some(parent) = next_parent {
            depth += 1;
            if max_depth > 0 && depth == max_depth {
                break;
            }
            let parent = parent.borrow();
            if max_depth == -1 && parent.is_default() {
                break; // skip the default scope when max_depth==-1
            }

            env.append(&mut parent.local_env(&mut seen_keys));
            next_parent = parent.parent.as_ref().map(ScopeRef::make_ref);
        }
        env
    }

    // The default scope is typically the top-most root scope. However in some environments (like the playground)
    // there can be a scope beneath root used as the default, that provides additional environment-specific
    // utilities. These are identified by the presence of a flag variable, to have them excluded from env().
    fn is_default(&self) -> bool {
        lazy_static! {
            static ref FLAG_VAR: Ident = "__DEFAULT_SCOPE__".into();
        };
        self.parent.is_none() || self.local.contains_key(&FLAG_VAR)
    }

    fn local_env(&self, seen_keys: &mut HashSet<Ident>) -> Vec<(Ident, Value)> {
        self.ordered_keys
            .iter()
            .filter(|key| !seen_keys.contains(key) && seen_keys.insert((*key).clone()))
            .map(|key| (key.clone(), self.local.get(key).unwrap().clone()))
            .collect()
    }
}

// The global root scope
thread_local! {
    static ROOT: ScopeRef<ReadOnly> = {
        let scope = ScopeRef::default();
        stdlib::attach_stdlib(&scope);
        scope.into_readonly()
    };
}

impl Scope {
    /// Get a real-only ScopeRef for the cached global root scope
    pub fn root() -> ScopeRef<ReadOnly> {
        ROOT.with(ScopeRef::make_ref)
    }

    /// Create a new owned child Scope under the global root scope
    /// To create an owned blank root scope with no stdlib, use Scope::default()
    pub fn new() -> Scope {
        Scope::root().child()
    }

    /// Convert owned Scope into a shared ScopeRef
    pub fn into_ref<A: ScopeAccess>(self) -> ScopeRef<A> {
        ScopeRef(Rc::new(RefCell::new(self)), PhantomData)
    }
}

/// A shared Scope reference with ReadOnly/Mutable markers, to have compile-time enforcement
/// for accessing the RefCell interior mutability.
#[derive(Debug)]
pub struct ScopeRef<A: ScopeAccess = ReadOnly>(Rc<RefCell<Scope>>, PhantomData<A>);

// Marker types
#[derive(Debug)]
pub enum ReadOnly {}

#[derive(Debug)]
pub enum Mutable {}

pub trait ScopeAccess {}
impl ScopeAccess for ReadOnly {}
impl ScopeAccess for Mutable {}

// Methods available on ReadOnly and Mutable scopes
impl<A: ScopeAccess> ScopeRef<A> {
    /// Borrow the inner Scope as read-only
    pub fn borrow(&self) -> Ref<Scope> {
        self.0.borrow()
    }

    /// Get a read-only ScopeRef pointing to the same inner Scope
    pub fn make_ref(&self) -> ScopeRef<ReadOnly> {
        ScopeRef(Rc::clone(&self.0), PhantomData)
    }

    /// Get a mutable ScopeRef with a copy of the inner Scope
    pub fn make_copy(&self) -> ScopeRef<Mutable> {
        let cloned = self.0.borrow().clone();
        ScopeRef(Rc::new(RefCell::new(cloned)), PhantomData)
    }

    /// Create a new owned Scope that is a child of this scope
    pub fn child(&self) -> Scope {
        Scope {
            parent: Some(self.make_ref()),
            ..Default::default()
        }
    }
}

// Methods available on Mutable scopes only
impl ScopeRef<Mutable> {
    pub fn borrow_mut(&self) -> RefMut<Scope> {
        self.0.borrow_mut()
    }
    pub fn into_readonly(self) -> ScopeRef<ReadOnly> {
        ScopeRef(self.0, PhantomData)
    }
    pub fn as_readonly(&self) -> ScopeRef<ReadOnly> {
        self.make_ref()
    }
}

impl Default for ScopeRef<Mutable> {
    fn default() -> Self {
        ScopeRef(Default::default(), PhantomData::<Mutable>)
    }
}
impl Clone for ScopeRef<ReadOnly> {
    fn clone(&self) -> Self {
        self.make_ref()
    }
}
impl Clone for ScopeRef<Mutable> {
    fn clone(&self) -> Self {
        self.make_copy()
    }
}

/*
impl<A: ScopeAccess> From<Scope> for ScopeRef<A> {
    fn from(scope: Scope) -> Self {
        scope.into_ref()
    }
}
impl From<ScopeRef<Mutable>> for ScopeRef<ReadOnly> {
    fn from(scope: ScopeRef<Mutable>) -> ScopeRef<ReadOnly> {
        self.into_readonly()
    }
}
*/
