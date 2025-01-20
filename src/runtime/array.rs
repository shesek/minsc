use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::iter::FromIterator;
use std::{fmt, mem, ops, vec};

use crate::display::{fmt_list, PrettyDisplay};
use crate::runtime::{Error, FieldAccess, FromValue, Result, Symbol, Value};

#[derive(Clone, PartialEq, Debug)]
pub struct Array(pub Vec<Value>);

impl ops::Deref for Array {
    type Target = Vec<Value>;
    fn deref(&self) -> &Vec<Value> {
        &self.0
    }
}

impl ops::DerefMut for Array {
    fn deref_mut(&mut self) -> &mut Vec<Value> {
        &mut self.0
    }
}

impl Array {
    pub fn into_inner(self) -> Vec<Value> {
        self.0
    }

    pub fn into_iter_of<T: FromValue>(self) -> impl Iterator<Item = Result<T>> {
        self.into_iter().map(T::from_value)
    }

    pub fn check_len(self, expected_len: usize) -> Result<Self> {
        ensure!(
            self.len() == expected_len,
            Error::InvalidLength(self.0.len(), expected_len)
        );
        // self is gone if the length check failed, so it isn't used by accident.
        Ok(self)
    }
    pub fn check_varlen(self, min_len: usize, max_len: usize) -> Result<Self> {
        if min_len == max_len {
            self.check_len(min_len)
        } else {
            ensure!(
                self.len() >= min_len && self.len() <= max_len,
                Error::InvalidVarLength(self.len(), min_len, max_len)
            );
            Ok(self)
        }
    }
    // Parse an Array that either contains a list of index:value tuples mapping from
    // element indexes to values, or a full list of all element values with no indexes.
    // Returned as a list of index:value tuples in both cases.
    pub fn mapped_or_all<T: FromValue>(
        self,
        expected_all_length: usize,
    ) -> Result<Vec<(usize, T)>> {
        if let Some(Value::Array(first_el)) = self.first() {
            if first_el.len() == 2 {
                // Differentiating the two cases assumes that the value type *is not a number*
                #[allow(clippy::get_first)]
                match (first_el.get(0), first_el.get(1)) {
                    (Some(Value::Number(_)), Some(Value::Number(_))) => (),
                    (Some(Value::Number(_)), Some(_non_number)) => {
                        // Provided as [ 0: $val0, 1: $val1, ... ]
                        return self.try_into();
                    }
                    _ => (),
                }
            }
        }
        // Provided as [ $val0, $val1, ... ]
        ensure!(
            self.len() == expected_all_length,
            Error::InvalidLength(self.len(), expected_all_length)
        );
        Ok(Vec::<T>::try_from(self)?.into_iter().enumerate().collect())
    }

    pub fn is_tagged_with(&self, tag: &str) -> bool {
        self.first().is_some_and(|el| match el {
            Value::String(el_s) => el_s == tag,
            _ => false,
        })
    }

    /// Unpack function arguments into a tuple or vec. Like try_into(), but with a
    /// wrapper error type to indicate the error was related to the arguments.
    /// Supports optional arguments by specifying an Option<T> as the return type.
    pub fn args_into<T: TryFrom<Array>>(self) -> Result<T>
    where
        Error: From<T::Error>,
    {
        self.try_into()
            .map_err(|e| Error::InvalidArgumentsError(Error::from(e).into()))
    }

    /// Get a single argument, ensuring there were no more
    pub fn arg_into<T: FromValue>(self) -> Result<T> {
        Ok(self.args_into::<(T,)>()?.0)
    }

    pub fn no_args(self) -> Result<()> {
        self.check_len(0)
            .map_err(|e| Error::InvalidArgumentsError(e.into()))
            .map(|_| ())
    }
}

lazy_static! {
    pub static ref SYM_MULTIVAL: Symbol = Symbol::new(Some("ARRAY_MULTIVAL_FIELD".into()));
}

// Tagged array field access
impl FieldAccess for Array {
    fn get_field(self, field: &Value) -> Option<Value> {
        let mut field_value = None;
        for el in self.into_inner() {
            if let Value::Array(mut el_arr) = el {
                if el_arr.len() == 2 && el_arr[0] == *field {
                    if !field_value.is_none() {
                        // Return the sentinel ARRAY_MULTIVAL symbol to indicate there are multiple matching fields.
                        // The values may be extracted with t::multi($arr, $key) instead.
                        return Some(SYM_MULTIVAL.clone().into());
                    }
                    field_value = Some(el_arr.remove(1));
                }
            }
        }
        field_value
    }
}

/// An Iterator over `Value`s, with conversion into FromValue types and improved error reporting
pub struct ValueItertor<I: Iterator<Item = Value>> {
    inner: I,
    count: usize,
}
impl<I: Iterator<Item = Value>> ValueItertor<I> {
    /// Convert the next Value into any FromValue type
    /// If the type is not an Option and there are no more items, an error will be raised.
    pub fn next_into<T: FromValue>(&mut self) -> Result<T> {
        // Wrap errors with Error::NthContext to tell which argument/element index they originated from
        // The counter is displayed as 1-indexed.
        let this_index = self.count + 1; // use the next index even when next() returns None (1-indexed)
        T::from_opt_value(self.next()).map_err(|e| Error::NthContext(this_index, e.into()))
    }

    /// Collect all Values into a Vec of any FromValue type
    pub fn collect_into<T: FromValue>(self) -> Result<Vec<T>> {
        let initial_count = self.count + 1;
        self.enumerate()
            .map(|(i, val)| {
                T::from_value(val).map_err(|e| Error::NthContext(initial_count + i, e.into()))
            })
            .collect()
    }
}
impl<I: Iterator<Item = Value>> Iterator for ValueItertor<I> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next()?;
        self.count += 1; // for Error::NthContext
        Some(item)
    }
}

impl IntoIterator for Array {
    type Item = Value;
    type IntoIter = ValueItertor<vec::IntoIter<Value>>;
    fn into_iter(self) -> Self::IntoIter {
        ValueItertor {
            inner: self.0.into_iter(),
            count: 0,
        }
    }
}

// Generic conversion from an iterator of any convertible type into an Array
impl<V: Into<Value>> FromIterator<V> for Array {
    fn from_iter<T: IntoIterator<Item = V>>(iter: T) -> Self {
        Self(iter.into_iter().map(Into::into).collect())
    }
}

// Generic conversion from 1/2/3/4-tuples of any convertible type into an Array
impl<A: Into<Value>> From<(A,)> for Array {
    fn from((a,): (A,)) -> Self {
        Array(vec![a.into()])
    }
}
impl<A: Into<Value>, B: Into<Value>> From<(A, B)> for Array {
    fn from((a, b): (A, B)) -> Self {
        Array(vec![a.into(), b.into()])
    }
}
impl<A: Into<Value>, B: Into<Value>, C: Into<Value>> From<(A, B, C)> for Array {
    fn from((a, b, c): (A, B, C)) -> Self {
        Array(vec![a.into(), b.into(), c.into()])
    }
}
impl<A: Into<Value>, B: Into<Value>, C: Into<Value>, D: Into<Value>> From<(A, B, C, D)> for Array {
    fn from((a, b, c, d): (A, B, C, D)) -> Self {
        Array(vec![a.into(), b.into(), c.into(), d.into()])
    }
}

// Generic conversion from native set types into Array
impl<T: Into<Value>> From<Vec<T>> for Array {
    fn from(vec: Vec<T>) -> Self {
        Array::from_iter(vec)
    }
}
impl<K: Into<Value>, V: Into<Value>> From<BTreeMap<K, V>> for Array {
    fn from(map: BTreeMap<K, V>) -> Self {
        Array::from_iter(map)
    }
}

// Generic conversion from Array into a Vec of any convertible type
impl<T: FromValue> TryFrom<Array> for Vec<T> {
    type Error = Error;
    fn try_from(arr: Array) -> Result<Vec<T>> {
        arr.into_iter().collect_into()
    }
}

// Generic conversion from Array into a HashSet of any convertible type
impl<T: FromValue + std::hash::Hash + Eq> TryFrom<Array> for HashSet<T> {
    type Error = Error;
    fn try_from(arr: Array) -> Result<HashSet<T>> {
        arr.into_iter().map(T::from_value).collect()
    }
}
// Generic conversion from a tagged Array into a HashMap of any convertible key/val
impl<K: FromValue + std::hash::Hash + Eq, V: FromValue> TryFrom<Array> for HashMap<K, V> {
    type Error = Error;
    fn try_from(arr: Array) -> Result<HashMap<K, V>> {
        arr.into_iter().map(<(K, V)>::from_value).collect()
    }
}

// Generic conversion from Array into a BTreeSet of any convertible type
impl<T: FromValue + Eq + Ord> TryFrom<Array> for BTreeSet<T> {
    type Error = Error;
    fn try_from(arr: Array) -> Result<BTreeSet<T>> {
        arr.into_iter().map(T::from_value).collect()
    }
}
// Generic conversion from a tagged Array into a BTreeMap of any convertible key/val
impl<K: FromValue + Ord, V: FromValue> TryFrom<Array> for BTreeMap<K, V> {
    type Error = Error;
    fn try_from(arr: Array) -> Result<BTreeMap<K, V>> {
        arr.into_iter().map(<(K, V)>::from_value).collect()
    }
}

// Generic conversion from Array into tuples of any convertible type
// Currently supports 1-tuples, 2-tuples and 3-tuples
impl<A: FromValue> TryFrom<Array> for (A,) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A,)> {
        let min_len = A::IS_REQUIRED as usize;
        let mut iter = arr.check_varlen(min_len, 1)?.into_iter();
        Ok((iter.next_into()?,))
    }
}
impl<A: FromValue, B: FromValue> TryFrom<Array> for (A, B) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B)> {
        let min_len = A::IS_REQUIRED as usize + B::IS_REQUIRED as usize;
        let mut iter = arr.check_varlen(min_len, 2)?.into_iter();
        Ok((iter.next_into()?, iter.next_into()?))
    }
}
impl<A: FromValue, B: FromValue, C: FromValue> TryFrom<Array> for (A, B, C) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B, C)> {
        let min_len = A::IS_REQUIRED as usize + B::IS_REQUIRED as usize + C::IS_REQUIRED as usize;
        let mut iter = arr.check_varlen(min_len, 3)?.into_iter();
        Ok((iter.next_into()?, iter.next_into()?, iter.next_into()?))
    }
}

impl fmt::Display for Array {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.pretty(None))
    }
}

impl PrettyDisplay for Array {
    const AUTOFMT_ENABLED: bool = true;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        if should_use_colon_syntax(&self.0) {
            let separator = colon_separator(&self.0);
            write!(f, "{}{}{}", self.0[0], separator, self.0[1].pretty(indent))
        } else {
            fmt_list(f, self.0.iter(), indent, |f, el, inner_indent| {
                write!(f, "{}", el.pretty(inner_indent))
            })
        }
    }

    fn prefer_multiline_anyway(&self) -> bool {
        self.len() > 10
    }
}

// Heuristic to decide whether to format 2-tuple arrays using the : colon syntax
fn should_use_colon_syntax(elements: &[Value]) -> bool {
    use Value::*;
    if elements.len() == 2 {
        match (&elements[0], &elements[1]) {
            // Never if the LHS is one of these (not typically used with colon tuple construction syntax)
            (Array(_) | Function(_) | Transaction(_) | Psbt(_), _) => false,

            // If the LHS is a String or Script, only if they're short (used as tagged list keys and predicates)
            (String(lhs), _) => lhs.len() < 43,
            (Script(lhs), _) => lhs.len() < 40,

            // Otherwise, only if the LHS and RHS are of different types
            (
                lhs @ (Bool(_) | Number(_) | Bytes(_) | Address(_) | PubKey(_) | SecKey(_)
                | Policy(_) | Descriptor(_) | TapInfo(_) | WshScript(_) | WithProb(..)
                | Network(_) | Symbol(_)),
                rhs,
            ) => mem::discriminant(lhs) != mem::discriminant(rhs),
        }
    } else {
        false
    }
}
// Heuristic to pick whether space should be used for the colon separator
// (no space for tuple values like $txid:$vout, with it for key-value-like structures)
fn colon_separator(elements: &[Value]) -> &str {
    use Value::*;
    // Assumes `elements` was already checked to be a 2-tuple
    match (&elements[0], &elements[1]) {
        (
            String(_) | PubKey(_) | SecKey(_) | Policy(_) | Script(_) | Descriptor(_) | TapInfo(_)
            | WshScript(_) | Psbt(_),
            _,
        ) => ": ",
        (_, Array(_)) => ": ",
        _ => ":",
    }
}
