use std::convert::{TryFrom, TryInto};
use std::{fmt, mem, ops, vec};

use crate::runtime::{Error, FromValue, Result, Value};
use crate::util::{fmt_list, PrettyDisplay};

#[derive(Debug, Clone, PartialEq)]
pub struct Array(pub Vec<Value>);

impl From<Vec<Value>> for Array {
    fn from(vec: Vec<Value>) -> Array {
        Array(vec)
    }
}
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

// Generic conversion from Array into a Vec of any convertible type
impl<T: FromValue> TryFrom<Array> for Vec<T> {
    type Error = Error;
    fn try_from(arr: Array) -> Result<Vec<T>> {
        arr.into_iter().collect_into()
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
fn should_use_colon_syntax(elements: &Vec<Value>) -> bool {
    use Value::*;
    if elements.len() == 2 {
        match (&elements[0], &elements[1]) {
            // Never if the LHS is one of these (not typically used with colon tuple construction syntax)
            (Array(_) | Function(_) | Transaction(_), _) => false,

            // If the LHS is a String or Script, only if they're short (used as tagged list keys and predicates)
            (String(lhs), _) => lhs.len() < 43,
            (Script(lhs), _) => lhs.len() < 40,

            // Otherwise, only if the LHS and RHS are of different types
            (
                lhs @ (Bool(_) | Number(_) | Bytes(_) | Address(_) | PubKey(_) | SecKey(_)
                | Policy(_) | Descriptor(_) | TapInfo(_) | WithProb(..) | Network(_)
                | Symbol(_)),
                rhs,
            ) => mem::discriminant(lhs) != mem::discriminant(rhs),
        }
    } else {
        false
    }
}
// Heuristic to pick whether space should be used for the colon separator
// (no space for tuple values like $txid:$vout, with it for key-value-like structures)
fn colon_separator(elements: &Vec<Value>) -> &str {
    use Value::*;
    // Assumes `elements` was already checked to be a 2-tuple
    match (&elements[0], &elements[1]) {
        (
            String(_) | PubKey(_) | SecKey(_) | Policy(_) | Script(_) | Descriptor(_) | TapInfo(_),
            _,
        ) => ": ",
        (_, Array(_)) => ": ",
        _ => ":",
    }
}
