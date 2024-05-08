use std::convert::{TryFrom, TryInto};
use std::{fmt, iter, mem, ops, vec};

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

    pub fn into_iter(self) -> vec::IntoIter<Value> {
        self.0.into_iter()
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

/// Iterator method to get the next Value converted into any FromValue type. The type can be an
/// Option to get back a None when iteration is finished, or a non-Option to back an an Error.
pub trait IterValueInto: Iterator<Item = Value> + Sized {
    fn next_into<T: FromValue>(&mut self) -> Result<T> {
        T::from_opt_value(self.next())
    }

    /// Wraps errors with Error::NthContext to tell which argument/element index they originated from.
    /// Note this always returns the next value like next_into(), `index` is purely for error display.
    fn nth_into<T: FromValue>(&mut self, index: usize) -> Result<T> {
        self.next_into()
            .map_err(|e| Error::NthContext(index, e.into()))
    }
}
impl<I: Iterator<Item = Value>> IterValueInto for I {}

// Allows collect()ing an Iterator over Values into a Vec of any FromValue type
impl<T: FromValue> iter::FromIterator<Value> for Result<Vec<T>> {
    fn from_iter<I: iter::IntoIterator<Item = Value>>(iter: I) -> Self {
        iter.into_iter()
            .enumerate()
            .map(|(i, val)| T::from_value(val).map_err(|e| Error::NthContext(i, e.into())))
            .collect()
        //iter.into_iter().map(T::from_value).collect()
    }
}

// Generic conversion from Array into a Vec of any convertible type
impl<T: FromValue> TryFrom<Array> for Vec<T> {
    type Error = Error;
    fn try_from(arr: Array) -> Result<Vec<T>> {
        // handled by the FromIterator<Value> implementation above
        arr.into_iter().collect()
    }
}

// Generic conversion from Array into tuples of any convertible type
// Currently supports 1-tuples, 2-tuples and 3-tuples
impl<A: FromValue> TryFrom<Array> for (A,) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A,)> {
        let min_len = A::is_required() as usize;
        let mut iter = arr.check_varlen(min_len, 1)?.into_iter();

        Ok((iter.nth_into(0)?,))
    }
}
impl<A: FromValue, B: FromValue> TryFrom<Array> for (A, B) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B)> {
        let min_len = A::is_required() as usize + B::is_required() as usize;
        let mut iter = arr.check_varlen(min_len, 2)?.into_iter();

        Ok((iter.nth_into(0)?, iter.nth_into(1)?))
    }
}
impl<A: FromValue, B: FromValue, C: FromValue> TryFrom<Array> for (A, B, C) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B, C)> {
        let min_len =
            A::is_required() as usize + B::is_required() as usize + C::is_required() as usize;
        let mut iter = arr.check_varlen(min_len, 3)?.into_iter();

        Ok((iter.nth_into(0)?, iter.nth_into(1)?, iter.nth_into(2)?))
    }
}

// Standard Display, with no newlines or indentation
impl fmt::Display for Array {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if should_use_colon_syntax(&self.0) {
            // Display 2-tuples using the A:B colon construction syntax
            write!(f, "{}{}{}", self.0[0], colon_separator(&self.0), self.0[1])
        } else {
            fmt_list(f, self.0.iter(), true, |f, el| write!(f, "{}", el))
        }
    }
}

// Multi-line display with indentation
impl PrettyDisplay for Array {
    fn multiline_fmt<W: fmt::Write>(&self, f: &mut W, indent: usize) -> fmt::Result {
        if should_use_colon_syntax(&self.0) {
            let separator = colon_separator(&self.0);
            write!(f, "{}{}{}", self.0[0], separator, self.0[1].pretty(indent))
        } else {
            write!(f, "[\n")?;
            for (i, e) in self.0.iter().enumerate() {
                if i > 0 {
                    write!(f, ",\n")?;
                }
                write!(f, "{:i$}{}", "", e.pretty(indent + 1), i = (indent + 1) * 2)?;
            }
            write!(f, "\n{:i$}]", "", i = indent * 2)
        }
    }
}

// Heuristic to decide whether to format 2-tuple arrays using the : colon syntax
fn should_use_colon_syntax(elements: &Vec<Value>) -> bool {
    use Value::*;
    if elements.len() == 2 {
        match (&elements[0], &elements[1]) {
            // Never if the LHS is one of these (not typically used with colon tuple construction syntax)
            (Bool(_) | Number(_) | Array(_) | Function(_) | Transaction(_), _) => false,

            // Always if the LHS is String or Script (used as tagged list keys and predicates)
            (String(_) | Script(_), _) => true,

            // Otherwise, only if the LHS and RHS are of different types
            (
                lhs @ (Bytes(_) | Address(_) | PubKey(_) | Policy(_) | Descriptor(_) | TapInfo(_)
                | WithProb(..) | Network(_) | Symbol(_)),
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
        (String(_) | PubKey(_) | Policy(_) | Script(_) | Descriptor(_) | TapInfo(_), _) => ": ",
        (_, Array(_)) => ": ",
        _ => ":",
    }
}
