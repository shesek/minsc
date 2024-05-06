use std::convert::{TryFrom, TryInto};
use std::{fmt, iter, mem, ops, vec};

use crate::runtime::{Error, FromValue, Result, Value};

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
    /// wrapper error type to indicate the error was related to argument parsing.
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
}
impl<I: Iterator<Item = Value>> IterValueInto for I {}

// Allows collect()ing an Iterator over Values into a Vec of any FromValue type
impl<T: FromValue> iter::FromIterator<Value> for Result<Vec<T>> {
    fn from_iter<I: iter::IntoIterator<Item = Value>>(iter: I) -> Self {
        iter.into_iter().map(T::from_value).collect()
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

        Ok((iter.next_into()?,))
    }
}
impl<A: FromValue, B: FromValue> TryFrom<Array> for (A, B) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B)> {
        let min_len = A::is_required() as usize + B::is_required() as usize;
        let mut iter = arr.check_varlen(min_len, 2)?.into_iter();

        Ok((iter.next_into()?, iter.next_into()?))
    }
}
impl<A: FromValue, B: FromValue, C: FromValue> TryFrom<Array> for (A, B, C) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B, C)> {
        let min_len =
            A::is_required() as usize + B::is_required() as usize + C::is_required() as usize;
        let mut iter = arr.check_varlen(min_len, 3)?.into_iter();

        Ok((iter.next_into()?, iter.next_into()?, iter.next_into()?))
    }
}

impl fmt::Display for Array {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Called with is_root_array=true to avoid the colon syntax for top-level arrays,
        // then recurses internally without it.
        fmt_array(f, self, true)
    }
}

fn fmt_array(f: &mut fmt::Formatter, arr: &Array, is_root_array: bool) -> fmt::Result {
    if should_use_colon_syntax(is_root_array, &arr.0) {
        // Display 2-tuples using the A:B colon construction syntax
        let space = iif!(arr.0[0].is_string(), " ", "");
        write!(f, "{}:{}{}", arr.0[0], space, arr.0[1])
    } else {
        write!(f, "[ ")?;
        for (i, element) in arr.0.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            match element {
                Value::Array(arr) => fmt_array(f, arr, false)?,
                other => write!(f, "{}", other)?,
            }
        }
        write!(f, " ]")
    }
}

fn should_use_colon_syntax(is_root_array:bool, elements: &Vec<Value>) -> bool {
    use Value::*;
    if !is_root_array && elements.len() == 2 {
        match (&elements[0], &elements[1]) {
            // Never if the LHS is one of these (not typically used with colon tuple construction syntax)
            (Bool(_) | Number(_) | Array(_) | Function(_) | Transaction(_) | Network(_), _) => {
                false
            }

            // Always if the LHS is a string (typically used as a key name for tagged lists)
            (String(_), _) => true,

            // Otherwise, only if the LHS and RHS are of different types
            (
                lhs @ (Bytes(_) | Script(_) | Address(_) | PubKey(_) | Policy(_) | Descriptor(_)
                | TapInfo(_) | WithProb(..)),
                rhs,
            ) => mem::discriminant(lhs) != mem::discriminant(rhs),
        }
    } else {
        false
    }
}
