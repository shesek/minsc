use std::convert::{TryFrom, TryInto};
use std::{fmt, iter, ops, vec};

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
        write!(f, "[ ")?;
        for (i, element) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", element)?;
        }
        write!(f, " ]")
    }
}
