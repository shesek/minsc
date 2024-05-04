use std::convert::TryFrom;
use std::{fmt, ops, vec};

use crate::runtime::{Error, FromValue, Result, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct Array(pub Vec<Value>);

impl Array {
    pub fn inner(self) -> Vec<Value> {
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
}

impl From<Vec<Value>> for Array {
    fn from(vec: Vec<Value>) -> Array {
        Array(vec)
    }
}
//impl From<Array> for Vec<Value> {
//    fn from(array: Array) -> Vec<Value> {
//        array.0
//    }
//}
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

// Generic conversion from Array into a Vec of any convertible type
impl<T: FromValue> TryFrom<Array> for Vec<T> {
    type Error = Error;
    fn try_from(arr: Array) -> Result<Vec<T>> {
        arr.0.into_iter().map(T::from_value).collect()
    }
}

// Generic conversion from Array into tuples of any convertible type
// Currently supports 1-tuples, 2-tuples and 3-tuples
impl<A: FromValue> TryFrom<Array> for (A,) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A,)> {
        let min_len = A::is_required() as usize;
        let mut arr = arr.check_varlen(min_len, 1)?;

        let a = A::from_opt_value(arr.pop())?;
        Ok((a,))
    }
}
impl<A: FromValue, B: FromValue> TryFrom<Array> for (A, B) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B)> {
        let min_len = A::is_required() as usize + B::is_required() as usize;
        let mut iter = arr.check_varlen(min_len, 2)?.into_iter();

        let a = A::from_opt_value(iter.next())?;
        let b = B::from_opt_value(iter.next())?;
        Ok((a, b))
    }
}
impl<A: FromValue, B: FromValue, C: FromValue> TryFrom<Array> for (A, B, C) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B, C)> {
        let min_len =
            A::is_required() as usize + B::is_required() as usize + C::is_required() as usize;
        let mut iter = arr.check_varlen(min_len, 3)?.into_iter();

        let a = A::from_opt_value(iter.next())?;
        let b = B::from_opt_value(iter.next())?;
        let c = C::from_opt_value(iter.next())?;
        Ok((a, b, c))
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
