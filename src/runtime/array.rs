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
        ensure!(
            self.len() >= min_len && self.len() <= max_len,
            Error::InvalidVarLength(self.len(), min_len, max_len)
        );
        Ok(self)
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
        let a = arr.check_len(1)?.remove(0);
        Ok((A::from_value(a)?,))
    }
}
impl<A: FromValue, B: FromValue> TryFrom<Array> for (A, B) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B)> {
        let mut iter = arr.check_len(2)?.into_iter();
        let a = A::from_value(iter.next().unwrap())?;
        let b = B::from_value(iter.next().unwrap())?;
        Ok((a, b))
    }
}
impl<A: FromValue, B: FromValue, C: FromValue> TryFrom<Array> for (A, B, C) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B, C)> {
        let mut iter = arr.check_len(3)?.into_iter();
        let a = A::from_value(iter.next().unwrap())?;
        let b = B::from_value(iter.next().unwrap())?;
        let c = C::from_value(iter.next().unwrap())?;
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
