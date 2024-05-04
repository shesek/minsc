use std::convert::{TryFrom, TryInto};
use std::{fmt, ops, vec};

use crate::runtime::{Error, Result, Value};

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
impl<T: TryFrom<Value>> TryFrom<Array> for Vec<T>
where
    Error: From<T::Error>,
{
    type Error = Error;
    fn try_from(arr: Array) -> Result<Vec<T>> {
        arr.0
            .into_iter()
            .map(|a| a.try_into().map_err(Error::from))
            .collect()
    }
}

// Generic conversion from Array into tuples of any convertible type
// Currently supports 1-tuples, 2-tuples and 3-tuples
impl<A: TryFrom<Value>> TryFrom<Array> for (A,)
where
    Error: From<A::Error>,
{
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A,)> {
        let a = arr.check_len(1)?.remove(0);
        Ok((a.try_into()?,))
    }
}
impl<A: TryFrom<Value>, B: TryFrom<Value>> TryFrom<Array> for (A, B)
where
    Error: From<A::Error>,
    Error: From<B::Error>,
{
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B)> {
        let mut iter = arr.check_len(2)?.into_iter();
        let a = iter.next().unwrap().try_into()?;
        let b = iter.next().unwrap().try_into()?;
        Ok((a, b))
    }
}
impl<A: TryFrom<Value>, B: TryFrom<Value>, C: TryFrom<Value>> TryFrom<Array> for (A, B, C)
where
    Error: From<A::Error>,
    Error: From<B::Error>,
    Error: From<C::Error>,
{
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B, C)> {
        let mut iter = arr.check_len(3)?.into_iter();
        let a = iter.next().unwrap().try_into()?;
        let b = iter.next().unwrap().try_into()?;
        let c = iter.next().unwrap().try_into()?;
        Ok((a, b, c))
    }
}

/*
impl<A: FromOptValue<A>, B: FromOptValue<B>> TryFrom<Array> for (A, B) {
    type Error = Error;
    fn try_from(arr: Array) -> Result<(A, B)> {
        ensure!(arr.len() <= 2, Error::InvalidArguments);
        let mut iter = arr.into_iter();
        Ok((A::from_opt_val(iter.next())?, B::from_opt_val(iter.next())?))
    }
}
*/

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
