//! Tagged Lists utilities
//!
//! Utilities for parsing the tagged list array structure, where each tagged element identified as a [name, value] tuple
//!
//! For example, a tagged transaction can look like:
//!
//!    [
//!      [ "version", 2 ],
//!      [ "locktime", 0 ],
//!      [ "inputs", [
//!        [ [ "txid", ... ], [ "vout", ... ] ],
//!        ...
//!      ] ]
//!    ]
//!
//! Or alternatively using the colon tuple syntax (equivalent to the above):
//!
//!    [
//!      "version": 2,
//!      "locktime": 0,
//!      "inputs": [
//!        [ "txid": ..., "vout": ... ],
//!        ...
//!      ]
//!    ]

use std::collections::HashSet;
use std::convert::TryInto;

use crate::runtime::{Array, Error, FromValue, Result, Value};

impl Array {
    /// Transform a tagged Value::Array into a Vec of tag names and their values
    pub fn into_tags(self) -> Result<Vec<(String, Value)>> {
        self.try_into()
            .map_err(|e| Error::InvalidTaggedList(Box::new(e)))
    }

    /// Run a closure over each tag, with automatic TagError wrapping
    pub fn for_each_tag<F>(self, mut f: F) -> Result<()>
    where
        F: FnMut(&str, Value) -> Result<()>,
    {
        for (tag, val) in self.into_tags()? {
            f(&tag, val).map_err(|e| Error::TagError(tag, e.into()))?;
        }
        Ok(())
    }

    /// Run a closure over each unique tag, erroring if there are any duplicates
    pub fn for_each_unique_tag<F>(self, mut f: F) -> Result<()>
    where
        F: FnMut(&str, Value) -> Result<()>,
    {
        let mut seen_tags = HashSet::new();
        self.for_each_tag(|tag, val| {
            if seen_tags.insert(tag.to_string()) {
                f(tag, val)
            } else {
                Err(Error::TagDuplicated)
            }
        })
    }

    /// Considered to be a tagged list if self is an array, self.0 is a 2-tuple array, and self.0.0 is a string.
    /// This could have false positives depending on the alternative non-tagged structure in use.
    pub fn is_tagged_array(&self) -> bool {
        if let Some(Value::Array(inner_array)) = self.first() {
            if inner_array.len() == 2 {
                if let Some(Value::String(_tag)) = inner_array.first() {
                    return true;
                }
            }
        }
        false
    }

    pub fn is_tagged_or_empty(&self) -> bool {
        self.is_empty() || self.is_tagged_array()
    }
}

impl Value {
    /// Parse values that can be either a tuple of (A,B) or a tagged list with `a_tag` and `b_tag`
    /// For example, tuple_or_tags::<Txid,u32>("txid", "vout") to accept either [$txid,$vout] tuples or tagged ["txid":$txid,"vout":$vout]
    pub fn tagged_or_tuple<A: FromValue, B: FromValue>(
        self,
        a_tag: &str,
        b_tag: &str,
    ) -> Result<(A, B)> {
        if self.is_tagged_or_empty() {
            // the empty case is handled here too get pretty error messages with the missing tag name
            Ok(self.tagged_into2_req(a_tag, b_tag)?)
        } else {
            self.into_tuple()
        }
    }

    pub fn is_tagged_array(&self) -> bool {
        match self {
            Value::Array(array) => array.is_tagged_array(),
            _ => false,
        }
    }

    pub fn is_tagged_or_empty(&self) -> bool {
        match self {
            Value::Array(array) => array.is_tagged_or_empty(),
            _ => false,
        }
    }

    pub fn into_tags(self) -> Result<Vec<(String, Value)>> {
        self.into_array()?.into_tags()
    }

    pub fn for_each_tag<F>(self, f: F) -> Result<()>
    where
        F: FnMut(&str, Value) -> Result<()>,
    {
        self.into_array()?.for_each_tag(f)
    }

    pub fn for_each_unique_tag<F>(self, f: F) -> Result<()>
    where
        F: FnMut(&str, Value) -> Result<()>,
    {
        self.into_array()?.for_each_unique_tag(f)
    }
}

/// Defines tagged_intoN(), tagged_intoN_optional(), tagged_intoN_required() and tagged_intoN_default() functions
/// to extract tagged values identified by their tag name (e.g. [ "txid": $txid, "vout": 0 ]) and automatically
/// convert them into any type that implements TryFrom<Value>.
macro_rules! impl_tagged_into {
    ($fn_name:ident, $opt_fn_name:ident, $req_fn_name:ident, $default_fn_name:ident, $($t:ident, $tag:ident, $idx:tt),+) => {

        // Implement tagged_intoN(), supporting both required and optional fields
        // For example: value.tagged_into2::<Txid, Option<u32>>("txid", "vout") to get back (Txid, Option<u32>)
        pub fn $fn_name<$($t: FromValue),+>(self, $($tag: &str),+)
            -> Result<($($t),+)>
        {
            // Use tagged_intoN_opt() to get the found fields as `Value`s, without converting them (yet)
            let res = self.$opt_fn_name($($tag),+)?; // (Option<Value>, Option<Value>, ..)

            // Convert the Option<Value>s into the requested type using the FromValue trait.
            // This will error if the field is not present and the requested type was not specified as an Option.
            Ok(($( $t::from_opt_value(res.$idx)
                .map_err(|e| Error::TagError($tag.to_string(), e.into()))? ),+))
        }

        // Implement tagged_intoN_optional(), where all fields are optional and returned as an Option
        // For example: valued.tagged_into2_optional::<Txid, u32>("txid", "vout") to get back (Option<Txid>, Option<u32>)
        pub fn $opt_fn_name<$($t: FromValue),+>(self, $($tag: &str),+)
            -> Result<($(Option<$t>),+)>
        {
            let mut res = ($(None::<$t>),+);

            self.for_each_tag(|tag, val| {
               $(if tag == $tag {
                    ensure!(res.$idx.is_none(), Error::TagDuplicated); // could use for_each_unique_tag(), but here we already have `res` so we can avoid allocating the `HashSet<String>` for seen tags
                    res.$idx = Some($t::from_value(val)?);
                    Ok(())
                } else)+ {
                    Err(Error::TagUnknown)
                }
            })?;

            Ok(res)
        }

        // Implement tagged_intoN_required(), requiring all tags to be present
        // For example: valued.tagged_into2_required::<Txid, u32>("txid", "vout") to get back (Txid, u32)
        pub fn $req_fn_name<$($t: FromValue),+>(self, $($tag: &str),+)
        -> Result<($($t),+)>
        {
            match self.$opt_fn_name($($tag),+)? {
                // match the case where all tags are available, extract their values out of the Option and return them
                #[allow(non_snake_case)] // type name aliases reused as variable names (e.g. A)
                ($(Some($t)),+) => Ok(($($t),+)),

                // otherwise, report which tag is missing
                $(res if res.$idx.is_none() => Err(Error::TagError($tag.to_string(), Error::MissingValue.into())),)+
                _ => unreachable!(),
            }
        }

        // Implement tagged_intoN_default(), using the Default value for missing tags
        pub fn $default_fn_name<$($t: FromValue + Default),+>(self, $($tag: &str),+)
        -> Result<($($t),+)>
        {
            if self.is_empty_array() {
                // Optimize the case of an empty tagged list. Would've worked through the else branch too.
                Ok(Default::default())
            } else {
                let res = self.$opt_fn_name($($tag),+)?;
                Ok(($( res.$idx.unwrap_or_default() ),+))
            }
        }
    };
}

#[rustfmt::skip]
impl Value {
    impl_tagged_into!(tagged_into2, tagged_into2_opt, tagged_into2_req, tagged_into2_default, A, a_tag, 0, B, b_tag, 1);
    impl_tagged_into!(tagged_into3, tagged_into3_opt, tagged_into3_req, tagged_into3_default, A, a_tag, 0, B, b_tag, 1, C, c_tag, 2);
    impl_tagged_into!(tagged_into4, tagged_into4_opt, tagged_into4_req, tagged_into4_default, A, a_tag, 0, B, b_tag, 1, C, c_tag, 2, D, d_tag, 3);
}
