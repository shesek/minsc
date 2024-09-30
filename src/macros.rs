macro_rules! impl_from_variant {
    ($name:ident, $enum:ident) => {
        impl_from_variant!($name, $enum, $name);
    };
    ($struct:path, $enum:ident, $variant:ident) => {
        impl From<$struct> for $enum {
            fn from(v: $struct) -> Self {
                $enum::$variant(v)
            }
        }
    };
}

// Implement TryFrom<&str> for a type that implements FromStr
macro_rules! impl_tryfrom_fromstr {
    ($type:ident) => {
        impl TryFrom<&str> for $type {
            type Error = <$type as FromStr>::Err;
            fn try_from(s: &str) -> Result<Self, Self::Error> {
                s.parse()
            }
        }
    };
}

// Simple extraction of a Value enum variant, with no specialized type coercion logic
macro_rules! impl_simple_into_variant {
    ($type:path, $variant:ident, $into_fn_name:ident, $error:ident) => {
        impl TryFrom<Value> for $type {
            type Error = Error;
            fn try_from(value: Value) -> Result<Self> {
                match value {
                    Value::$variant(x) => Ok(x),
                    v => Err(Error::$error(v.into())),
                }
            }
        }
        impl Value {
            pub fn $into_fn_name(self) -> Result<$type> {
                self.try_into()
            }
        }
    };
}

// Error handling utilities

macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err($e.into());
        }
    };
}

macro_rules! bail {
    ($e:expr) => {
        return Err($e.into())
    };
}

// Syntactic sugar for a one-liner lazily-evaluated if expression
macro_rules! iif {
    ($cond:expr, $then:expr, $else:expr) => {
        if $cond {
            $then
        } else {
            $else
        }
    };
}

// Helper macros for PrettyDisplay field formatting

macro_rules! fmt_field {
    ($self:ident, $field:ident, $f:ident, $sep:expr, $is_first:ident, $($arg:tt)*) => {
        if $is_first {
            $is_first = false;
        } else {
            write!($f, ",")?;
        }
        write!($f, "{}\"{}\": ", $sep, stringify!($field))?;
        write!($f, $($arg)*)?;
    };
    // Format using the field's Display by default
    ($self:ident, $field:ident, $f:ident, $sep:expr, $is_first:ident) => {
        fmt_field!($self, $field, $f, $sep, $is_first, "{}", $self.$field)
    };
}

macro_rules! fmt_opt_field {
    ($self:ident, $field:ident, $f:ident, $sep:expr, $is_first:ident, $($arg:tt)*) => {
        if let Some($field) = &$self.$field {
            if $is_first {
                $is_first = false;
            } else {
                write!($f, ",")?;
            }
            write!($f, "{}\"{}\": ", $sep, stringify!($field))?;
            write!($f, $($arg)*)?;
        }
    };
    // Format using the field's Display by default
    ($self:ident, $field:ident, $f:ident, $sep:expr, $is_first:ident) => {
        fmt_opt_field!($self, $field, $f, $sep, $is_first, "{}", $field)
    };
}

#[rustfmt::skip]
macro_rules! fmt_map_field {
    ($self:ident, $field:ident, $f:ident, $sep:expr, $is_first:ident, $inner_indent:expr, $el_fn:expr) => {
        if !$self.$field.is_empty() {
            #[allow(unused_assignments)]
            if $is_first {
                $is_first = false;
            } else {
                write!($f, ",")?;
            }
            write!($f, "{}\"{}\": ", $sep, stringify!($field))?;
            util::fmt_list($f, &mut $self.$field.iter(), $inner_indent, $el_fn)?;
        }
    };
    // Format using the key/value's PrettyDisplay by default
    ($self:ident, $field:ident, $f:ident, $sep:expr, $is_first:ident, $inner_indent:expr) => {
        fmt_map_field!(
            $self, $field, $f, $sep, $is_first, $inner_indent,
            |f, (k, v), el_indent| write!(f, "{}: {}", k.pretty(el_indent), v.pretty(el_indent))
        );
    };
}

macro_rules! impl_simple_pretty {
    ($target:ty, $var:tt, $($arg:tt)*) => {
        impl PrettyDisplay for $target {
            const AUTOFMT_ENABLED: bool = false;

            fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
                let $var = self; // to make it available in the calling context
                write!(f, $($arg)*)
            }
        }
    };
}
