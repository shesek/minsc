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
