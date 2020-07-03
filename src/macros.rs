macro_rules! impl_from_variant {
    ($name:ident, $enum:ident) => {
        impl From<$name> for $enum {
            fn from(v: $name) -> Self {
                $enum::$name(v)
            }
        }
    };
}
