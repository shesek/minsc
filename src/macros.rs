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
