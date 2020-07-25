use std::fmt::Debug;
use std::str::FromStr;

pub fn concat<T>(mut list: Vec<T>, val: Option<T>) -> Vec<T> {
    if let Some(val) = val {
        list.push(val);
    }
    list
}

// extract N out of "N years"
// `s` is assumed to be valid, because the parser already matched it against a regex
pub fn parse_str_prefix<T: FromStr>(s: &str) -> T
where
    <T as FromStr>::Err: Debug,
{
    s.split_ascii_whitespace().next().unwrap().parse().unwrap()
}
