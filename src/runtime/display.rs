use std::fmt;

use bitcoin::hex::DisplayHex;

use super::Value;

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Mostly round-trip-able, see ExprRepr for a string representation that always is
        match self {
            Value::Number(x) => write!(f, "{}", x),
            Value::Bool(x) => write!(f, "{}", x),
            Value::Bytes(x) => write!(f, "0x{}", x.as_hex()),
            Value::String(x) => fmt_quoted_str(f, x),
            Value::Policy(x) => write!(f, "{}", x),
            Value::WithProb(p, x) => write!(f, "{}@{}", p, x),
            Value::Function(x) => write!(f, "{}", x), // not round-trip-able (cannot be)
            Value::Network(x) => write!(f, "{}", x),
            Value::Symbol(x) => write!(f, "{}", x),
            Value::Descriptor(x) => write!(f, "{}", x.pretty(None)), // not round-trip-able (ExprRepr is)
            Value::Psbt(x) => write!(f, "{}", x.pretty(None)),
            Value::SecKey(x) => write!(f, "{}", x.pretty(None)),
            Value::PubKey(x) => write!(f, "{}", x.pretty(None)),
            Value::Array(x) => write!(f, "{}", x.pretty(None)),
            Value::Transaction(x) => write!(f, "{}", x.pretty(None)),
            Value::Script(x) => write!(f, "{}", x.pretty(None)),
            Value::Address(x) => write!(f, "{}", x.pretty(None)),
            Value::TapInfo(x) => write!(f, "{}", x.pretty(None)),
            Value::WshScript(x) => write!(f, "{}", x.pretty(None)),
        }
    }
}

impl PrettyDisplay for Value {
    const AUTOFMT_ENABLED: bool = false;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        match self {
            Value::PubKey(x) => write!(f, "{}", x.pretty(indent)),
            Value::SecKey(x) => write!(f, "{}", x.pretty(indent)),
            Value::Array(x) => write!(f, "{}", x.pretty(indent)),
            Value::Script(x) => write!(f, "{}", x.pretty(indent)),
            Value::Address(x) => write!(f, "{}", x.pretty(indent)),
            Value::Transaction(x) => write!(f, "{}", x.pretty(indent)),
            Value::TapInfo(x) => write!(f, "{}", x.pretty(indent)),
            Value::Psbt(x) => write!(f, "{}", x.pretty(indent)),
            Value::WshScript(x) => write!(f, "{}", x.pretty(indent)),
            Value::Descriptor(x) => write!(f, "{}", x.pretty(indent)),

            // Use Display for other types that don't implement PrettyDisplay
            other => write!(f, "{}", other),
        }
    }
}

/// Display-like with custom formatting options, newlines/indentation handling and the ability to implement on foreign types
pub trait PrettyDisplay: Sized {
    const AUTOFMT_ENABLED: bool;
    const MAX_ONELINER_LENGTH: usize = 125;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result;

    /// Use multi-line indented formatting for long lines ove MAX_ONELINER_LENGTH,
    /// or the one-liner formatting otherwise
    fn auto_fmt<W: fmt::Write>(&self, w: &mut W, indent: Option<usize>) -> fmt::Result {
        if !Self::AUTOFMT_ENABLED || indent.is_none() || self.prefer_multiline_anyway() {
            return self.pretty_fmt(w, indent);
        }

        // Try formatting into a buffer with no newlines first, to determine whether it exceeds the length limit.
        // The LimitedWriter will reject writes once the limit is reached, terminating the process midway through.
        let mut one_liner = String::new();
        let mut lwriter = LimitedWriter::new(&mut one_liner, Self::MAX_ONELINER_LENGTH);
        if self.pretty_fmt(&mut lwriter, None).is_ok() {
            // Fits in MAX_ONELINER_LIMIT, forward the buffered string to the outer `w` formatter
            write!(w, "{}", one_liner)
        } else {
            // The one-liner was too long, use multi-line formatting with indentation instead
            self.pretty_fmt(w, indent)
        }
    }

    /// Don't try fitting into a one-liner if this test passes
    fn prefer_multiline_anyway(&self) -> bool {
        false
    }

    /// Get back a Display-able struct with pretty-formatting
    fn pretty(&self, indent: Option<usize>) -> PrettyDisplayer<'_, Self> {
        PrettyDisplayer {
            inner: self,
            indent,
        }
    }
    fn pretty_multiline(&self) -> PrettyDisplayer<'_, Self> {
        self.pretty(Some(0))
    }

    fn pretty_str(&self) -> String {
        self.pretty(None).to_string()
    }
    fn multiline_str(&self) -> String {
        self.pretty_multiline().to_string()
    }
}

/// A wrapper type implementing Display over PrettyDisplay::auto_fmt()
#[derive(Debug)]
pub struct PrettyDisplayer<'a, T: PrettyDisplay> {
    inner: &'a T,
    /// Setting this implies enabling new-lines
    indent: Option<usize>,
}
impl<'a, T: PrettyDisplay> fmt::Display for PrettyDisplayer<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.auto_fmt(f, self.indent)
    }
}

impl_simple_pretty!(Vec<u8>, bytes, "0x{}", bytes.as_hex());

impl<T: PrettyDisplay> PrettyDisplay for Vec<T> {
    const AUTOFMT_ENABLED: bool = true;
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        fmt_list(f, self.iter(), indent, |f, el, inner_indent| {
            write!(f, "{}", el.pretty(inner_indent))
        })
    }
}

pub fn fmt_quoted_str<W: fmt::Write>(f: &mut W, str: &str) -> fmt::Result {
    write!(f, "\"")?;
    for char in str.chars() {
        match char {
            '\r' => write!(f, "\\r")?,
            '\n' => write!(f, "\\n")?,
            '\t' => write!(f, "\\t")?,
            '"' => write!(f, "\\\"")?,
            _ => write!(f, "{}", char)?,
        };
    }
    write!(f, "\"")
}

pub fn quote_str(s: &str) -> String {
    let mut quoted = String::with_capacity(s.len());
    fmt_quoted_str(&mut quoted, s).unwrap();
    quoted
}

pub const INDENT_WIDTH: usize = 2;

pub fn fmt_list<T, F, W, I>(w: &mut W, iter: I, indent: Option<usize>, func: F) -> fmt::Result
where
    W: fmt::Write,
    I: Iterator<Item = T>,
    F: Fn(&mut W, T, Option<usize>) -> fmt::Result,
{
    let (newline_or_space, inner_indent, indent_w, inner_indent_w) = indentation_params(indent);

    write!(w, "[")?;
    for (i, item) in iter.enumerate() {
        if i > 0 {
            write!(w, ",")?;
        }
        write!(w, "{newline_or_space}{:inner_indent_w$}", "")?;
        func(w, item, inner_indent)?;
    }
    write!(w, "{newline_or_space}{:indent_w$}]", "")
}

pub fn indentation_params(indent: Option<usize>) -> (&'static str, Option<usize>, usize, usize) {
    let newline_or_space = iif!(indent.is_some(), "\n", " ");
    let inner_indent = indent.map(|n| n + 1);
    let indent_w = indent.map_or(0, |n| n * INDENT_WIDTH);
    let inner_indent_w = inner_indent.map_or(0, |n| n * INDENT_WIDTH);

    (newline_or_space, inner_indent, indent_w, inner_indent_w)
}

/// A Write wrapper that allows up the `limit` bytes to be written through it to the inner `writer`.
/// If the limit is reached, an fmt::Error is raised. This is used as an optimization by PrettyDisplay.
pub struct LimitedWriter<'a, W: fmt::Write + ?Sized> {
    writer: &'a mut W,
    limit: usize,
    total: usize,
}
impl<'a, W: fmt::Write + ?Sized> LimitedWriter<'a, W> {
    pub fn new(writer: &'a mut W, limit: usize) -> Self {
        LimitedWriter {
            writer,
            limit,
            total: 0,
        }
    }
}
impl<W: fmt::Write + ?Sized> fmt::Write for LimitedWriter<'_, W> {
    fn write_str(&mut self, buf: &str) -> fmt::Result {
        self.total += buf.len();
        if self.total > self.limit {
            Err(fmt::Error)
        } else {
            self.writer.write_str(buf)
        }
    }
}
