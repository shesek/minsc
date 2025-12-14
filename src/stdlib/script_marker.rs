use std::{iter, str};

use bitcoin::opcodes::all::{OP_ENDIF, OP_NOTIF};
use bitcoin::script::{Instruction, Instructions, Script, ScriptBuf};

pub trait ScriptMarker {
    /// Iterate over Script, detecting and extracting script markers encoded
    /// as PUSH(magic_bytes) OP_NOTIF PUSH(kind) PUSH(body) OP_ENDIF
    fn iter_with_markers<'a, 'b>(&'a self, magic_bytes: &'b [u8]) -> MarkerIterator<'a, 'b>;

    /// Strip out script markers
    fn strip_markers(&self, magic_bytes: &[u8]) -> Result<ScriptBuf, MarkerError>;
}

impl ScriptMarker for Script {
    fn iter_with_markers<'a, 'b>(&'a self, magic_bytes: &'b [u8]) -> MarkerIterator<'a, 'b> {
        MarkerIterator {
            inner: self.instructions().peekable(),
            magic_bytes,
        }
    }

    fn strip_markers(&self, magic_bytes: &[u8]) -> Result<ScriptBuf, MarkerError> {
        self.iter_with_markers(magic_bytes)
            .filter_map(|item| match item {
                Ok(MarkerItem::Instruction(inst)) => Some(Ok(inst)),
                Ok(MarkerItem::Marker(_)) => None,
                Err(e) => Some(Err(e)),
            })
            .collect()
    }
}

/// An iterator over Script that detects and extracts script markers encoded in it
#[derive(Debug)]
pub struct MarkerIterator<'a, 'b> {
    inner: iter::Peekable<Instructions<'a>>,
    magic_bytes: &'b [u8],
}

/// Items found during iteration, either a standard Script instruction or a Marker
#[derive(Debug)]
pub enum MarkerItem<'a> {
    Instruction(Instruction<'a>),
    Marker(Marker<'a>),
}

#[derive(Debug)]
/// Marker data extracted from a Script
/// Both kind and body are expected to be a valid UTF-8 string.
pub struct Marker<'a> {
    pub kind: &'a str,
    pub body: &'a str,
}

impl<'a, 'b> Iterator for MarkerIterator<'a, 'b> {
    type Item = Result<MarkerItem<'a>, MarkerError>;

    fn next(&mut self) -> Option<Result<MarkerItem<'a>, MarkerError>> {
        use Instruction as I;

        Some(match self.inner.next()? {
            // Look for a PUSH for the MAGIC_BYTES, followed by an OP_NOTIF
            Ok(I::PushBytes(push))
                if push.as_bytes() == self.magic_bytes
                    && self.inner.next_if_eq(&Ok(I::Op(OP_NOTIF))).is_some() =>
            {
                // Extract the `kind` and optional `body` PUSH instructions
                // Must be valid UTF-8 strings
                let mut pushes = iter::from_fn(|| {
                    let push_instruction =
                        self.inner.next_if(|i| matches!(i, Ok(I::PushBytes(_))))?;
                    let Ok(I::PushBytes(push)) = push_instruction else {
                        unreachable!("checked by next_if()");
                    };
                    Some(str::from_utf8(push.as_bytes()).map_err(Into::into))
                });
                let kind = match pushes.next() {
                    Some(Ok(kind)) => kind,
                    Some(Err(err)) => return Some(Err(err)),
                    None => return Some(Err(MarkerError::MissingPush)),
                };
                let body = match pushes.next() {
                    Some(Ok(body)) => body,
                    Some(Err(err)) => return Some(Err(err)),
                    None => "",
                };

                // Verify the next opcode is an OP_ENDIF
                if self.inner.next_if_eq(&Ok(I::Op(OP_ENDIF))).is_none() {
                    return Some(Err(MarkerError::MissingEndIf));
                }

                Ok(MarkerItem::Marker(Marker { kind, body }))
            }
            Ok(instruction) => Ok(MarkerItem::Instruction(instruction)),
            Err(e) => Err(MarkerError::InvalidScript(e)),
        })
    }
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum MarkerError {
    #[error("ScriptMarker: Missing expected PUSH in NOTIF block")]
    MissingPush,

    #[error("ScriptMarker: Expected ENDIF after 1 or 2 pushes")]
    MissingEndIf,

    #[error("ScriptMarker: UTF-8 Error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error(transparent)]
    InvalidScript(bitcoin::script::Error),
}
