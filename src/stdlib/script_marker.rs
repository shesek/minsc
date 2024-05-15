use std::{iter, str};

use bitcoin::opcodes::all as ops;
use bitcoin::script::{Instruction, Instructions, Script, ScriptBuf};
use miniscript::bitcoin;

pub trait ScriptMarker {
    /// Iterate over Script, detecting and extracting script markers encoded
    /// as PUSH(magic_bytes) OP_DROP PUSH(kind) OP_DROP PUSH(body) OP_DROP
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
        Some(match self.inner.next()? {
            Err(e) => Err(MarkerError::InvalidScript(e)),
            Ok(Instruction::PushBytes(push)) if push.as_bytes() == self.magic_bytes => {
                read_marker(&mut self.inner).map(MarkerItem::Marker)
            }
            Ok(instruction) => Ok(MarkerItem::Instruction(instruction)),
        })
    }
}

// Attempt to read the marker's kind and body following the marker magic (already read by now).
// Instructions will be consumed from the iterator as long as they match the expected format.
// The first non-matching instruction will result in an error, but remain available in the iterator
// so that they can be included when encoding Script to a string.
fn read_marker<'a>(
    instructions: &mut iter::Peekable<Instructions<'a>>,
) -> Result<Marker<'a>, MarkerError> {
    let res = (|| {
        verify_drop(instructions)?; // look for the OP_DROP following the magic marker
        let kind = str::from_utf8(read_pushdrop(instructions)?)?;
        let body = str::from_utf8(read_pushdrop(instructions)?)?;
        Ok(Marker { kind, body })
    })();

    // Consume errors emitted by the underlying Instructions iterator during marker parsing.
    // Without this, MarkerIterator would emit these errors twice.
    if let Err(MarkerError::InvalidMarkScript(_)) = res {
        // I was not able to satisfy the borrow checker to handle this inside peek_next_instruction(),
        // so this is done here instead.
        let _ = instructions
            .next()
            .expect("was peeked at")
            .expect_err("was an error");
    }
    res
}

// Look for PUSH followed by a DROP and consume them from the Instructions iterator.
// Non-matching instructions will result in an error, but remain in the iterator.
// Note: a PUSH followed by a non-DROP will leave the non-DROP but consume the PUSH.
fn read_pushdrop<'a>(
    instructions: &mut iter::Peekable<Instructions<'a>>,
) -> Result<&'a [u8], MarkerError> {
    match peek_next_instruction(instructions)? {
        Instruction::PushBytes(push) => {
            let push_data = push.as_bytes();
            let _ = instructions.next().expect("just peeked at");
            verify_drop(instructions)?;
            Ok(push_data)
        }
        _ => Err(MarkerError::MissingPush),
    }
}

// Verify that the next instruction is an OP_DROP and consume it
fn verify_drop(instructions: &mut iter::Peekable<Instructions>) -> Result<(), MarkerError> {
    match peek_next_instruction(instructions)? {
        Instruction::Op(opcode) if *opcode == ops::OP_DROP => {
            let _ = instructions.next().expect("just peeked at");
            Ok(())
        }
        _ => Err(MarkerError::MissingDrop),
    }
}

// Peek at the next instruction first, so that non-matching script instructions
// are not prematurely consumed from the inner Instructions iterator.
fn peek_next_instruction<'a, 'b>(
    instructions: &'b mut iter::Peekable<Instructions<'a>>,
) -> Result<&'b Instruction<'a>, MarkerError> {
    match instructions.peek() {
        Some(Ok(inst)) => Ok(inst),
        Some(Err(e)) => Err(MarkerError::InvalidMarkScript(e.clone())),
        None => Err(MarkerError::EarlyEos),
    }
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum MarkerError {
    #[error("ScriptMarker: Missing expected PUSH")]
    MissingPush,

    #[error("ScriptMarker: Missing expected DROP following PUSH")]
    MissingDrop,

    #[error("ScriptMarker: Unexpected end of script")]
    EarlyEos,

    #[error("ScriptMarker: UTF-8 Error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    /// An invalid Script (e.g. end-of-bound PUSH) was detected following the magic marker
    #[error("ScriptMarker: {0}")]
    InvalidMarkScript(bitcoin::script::Error),

    /// An invalid Script was detected, unrelated to the magic marker
    #[error(transparent)]
    InvalidScript(bitcoin::script::Error),
}
