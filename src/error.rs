use crate::Ident;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Assigned variable name already exists: {0}")]
    AssignedVariableExists(Ident),

    #[error("Missing function: {0}")]
    FnNotFound(Ident),

    #[error("Not a function: {0}")]
    NotFn(Ident),

    #[error("Function {0} expected {1} arguments, not {2}")]
    ArgumentMismatch(Ident, usize, usize),
}
