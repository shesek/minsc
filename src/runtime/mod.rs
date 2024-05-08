use std::borrow::Borrow;
use std::convert::{TryFrom, TryInto};

use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::blockdata::script::Builder as ScriptBuilder;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::script::{PushBytesBuf, ScriptBuf};
use miniscript::bitcoin;

use crate::parser::{ast, Expr, Stmt};
use crate::util::{self, DeriveExt, EC};
use crate::{stdlib, time};

pub use crate::error::RuntimeError as Error;
pub type Result<T> = std::result::Result<T, Error>;

pub mod array;
pub mod function;
pub mod scope;
pub mod value;
pub use array::{Array, IterValueInto};
pub use function::{Call, Function};
pub use scope::Scope;
pub use value::{FromValue, Number, Number::*, Symbol, Value};

/// Evaluate an expression. Expressions have no side-effects and return a value.
pub trait Evaluate {
    fn eval(&self, scope: &Scope) -> Result<Value>;
}

/// Execute a statement. Statements have side-effects and don't have a return value.
pub trait Execute {
    fn exec(&self, scope: &mut Scope) -> Result<()>;
}

//
// Execution
//

impl Execute for ast::Assign {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        for assignment in &self.0 {
            let value = assignment.rhs.eval(scope)?;
            scope.set(assignment.lhs.clone(), value)?;
        }
        Ok(())
    }
}

impl Execute for ast::FnDef {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        let func = Function::from(self.clone());
        scope.set(self.ident.clone(), func)
    }
}

impl Execute for ast::IfStmt {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        if self.condition.eval(scope)?.into_bool()? {
            self.then_body.exec(scope)
        } else if let Some(else_body) = &*self.else_body {
            else_body.exec(scope)
        } else {
            Ok(())
        }
    }
}

impl Execute for ast::Stmt {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        match self {
            Stmt::FnDef(x) => x.exec(scope),
            Stmt::Assign(x) => x.exec(scope),
            Stmt::If(x) => x.exec(scope),
        }
    }
}

impl Execute for ast::Stmts {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        for stmt in &self.0 {
            stmt.exec(scope)?;
        }
        Ok(())
    }
}

//
// Evaluation
//

impl Evaluate for ast::Call {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let func = self.func.eval(scope)?.into_fn()?;
        let args = eval_exprs(scope, &self.args)?;

        func.call(args, scope).map_err(|e| {
            // Use the function name used by the caller if the function was accessed using a simple
            // identifier. Otherwise, use the name associated with the Function itself (only available
            // for user functions defined using a named fn statement, not for anonymous or native).
            let ident = self.func.as_ident().or_else(|| func.ident());
            Error::CallError(ident.cloned(), e.into())
        })
    }
}

impl Evaluate for ast::IfExpr {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        if self.condition.eval(scope)?.into_bool()? {
            self.then_val.eval(scope)
        } else {
            self.else_val.eval(scope)
        }
    }
}

impl Evaluate for ast::Or {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        eval_andor(&self.0, scope, true, "or", 1)
    }
}

impl Evaluate for ast::And {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        eval_andor(&self.0, scope, false, "and", self.0.len())
    }
}

fn eval_andor(
    operands: &[Expr],
    scope: &Scope,
    bool_stop_on: bool,
    desc_op: &str,
    desc_thresh_n: usize,
) -> Result<Value> {
    // Peek at the first operand to determine if its an operation between booleans or between policies.
    // All the other operands are expected to have the same type.
    let first_operand = operands[0].eval(scope)?;
    match &first_operand {
        Value::Bool(_) => eval_bool_andor(first_operand, &operands[1..], scope, bool_stop_on),
        Value::Policy(_) | Value::WithProb(_, _) | Value::PubKey(_) | Value::Array(_) => {
            eval_policy_andor(desc_op, desc_thresh_n, first_operand, &operands[1..], scope)
        }
        _ => Err(Error::InvalidArguments),
    }
}

// Evaluate && / || for booleans (lazily evaluated)
fn eval_bool_andor(
    first_operand: Value,
    other_exprs: &[Expr],
    scope: &Scope,
    stop_on: bool,
) -> Result<Value> {
    if first_operand.into_bool()? == stop_on {
        return Ok(stop_on.into());
    }
    for expr in other_exprs {
        let operand = expr.eval(scope)?;
        if operand.into_bool()? == stop_on {
            return Ok(stop_on.into());
        }
    }
    Ok((!stop_on).into())
}

// Evaluate && / || for combining policies, using the or()/and()/thres() policy functions
fn eval_policy_andor(
    op_name: &str,
    thresh_n: usize,
    first_policy: Value,
    other_policies: &[Expr],
    scope: &Scope,
) -> Result<Value> {
    let policies = [&[first_policy], &eval_exprs(scope, other_policies)?[..]].concat();
    if policies.len() == 2 {
        // delegate to or()/and() when there are exactly 2 subpolicies
        call_args(scope, &op_name.into(), policies)
    } else {
        // delegate to thresh() when there are more
        let mut args = vec![thresh_n.into()];
        args.extend(policies);
        call_args(scope, &"thresh".into(), args)
    }
}

impl Evaluate for ast::Thresh {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        call_exprs(scope, &"thresh".into(), &[&*self.thresh, &*self.policies])
    }
}

impl Evaluate for ast::Ident {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        scope
            .get(&self)
            .cloned()
            .ok_or_else(|| Error::VarNotFound(self.clone()))
    }
}

impl Evaluate for ast::Array {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let elements = eval_exprs(scope, &self.0)?;
        Ok(elements.into())
    }
}

impl Evaluate for ast::ArrayAccess {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let value = self.array.eval(scope)?;
        let index = self.index.eval(scope)?.into_usize()?;
        Ok(match value {
            Value::Array(mut array) => {
                ensure!(index < array.len(), Error::ArrayIndexOutOfRange);
                array.remove(index)
            }
            Value::Bytes(mut bytes) => {
                ensure!(index < bytes.len(), Error::ArrayIndexOutOfRange);
                (bytes.remove(index) as i64).into()
            }
            other => bail!(Error::NoArrayAccess(other)),
        })
    }
}

impl Evaluate for ast::ChildDerive {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let mut node = self.parent.eval(scope)?;

        for derivation_step in &self.path {
            node = match derivation_step.eval(scope)? {
                // Derive with a BIP 32 child code index number
                Value::Number(child_num) => {
                    let child_num = ChildNumber::from_normal_idx(child_num.into_u32()?)?;
                    node.derive_path(&[child_num][..], self.is_wildcard)?
                }

                // Derive with a hash converted into a series of BIP32 non-hardened derivations using hash_to_child_vec()
                Value::Bytes(bytes) => {
                    let hash = sha256::Hash::from_slice(&bytes)?;
                    node.derive_path(util::hash_to_child_vec(hash), self.is_wildcard)?
                }

                // Derive a BIP389 Multipath descriptor
                Value::Array(child_nums) => {
                    let child_paths = child_nums
                        .into_iter()
                        .map(|c| {
                            // XXX this doesn't support hashes
                            let child_num = ChildNumber::from_normal_idx(c.into_u32()?)?;
                            Ok(DerivationPath::from(&[child_num][..]))
                        })
                        .collect::<Result<Vec<_>>>()?;

                    node.derive_multi(&child_paths, self.is_wildcard)?
                }

                _ => bail!(Error::InvalidDerivationCode),
            }
        }
        Ok(node)
    }
}

impl Evaluate for ast::FnExpr {
    fn eval(&self, _scope: &Scope) -> Result<Value> {
        Ok(Function::from(self.clone()).into())
    }
}

impl Evaluate for ast::ScriptFrag {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let frags = eval_exprs(scope, &self.fragments)?;
        Ok(script_frag(Value::array(frags))?.into())
    }
}

fn script_frag(value: Value) -> Result<ScriptBuf> {
    let push_int = |num| ScriptBuilder::new().push_int(num).into_script();
    let push_slice = |slice| -> Result<_> {
        Ok(ScriptBuilder::new()
            .push_slice(PushBytesBuf::try_from(slice)?)
            .into_script())
    };
    Ok(match value {
        // As script code
        Value::Script(script) => script,

        // As data pushes
        Value::Number(Number::Int(n)) => push_int(n),
        Value::Bool(val) => push_int(val as i64),
        Value::Bytes(bytes) => push_slice(bytes)?,
        Value::String(string) => push_slice(string.into_bytes())?,
        Value::PubKey(desc_pubkey) => {
            let pubkey = desc_pubkey.at_derivation_index(0)?.derive_public_key(&EC)?;
            ScriptBuilder::new().push_key(&pubkey).into_script()
        }

        // Flatten arrays
        Value::Array(elements) => {
            let scriptbytes = elements
                .into_iter()
                .map(|val| Ok(script_frag(val)?.into_bytes()))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<u8>>();
            ScriptBuf::from(scriptbytes)
        }

        Value::Number(Number::Float(n)) => bail!(Error::InvalidScriptFragIntOnly(n)),
        v => bail!(Error::InvalidScriptFrag(v)),
    })
    // XXX could reuse a single ScriptBuilder, if writing raw `ScriptBuf`s into it was possible
}

impl Evaluate for ast::Not {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        Ok((!self.0.eval(scope)?.into_bool()?).into())
    }
}

impl Evaluate for ast::Infix {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        self.op
            .apply(self.lhs.eval(scope)?, self.rhs.eval(scope)?, scope)
            .map_err(|e| Error::InfixOpError(self.op, e.into()))
    }
}

impl ast::InfixOp {
    fn apply(&self, lhs: Value, rhs: Value, scope: &Scope) -> Result<Value> {
        use ast::InfixOp::*;
        use Value::{Array, Bytes, Number as Num, Policy, PubKey, Script, String, WithProb};

        Ok(match (self, lhs, rhs) {
            // == != for all types
            (Eq, a, b) => (a == b).into(),
            (NotEq, a, b) => (a != b).into(),

            // < > <= >= for numbers (integers and floats cannot be mixed)
            (Gt, Num(Int(a)), Num(Int(b))) => (a > b).into(),
            (Lt, Num(Int(a)), Num(Int(b))) => (a < b).into(),
            (Gte, Num(Int(a)), Num(Int(b))) => (a >= b).into(),
            (Lte, Num(Int(a)), Num(Int(b))) => (a <= b).into(),

            (Gt, Num(Float(a)), Num(Float(b))) => (a > b).into(),
            (Lt, Num(Float(a)), Num(Float(b))) => (a < b).into(),
            (Gte, Num(Float(a)), Num(Float(b))) => (a >= b).into(),
            (Lte, Num(Float(a)), Num(Float(b))) => (a <= b).into(),

            // + - * for numbers (integers and floats cannot be mixed)
            (Add, Num(Int(a)), Num(Int(b))) => a.checked_add(b).ok_or(Error::Overflow)?.into(),
            (Subtract, Num(Int(a)), Num(Int(b))) => a.checked_sub(b).ok_or(Error::Overflow)?.into(),
            (Multiply, Num(Int(a)), Num(Int(b))) => a.checked_mul(b).ok_or(Error::Overflow)?.into(),

            (Add, Num(Float(a)), Num(Float(b))) => (a + b).into(),
            (Subtract, Num(Float(a)), Num(Float(b))) => (a - b).into(),
            (Multiply, Num(Float(a)), Num(Float(b))) => (a * b).into(),

            // + for arrays, bytes and strings
            (Add, Array(a), Array(b)) => [a.0, b.0].concat().into(),
            (Add, Bytes(a), Bytes(b)) => [a, b].concat().into(),
            (Add, String(a), String(b)) => [a, b].concat().into(),

            // + for taproot construction (internal_key+script_tree)
            (Add, k @ PubKey(_), s)
            | (Add, k @ Bytes(_), s @ Script(_) | s @ Policy(_) | s @ Array(_)) => {
                stdlib::taproot::tr(k, Some(s), scope)?
            }

            // * to repeat script fragments
            (Multiply, s @ Script(_), Num(Int(n))) | (Multiply, Num(Int(n)), s @ Script(_)) => {
                vec![s; n.try_into()?].into()
            }

            // @ to assign execution probabilities (to Script/Policy only)
            (Prob, Num(prob), v @ Policy(_) | v @ Script(_)) => {
                WithProb(prob.into_usize()?, v.into())
            }

            // A:B array tuple construction
            (Colon, a, b) => vec![a, b].into(),

            // Specialized error for mixed-up number types
            (_, lhs @ Num(Int(_)), rhs @ Num(Float(_)))
            | (_, lhs @ Num(Float(_)), rhs @ Num(Int(_))) => {
                bail!(Error::InfixOpMixedNum(lhs, rhs))
            }

            // Generic error for all other unmatched invocations
            (_, lhs, rhs) => bail!(Error::InfixOpArgs(lhs, rhs)),
        })
    }
}

impl Evaluate for ast::Duration {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let seq_num = match self {
            ast::Duration::BlockHeight(num_blocks) => {
                let num_blocks = num_blocks.eval(scope)?.into_u32()?;
                time::relative_height_to_seq(num_blocks)?
            }
            ast::Duration::BlockTime { parts, heightwise } => {
                let block_interval = scope.builtin("BLOCK_INTERVAL").clone().into_u32()?;

                let time_parts = parts
                    .into_iter()
                    .map(|(num, unit)| Ok((num.eval(scope)?.into_f64()?, *unit)))
                    .collect::<Result<Vec<_>>>()?;

                time::relative_time_to_seq(&time_parts[..], *heightwise, block_interval)?
            }
        };
        Ok(Value::from(seq_num as i64))
    }
}

impl Evaluate for ast::BtcAmount {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let amount_n = self.0.eval(scope)?.into_f64()?;
        let amount = bitcoin::SignedAmount::from_float_in(amount_n, self.1)?;
        Ok(Value::from(amount.to_sat()))
    }
}

impl Evaluate for ast::Block {
    // Execute the block in a new child scope, with no visible side-effects.
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let mut scope = scope.child();
        for stmt in &self.stmts {
            stmt.exec(&mut scope)?;
        }
        if let Some(return_value) = &self.return_value {
            // The return value is the final expression within the function body,
            // optionally prefixed with the `return` keyword
            return_value.eval(&scope)
        } else if let Some(Value::Function(func)) = scope.get(&"main".into()) {
            // The return value is the evaluation of main()
            func.call(vec![], &scope)
        } else {
            Err(Error::NoReturnValue)
        }
    }
}

impl Evaluate for Expr {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        Ok(match self {
            Expr::Ident(x) => x.eval(scope)?,
            Expr::Call(x) => x.eval(scope)?,
            Expr::If(x) => x.eval(scope)?,
            Expr::Or(x) => x.eval(scope)?,
            Expr::And(x) => x.eval(scope)?,
            Expr::Thresh(x) => x.eval(scope)?,
            Expr::Block(x) => x.eval(scope)?,
            Expr::Array(x) => x.eval(scope)?,
            Expr::ArrayAccess(x) => x.eval(scope)?,
            Expr::ChildDerive(x) => x.eval(scope)?,
            Expr::ScriptFrag(x) => x.eval(scope)?,
            Expr::FnExpr(x) => x.eval(scope)?,
            Expr::Infix(x) => x.eval(scope)?,
            Expr::Not(x) => x.eval(scope)?,
            Expr::BtcAmount(x) => x.eval(scope)?, // eval'd as number
            Expr::Duration(x) => x.eval(scope)?,  // eval'd as number

            Expr::Address(x) => Value::Address(x.clone().assume_checked()),
            Expr::PubKey(x) => Value::PubKey(x.clone()),
            Expr::Bytes(x) => Value::Bytes(x.clone()),
            Expr::String(x) => Value::String(x.clone()),
            Expr::Int(x) => Value::Number(Number::Int(*x)),
            Expr::Float(x) => Value::Number(Number::Float(*x)),
            Expr::DateTime(x) => Value::Number(x.timestamp().into()), // eval's as number
        })
    }
}

/// Call the function with the given expressions evaluated into values
fn call_exprs<T: Borrow<Expr>>(scope: &Scope, ident: &ast::Ident, exprs: &[T]) -> Result<Value> {
    call_args(scope, ident, eval_exprs(scope, exprs)?)
}

/// Call the function with the given argument values (already evaluated)
fn call_args(scope: &Scope, ident: &ast::Ident, args: Vec<Value>) -> Result<Value> {
    let func = scope
        .get(ident)
        .ok_or_else(|| Error::FnNotFound(ident.clone()))?;

    func.call(args, scope)
        .map_err(|e| Error::CallError(Some(ident.clone()), e.into()))
}

/// Evaluate a list of expressions to produce a list of values
fn eval_exprs<T: Borrow<Expr>>(scope: &Scope, exprs: &[T]) -> Result<Vec<Value>> {
    exprs.iter().map(|arg| arg.borrow().eval(scope)).collect()
}
