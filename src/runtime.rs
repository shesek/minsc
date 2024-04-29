use std::borrow::Borrow;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, ExtendendPubKey};
use bitcoin::blockdata::script::Builder as ScriptBuilder;
use bitcoin::hashes::{self, sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::key::TweakedPublicKey;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{
    Address, Network, PublicKey, ScriptBuf, WitnessProgram, WitnessVersion, XOnlyPublicKey,
};
use miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, SinglePub, SinglePubKey};
use miniscript::{bitcoin, descriptor, ScriptContext};

use crate::ast::{self, Expr, Stmt};
use crate::function::{Call, Function};
use crate::util::{self, DeriveExt, DescriptorExt, EC};
use crate::{stdlib, time, Error, Result, Scope};
use crate::{DescriptorDpk as Descriptor, MiniscriptDpk as Miniscript, PolicyDpk as Policy};

/// A runtime value. This is what gets passed around as function arguments, returned from functions,
/// and assigned to variables.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    PubKey(DescriptorPublicKey),
    Bytes(Vec<u8>),
    String(String),
    Number(Number),
    Bool(bool),
    Network(Network),

    Policy(Policy),
    WithProb(usize, Box<Value>),

    Descriptor(Descriptor),
    Script(ScriptBuf),
    Address(Address),
    TapInfo(TaprootSpendInfo),

    Function(Function),
    Array(Vec<Value>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Number {
    Int(i64),
    Float(f64),
}
impl_from_variant!(i64, Number, Int);
impl_from_variant!(f64, Number, Float);

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
        for stmt in &self.stmts {
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
        call_exprs(scope, &self.ident, &self.args)
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
            Value::Array(mut elements) => {
                ensure!(index < elements.len(), Error::ArrayIndexOutOfRange);
                elements.remove(index)
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
        Ok(script_frag(Value::Array(frags))?.into())
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
            .apply(self.lhs.eval(scope)?, self.rhs.eval(scope)?)
            .map_err(|e| Error::InfixOpError(self.op, e.into()))
    }
}

impl ast::InfixOp {
    fn apply(&self, lhs: Value, rhs: Value) -> Result<Value> {
        use ast::InfixOp::*;
        use Number::{Float, Int};
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

            // + for arrays
            (Add, Array(a), Array(b)) => [a, b].concat().into(),
            // + for bytes
            (Add, Bytes(a), Bytes(b)) => [a, b].concat().into(),
            // + for strings
            (Add, String(a), String(b)) => [a, b].concat().into(),

            // + for tap tweak (internal_key+script_tree)
            (Add, k @ PubKey(_), s)
            | (Add, k @ Bytes(_), s @ Script(_) | s @ Policy(_) | s @ Array(_)) => {
                stdlib::taproot::tap_tweak(k, s)?
            }

            // @ to assign execution probabilities (to Script/Policy only)
            (Prob, Num(prob), v @ Policy(_) | v @ Script(_)) => {
                WithProb(prob.into_usize()?, v.into())
            }

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

impl Evaluate for ast::DateTime {
    fn eval(&self, _: &Scope) -> Result<Value> {
        let unix_timestamp = time::parse_datetime(&self.0)?;
        Ok(Value::from(unix_timestamp as i64))
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
            Expr::BtcAmount(x) => x.eval(scope)?,

            Expr::Duration(x) => x.eval(scope)?,
            Expr::DateTime(x) => x.eval(scope)?,
            Expr::PubKey(x) => Value::PubKey(x.parse()?),
            Expr::Bytes(x) => Value::Bytes(x.clone()),
            Expr::String(x) => Value::String(x.clone()),
            Expr::Int(x) => Value::Number(Number::Int(*x)),
            Expr::Float(x) => Value::Number(Number::Float(*x)),
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
        .map_err(|e| Error::CallError(ident.clone(), e.into()))
}

/// Evaluate a list of expressions to produce a list of values
fn eval_exprs<T: Borrow<Expr>>(scope: &Scope, exprs: &[T]) -> Result<Vec<Value>> {
    exprs.iter().map(|arg| arg.borrow().eval(scope)).collect()
}

//
// Value conversions
//

// From primitive numbers to Value
impl From<i64> for Value {
    fn from(n: i64) -> Value {
        Number::Int(n).into()
    }
}
impl From<f64> for Value {
    fn from(n: f64) -> Value {
        Number::Float(n).into()
    }
}
impl From<usize> for Value {
    fn from(num: usize) -> Self {
        // TODO this should use TryFrom
        Number::Int(num.try_into().unwrap()).into()
    }
}

// From NativeFunction/UserFunction to Value
impl<T: Into<Function>> From<T> for Value {
    fn from(f: T) -> Self {
        Value::Function(f.into())
    }
}

// From the underlying enum inner type to Value
impl_from_variant!(Policy, Value);
impl_from_variant!(Descriptor, Value);
impl_from_variant!(DescriptorPublicKey, Value, PubKey);
impl_from_variant!(ScriptBuf, Value, Script);
impl_from_variant!(Address, Value);
impl_from_variant!(Vec<Value>, Value, Array);
impl_from_variant!(Vec<u8>, Value, Bytes);
impl_from_variant!(String, Value);
impl_from_variant!(Network, Value);
impl_from_variant!(TaprootSpendInfo, Value, TapInfo);
impl_from_variant!(Number, Value);
impl_from_variant!(bool, Value, Bool);

// From Value to the underlying enum inner type
// Simple extraction of the enum variant, with no specialized type coercion logic
macro_rules! impl_simple_into_variant_conv {
    ($type:path, $variant:ident, $into_fn_name:ident, $error:ident) => {
        impl TryFrom<Value> for $type {
            type Error = Error;
            fn try_from(value: Value) -> Result<Self> {
                match value {
                    Value::$variant(x) => Ok(x),
                    v => Err(Error::$error(v)),
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
impl_simple_into_variant_conv!(bool, Bool, into_bool, NotBool);
impl_simple_into_variant_conv!(Number, Number, into_number, NotNumber);
impl_simple_into_variant_conv!(Vec<Value>, Array, into_array, NotArray);
impl_simple_into_variant_conv!(Network, Network, into_network, NotNetwork);
impl_simple_into_variant_conv!(Function, Function, into_fn, NotFn);
impl_simple_into_variant_conv!(ScriptBuf, Script, into_script, NotScript);
impl_simple_into_variant_conv!(String, String, into_string, NotString);

// From Value to f64 primitive, with coercion rules
// Extracts the f64 out of Number::Float, or casts Value::Int into one
impl TryInto<f64> for Value {
    type Error = Error;
    fn try_into(self) -> Result<f64> {
        Ok(match self.into_number()? {
            Number::Float(n) => n,
            Number::Int(n) => n as f64, // always safe to convert
        })
    }
}

// From Value/Number to primitive integer types, with coercion and overflow checks
// Automatically coerces floats into integers when they are whole, finite and within the integer type range
macro_rules! impl_int_num_conv {
    ($type:ident, $fn_name:ident) => {
        impl TryFrom<Number> for $type {
            type Error = Error;
            fn try_from(number: Number) -> Result<Self> {
                fn safe_int_from_f64(n: f64) -> bool {
                    n.is_finite()
                        && n.fract() == 0.0
                        && n >= $type::MIN as f64
                        && n <= $type::MAX as f64
                }
                Ok(match number {
                    Number::Int(n) => n.try_into()?,
                    Number::Float(n) if safe_int_from_f64(n) => n as $type,
                    Number::Float(n) => bail!(Error::NotIntLike(n)),
                })
            }
        }
        impl TryFrom<Value> for $type {
            type Error = Error;
            fn try_from(value: Value) -> Result<Self> {
                // Extract the Value::Number, then delegate to TryFrom<Number> above
                value.into_number()?.try_into()
            }
        }
        impl Number {
            pub fn $fn_name(self) -> Result<$type> {
                self.try_into()
            }
        }
        impl Value {
            pub fn $fn_name(self) -> Result<$type> {
                self.try_into()
            }
        }
    };
}
impl_int_num_conv!(i64, into_i64);
impl_int_num_conv!(usize, into_usize);
impl_int_num_conv!(u32, into_u32);
impl_int_num_conv!(u64, into_u64);
impl_int_num_conv!(i32, into_i32);

// From Value to Bitcoin/Miniscript types
impl TryFrom<Value> for Policy {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Policy(policy) => Ok(policy),
            // Pubkeys are coerced into a pk() policy
            Value::PubKey(pubkey) => Ok(Policy::Key(pubkey)),
            v => Err(Error::NotPolicyLike(v)),
        }
    }
}
impl TryFrom<Value> for DescriptorPublicKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::PubKey(x) => Ok(x),
            // Bytes are coerced into a PubKey when they are 33 or 32 bytes long
            Value::Bytes(bytes) => {
                let key = match bytes.len() {
                    33 => SinglePubKey::FullKey(PublicKey::from_slice(&bytes)?),
                    32 => SinglePubKey::XOnly(XOnlyPublicKey::from_slice(&bytes)?),
                    // uncompressed keys are currently unsupported
                    len => bail!(Error::InvalidPubKeyLen(len)),
                };
                Ok(DescriptorPublicKey::Single(SinglePub { key, origin: None }))
            }
            v => Err(Error::NotPubKey(v)),
        }
    }
}
impl TryFrom<Value> for Descriptor {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Descriptor(x) => Ok(x),
            // PubKeys are coerced into a wpkh() descriptor
            Value::PubKey(x) => Ok(Descriptor::new_wpkh(x)?),
            v => Err(Error::NotDescriptorLike(v)),
        }
    }
}
impl<Ctx: ScriptContext> TryFrom<Value> for Miniscript<Ctx> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(value.into_policy()?.compile()?)
    }
}
impl TryFrom<Value> for TaprootSpendInfo {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::TapInfo(tapinfo) => tapinfo,
            Value::Descriptor(desc) => match desc.at_derivation_index(0)? {
                miniscript::Descriptor::Tr(tr_desc) => (*tr_desc.spend_info()).clone(),
                _ => bail!(Error::NotTapInfoLike(Value::Descriptor(desc))),
            },
            v => bail!(Error::NotTapInfoLike(v)),
        })
    }
}

// From Bitcoin/Miniscript types to Value
impl From<XOnlyPublicKey> for Value {
    fn from(key: XOnlyPublicKey) -> Self {
        Value::PubKey(DescriptorPublicKey::Single(SinglePub {
            key: SinglePubKey::XOnly(key),
            origin: None,
        }))
    }
}
impl From<TweakedPublicKey> for Value {
    fn from(key: TweakedPublicKey) -> Self {
        key.to_inner().into()
    }
}
impl From<ExtendendPubKey> for Value {
    fn from(xpub: ExtendendPubKey) -> Self {
        Value::PubKey(DescriptorPublicKey::XPub(DescriptorXKey {
            xkey: xpub,
            derivation_path: DerivationPath::master(),
            wildcard: descriptor::Wildcard::Unhardened,
            origin: if xpub.depth > 0 {
                Some((xpub.parent_fingerprint, [xpub.child_number][..].into()))
            } else {
                None
            },
        }))
    }
}

// From Value to Vec<u8>
impl TryFrom<Value> for Vec<u8> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Bytes(bytes) => bytes,
            Value::String(string) => string.into_bytes(),
            Value::Script(script) => script.into_bytes(),
            v => bail!(Error::NotBytesLike(v)),
        })
    }
}

// From Value to Hash types +
// From Hash types to Value
macro_rules! impl_hash_conv {
    ($name:path) => {
        impl TryFrom<Value> for $name {
            type Error = Error;
            fn try_from(value: Value) -> Result<Self> {
                match value {
                    Value::Bytes(b) => Ok(Self::from_slice(&b)?),
                    v => Err(Error::NotHashLike(v)),
                }
            }
        }
        impl From<$name> for Value {
            fn from(hash: $name) -> Self {
                Value::Bytes(hash.to_byte_array().to_vec())
            }
        }
    };
}
impl_hash_conv!(hashes::sha256::Hash);
impl_hash_conv!(hashes::sha256d::Hash);
impl_hash_conv!(hashes::ripemd160::Hash);
impl_hash_conv!(hashes::hash160::Hash);
impl_hash_conv!(miniscript::hash256::Hash);

//
// Value methods & traits
//

impl Value {
    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }
    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }
    pub fn is_bytes(&self) -> bool {
        matches!(self, Value::Bytes(_))
    }
    pub fn is_policy(&self) -> bool {
        matches!(self, Value::Policy(_))
    }
    pub fn is_desc(&self) -> bool {
        matches!(self, Value::Descriptor(_))
    }
    pub fn is_script(&self) -> bool {
        matches!(self, Value::Script(_))
    }
    pub fn into_f64(self) -> Result<f64> {
        self.try_into()
    }
    pub fn into_policy(self) -> Result<Policy> {
        self.try_into()
    }
    pub fn into_key(self) -> Result<DescriptorPublicKey> {
        self.try_into()
    }
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.try_into()
    }
    pub fn into_desc(self) -> Result<Descriptor> {
        self.try_into()
    }
    pub fn into_miniscript<Ctx: ScriptContext>(self) -> Result<Miniscript<Ctx>> {
        self.try_into()
    }
    pub fn into_tapinfo(self) -> Result<TaprootSpendInfo> {
        self.try_into()
    }
    pub fn into_spk(self) -> Result<ScriptBuf> {
        Ok(match self {
            // Raw scripts are returned as-is
            Value::Script(script) => script,
            // Descriptors (or values coercible into them) are converted into their scriptPubKey
            v @ Value::Descriptor(_) | v @ Value::PubKey(_) => v.into_desc()?.to_script_pubkey()?,
            // TapInfo returns the output V1 witness program of the output key
            Value::TapInfo(tapinfo) => ScriptBuf::new_witness_program(&WitnessProgram::new(
                WitnessVersion::V1,
                &tapinfo.output_key().serialize(),
            )?),
            v => bail!(Error::NotSpkLike(v)),
        })
    }

    pub fn type_of(&self) -> &'static str {
        match self {
            Value::PubKey(_) => "pubkey",
            Value::Number(_) => "number",
            Value::Bool(_) => "bool",
            Value::Bytes(_) => "bytes",
            Value::String(_) => "string",
            Value::Policy(_) => "policy",
            Value::WithProb(_, _) => "withprob",
            Value::Descriptor(_) => "descriptor",
            Value::Address(_) => "address",
            Value::Script(_) => "script",
            Value::Function(_) => "function",
            Value::Network(_) => "network",
            Value::TapInfo(_) => "tapinfo",
            Value::Array(_) => "array",
        }
    }
}

// Parse & evaluate the string code in the default global scope to produce a Value
impl FromStr for Value {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        s.parse::<Expr>()?.eval(&Scope::root())
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Value::PubKey(x) => write!(f, "{}", x),
            Value::Number(x) => write!(f, "{}", x),
            Value::Bool(x) => write!(f, "{}", x),
            Value::Bytes(x) => write!(f, "0x{}", x.to_lower_hex_string()),
            Value::String(x) => write!(f, "\"{}\"", escape_str(x)),
            Value::Policy(x) => write!(f, "{}", x),
            Value::WithProb(p, x) => write!(f, "{}@{}", p, x),
            Value::Descriptor(x) => write!(f, "{}", x),
            Value::Address(x) => write!(f, "{}", x),
            Value::Script(x) => write!(f, "{:?}", x),
            Value::Function(x) => write!(f, "{:?}", x),
            Value::Network(x) => write!(f, "{}", x),
            Value::TapInfo(x) => write!(f, "{:?}", x),
            Value::Array(elements) => {
                write!(f, "[ ")?;
                for (i, element) in elements.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", element)?;
                }
                write!(f, " ]")
            }
        }
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Number::Int(x) => write!(f, "{}", x),
            Number::Float(x) => write!(f, "{:?}", x),
        }
    }
}

fn escape_str(str: &str) -> String {
    str.bytes()
        .into_iter()
        .flat_map(core::ascii::escape_default)
        .map(char::from)
        .collect()
}
