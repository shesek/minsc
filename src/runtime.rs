use std::borrow::Borrow;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

use bitcoin::blockdata::script::Builder as ScriptBuilder;
use bitcoin::hashes::{self, hex::ToHex, Hash};
use bitcoin::util::bip32::DerivationPath;
use bitcoin::{Address, Network, Script};
use miniscript::bitcoin;
use miniscript::descriptor::DescriptorPublicKey;

use crate::ast::{self, Expr, Stmt};
use crate::function::{Call, Function};
use crate::util::{DeriveExt, DescriptorExt, MiniscriptExt, EC};
use crate::{stdlib, time, Descriptor, Error, Miniscript, Policy, Result, Scope};

/// A runtime value. This is what gets passed around as function arguments, returned from functions,
/// and assigned to variables.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    PubKey(DescriptorPublicKey),
    Bytes(Vec<u8>),
    Number(i64),
    Bool(bool),
    Network(Network),

    Policy(Policy),
    WithProb(usize, Box<Value>),

    Miniscript(Miniscript),
    Descriptor(Descriptor),
    Script(Script),
    Address(Address),

    Function(Function),
    Array(Vec<Value>),
}

impl_from_variant!(Policy, Value);
impl_from_variant!(Miniscript, Value);
impl_from_variant!(Descriptor, Value);
impl_from_variant!(DescriptorPublicKey, Value, PubKey);
impl_from_variant!(Script, Value);
impl_from_variant!(Address, Value);
impl_from_variant!(Vec<Value>, Value, Array);
impl_from_variant!(Vec<u8>, Value, Bytes);
impl_from_variant!(Network, Value);
impl_from_variant!(i64, Value, Number);
impl_from_variant!(bool, Value, Bool);
impl From<usize> for Value {
    fn from(num: usize) -> Self {
        Value::Number(num.try_into().unwrap())
    }
}
impl<T: Into<Function>> From<T> for Value {
    fn from(f: T) -> Self {
        Value::Function(f.into())
    }
}

/// Evaluate an expression. Expressions have no side-effects and return a value.
pub trait Evaluate {
    fn eval(&self, scope: &Scope) -> Result<Value>;
}

/// Execute a statement. Statements have side-effects and don't have a return value.
pub trait Execute {
    fn exec(&self, scope: &mut Scope) -> Result<()>;
}

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

impl Execute for Stmt {
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        match self {
            Stmt::FnDef(x) => x.exec(scope),
            Stmt::Assign(x) => x.exec(scope),
        }
    }
}

impl Evaluate for ast::Call {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        call_exprs(scope, &self.ident, &self.args)
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
    // Peek at the first operand to determine if its an operation between booleans or between descriptors.
    // All the other operands are expected to have the same type.
    let first_operand = operands[0].eval(scope)?;
    match &first_operand {
        Value::Bool(_) => eval_bool_andor(first_operand, &operands[1..], scope, bool_stop_on),
        Value::Policy(_) | Value::WithProb(_, _) => {
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
            other => bail!(Error::NotArray(other)),
        })
    }
}

impl Evaluate for ast::ChildDerive {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let parent = self.parent.eval(scope)?;
        let mut path = DerivationPath::master();
        for child in &self.path {
            let child = child.eval(scope)?.into_usize()? as u32;
            path = path.into_child(child.into());
        }

        parent.derive_path(path, self.is_wildcard)
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

fn script_frag(value: Value) -> Result<Script> {
    Ok(match value {
        // As script code
        v @ Value::Script(_) | v @ Value::Miniscript(_) | v @ Value::Policy(_) => {
            v.into_script()?
        }

        // As data pushes
        Value::Number(n) => ScriptBuilder::new().push_int(n).into_script(),
        Value::Bool(val) => ScriptBuilder::new().push_int(val as i64).into_script(),
        Value::Bytes(bytes) => ScriptBuilder::new().push_slice(&bytes).into_script(),
        Value::PubKey(desc_pubkey) => {
            let pubkey = desc_pubkey.derive_public_key(&EC)?;
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
            scriptbytes.into()
        }

        v => bail!(Error::InvalidScriptFrag(v)),
    })
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
            .map_err(|e| Error::OpError(self.op, e.into()))
    }
}

impl ast::InfixOp {
    fn apply(&self, lhs: Value, rhs: Value) -> Result<Value> {
        use ast::InfixOp::*;
        use Value::*;

        Ok(match (self, lhs, rhs) {
            // == != for all types
            (Eq, a, b) => (a == b).into(),
            (NotEq, a, b) => (a != b).into(),
            // < > <= >= for numbers only
            (Gt, Number(a), Number(b)) => (a > b).into(),
            (Lt, Number(a), Number(b)) => (a < b).into(),
            (Gte, Number(a), Number(b)) => (a >= b).into(),
            (Lte, Number(a), Number(b)) => (a <= b).into(),
            // + - for numbers
            (Add, Number(a), Number(b)) => a.checked_add(b).ok_or(Error::Overflow)?.into(),
            (Subtract, Number(a), Number(b)) => a.checked_sub(b).ok_or(Error::Overflow)?.into(),
            // + for arrays
            (Add, Array(a), Array(b)) => [a, b].concat().into(),
            // + for bytes
            (Add, Bytes(a), Bytes(b)) => [a, b].concat().into(),
            // @ to assign execution probability
            (Prob, Number(prob), value) => WithProb(prob.try_into()?, value.into()),
            // + for tap tweak (internal_key+script_tree)
            (Add, i @ PubKey(_), t)
            | (Add, i @ Bytes(_), t @ Script(_))
            | (Add, i @ Bytes(_), t @ Miniscript(_))
            | (Add, i @ Bytes(_), t @ Policy(_))
            | (Add, i @ Bytes(_), t @ Array(_)) => stdlib::taproot::tap_tweak(i, Some(t))?.into(),

            _ => bail!(Error::InvalidArguments),
        })
    }
}

impl Evaluate for ast::Duration {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let block_interval = scope
            .get(&"BLOCK_INTERVAL".into())
            .expect("built-in var")
            .clone()
            .into_usize()? as f64;
        let seq_num = time::duration_to_seq(self, block_interval)?;
        Ok(Value::Number(seq_num as i64))
    }
}

impl Evaluate for ast::DateTime {
    fn eval(&self, _: &Scope) -> Result<Value> {
        let unix_timestamp = time::parse_datetime(&self.0)?;
        Ok(Value::Number(unix_timestamp as i64))
    }
}

impl Evaluate for ast::BtcAmount {
    fn eval(&self, _: &Scope) -> Result<Value> {
        let amount = bitcoin::Amount::from_str(&self.0)?;
        Ok(Value::Number(amount.as_sat().try_into()?))
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

impl Execute for ast::Library {
    // Execute the library in the given scope, producing visible side-effects
    fn exec(&self, scope: &mut Scope) -> Result<()> {
        for stmt in &self.stmts {
            stmt.exec(scope)?;
        }
        Ok(())
    }
}

impl Evaluate for Expr {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        Ok(match self {
            Expr::Ident(x) => x.eval(scope)?,
            Expr::Call(x) => x.eval(scope)?,
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

            Expr::Duration(x) => x.eval(scope)?,
            Expr::DateTime(x) => x.eval(scope)?,
            Expr::BtcAmount(x) => x.eval(scope)?,
            Expr::PubKey(x) => Value::PubKey(x.parse()?),
            Expr::Bytes(x) => Value::Bytes(x.clone()),
            Expr::Number(x) => Value::Number(*x),
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

impl TryFrom<Value> for Policy {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Policy(policy) => Ok(policy),
            Value::PubKey(pubkey) => Ok(Policy::Key(pubkey)),
            arr @ Value::Array(_) => stdlib::miniscript::fns::all_(arr)?.try_into(),
            v => Err(Error::NotPolicyLike(v)),
        }
    }
}

impl TryFrom<Value> for i64 {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Number(n) => Ok(n),
            v => Err(Error::NotNumber(v)),
        }
    }
}

macro_rules! impl_num_conv {
    ($type:path, $fn_name:ident) => {
        impl TryFrom<Value> for $type {
            type Error = Error;
            fn try_from(value: Value) -> Result<Self> {
                Ok(value.into_i64()?.try_into()?)
            }
        }
        impl Value {
            pub fn $fn_name(self) -> Result<$type> {
                self.try_into()
            }
        }
    };
}
impl_num_conv!(usize, into_usize);
impl_num_conv!(u32, into_u32);
impl_num_conv!(u64, into_u64);
impl_num_conv!(i32, into_i32);

impl TryFrom<Value> for bool {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Bool(b) => Ok(b),
            v => Err(Error::NotBool(v)),
        }
    }
}

impl TryFrom<Value> for DescriptorPublicKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        use bitcoin::util::key::{PublicKey, XOnlyPublicKey};
        use miniscript::descriptor::{DescriptorSinglePub, SinglePubKey};
        match value {
            Value::PubKey(x) => Ok(x),
            Value::Bytes(bytes) => {
                let key = match bytes.len() {
                    33 => SinglePubKey::FullKey(PublicKey::from_slice(&bytes)?),
                    32 => SinglePubKey::XOnly(XOnlyPublicKey::from_slice(&bytes)?),
                    // uncompressed keys are currently unsupported
                    len => bail!(Error::InvalidPubKeyLen(len)),
                };
                Ok(DescriptorPublicKey::SinglePub(DescriptorSinglePub {
                    key,
                    origin: None,
                }))
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
            Value::Miniscript(x) => Ok(Descriptor::new_wsh(x)?),
            Value::Policy(x) => Ok(Descriptor::new_wsh(x.compile()?)?),
            Value::PubKey(x) => Ok(Descriptor::new_wpkh(x)?),
            v => Err(Error::NotDescriptorLike(v)),
        }
    }
}
impl TryFrom<Value> for Miniscript {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Miniscript(x) => Ok(x),
            Value::Policy(x) => Ok(x.compile()?),
            v => Err(Error::NotMiniscriptLike(v)),
        }
    }
}

impl TryFrom<Value> for Vec<u8> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Bytes(bytes) => bytes,
            Value::Script(script) => script.into_bytes(),
            v => bail!(Error::NotBytes(v)),
        })
    }
}

impl TryFrom<Value> for Vec<Value> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Array(array) => Ok(array),
            v => Err(Error::NotArray(v)),
        }
    }
}

impl TryFrom<Value> for Function {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Function(f) => Ok(f),
            v => Err(Error::NotFn(v)),
        }
    }
}

impl TryFrom<Value> for Network {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::Network(network) => Ok(network),
            v => Err(Error::NotNetwork(v)),
        }
    }
}

impl TryFrom<Value> for Script {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Script(script) => script,
            Value::Bytes(bytes) => bytes.into(),
            v @ Value::Miniscript(_) | v @ Value::Policy(_) => {
                v.into_miniscript()?.derive_keys()?.encode()
            }
            v => bail!(Error::NotScriptLike(v)),
        })
    }
}

impl TryFrom<Value> for String {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(String::from_utf8(value.into_bytes()?)?)
    }
}

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
                Value::Bytes(hash.into_inner().to_vec())
            }
        }
    };
}
impl_hash_conv!(hashes::sha256::Hash);
impl_hash_conv!(hashes::sha256d::Hash);
impl_hash_conv!(hashes::ripemd160::Hash);
impl_hash_conv!(hashes::hash160::Hash);

impl Value {
    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }
    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }
    pub fn into_policy(self) -> Result<Policy> {
        self.try_into()
    }
    pub fn into_i64(self) -> Result<i64> {
        self.try_into()
    }
    pub fn into_bool(self) -> Result<bool> {
        self.try_into()
    }
    pub fn into_key(self) -> Result<DescriptorPublicKey> {
        self.try_into()
    }
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.try_into()
    }
    pub fn into_miniscript(self) -> Result<Miniscript> {
        self.try_into()
    }
    pub fn into_desc(self) -> Result<Descriptor> {
        self.try_into()
    }
    pub fn into_script(self) -> Result<Script> {
        self.try_into()
    }
    pub fn into_string(self) -> Result<String> {
        self.try_into()
    }
    pub fn into_fn(self) -> Result<Function> {
        self.try_into()
    }
    pub fn into_array(self) -> Result<Vec<Value>> {
        self.try_into()
    }
    pub fn into_spk(self) -> Result<Script> {
        // Need to check if its 'descriptor-like' first because Miniscript/Policy are both
        if self.is_desc_like() {
            self.into_desc()?.to_script_pubkey()
        } else {
            self.into_script()
        }
    }

    pub fn is_script_like(&self) -> bool {
        matches!(self, Value::Script(_) | Value::Bytes(_)) || self.is_miniscript_like()
    }
    pub fn is_desc_like(&self) -> bool {
        matches!(self, Value::Descriptor(_) | Value::PubKey(_)) || self.is_miniscript_like()
    }
    pub fn is_miniscript_like(&self) -> bool {
        matches!(self, Value::Miniscript(_) | Value::Policy(_))
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Value::PubKey(x) => write!(f, "{}", x),
            Value::Number(x) => write!(f, "{}", x),
            Value::Bool(x) => write!(f, "{}", x),
            Value::Bytes(x) => write!(f, "0x{}", x.to_hex()),
            Value::Policy(x) => write!(f, "{}", x),
            Value::WithProb(p, x) => write!(f, "{}@{}", p, x),
            Value::Miniscript(x) => write!(f, "{}", x),
            Value::Descriptor(x) => write!(f, "{}", x),
            Value::Address(x) => write!(f, "{}", x),
            Value::Script(x) => write!(f, "{:?}", x),
            Value::Function(x) => write!(f, "{:?}", x),
            Value::Network(x) => write!(f, "{}", x),
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
