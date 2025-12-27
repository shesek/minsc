use std::convert::{TryFrom, TryInto};

use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{script::Instruction, Opcode, Psbt, ScriptBuf, Transaction};

use bitcoin_scriptexec::{
    Exec, ExecCtx, ExecError, ExecStats, ExecutionResult, Options, Stack, TxTemplate,
};

use crate::parser::Library;
use crate::runtime::{Array, Error, Execute, Mutable, Result, ScopeRef, Symbol, Value};

lazy_static! {
    static ref SCRIPTEXEC_LIB: Library = include_str!("scriptexec.minsc").parse().unwrap();
    static ref SYM_LEGACY: Symbol = Symbol::new(Some("ctx::legacy".into()));
    static ref SYM_SEGWITV0: Symbol = Symbol::new(Some("ctx::segwitv0".into()));
    static ref SYM_TAPSCRIPT: Symbol = Symbol::new(Some("ctx::tapscript".into()));
}

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    {
        let mut scope = scope.borrow_mut();
        scope.set_fn("script::exec", fns::exec).unwrap();
        scope.set_fn("script::trace", fns::trace).unwrap();
        // script::eval(), script::verify(), script::ptrace(), tx::exec() and more are provided by scriptexec.minsc

        scope.set("ctx::legacy", SYM_LEGACY.clone()).unwrap();
        scope.set("ctx::segwitv0", SYM_SEGWITV0.clone()).unwrap();
        scope.set("ctx::tapscript", SYM_TAPSCRIPT.clone()).unwrap();
    }
    SCRIPTEXEC_LIB.exec(scope).unwrap();
}

pub mod fns {
    use super::*;

    pub fn exec(args: Array, _: &ScopeRef) -> Result<Value> {
        let mut exec = init_exec(args)?;
        while exec.exec_next().is_ok() {}
        let result = exec.result().expect("must exists");

        Ok(result.clone().into())
    }

    pub fn trace(args: Array, _: &ScopeRef) -> Result<Value> {
        let mut exec = init_exec(args)?;
        Ok(exec_trace(&mut exec).into())
    }
}

fn init_exec(args: Array) -> Result<Exec> {
    let (script, opt, ctx): (ScriptBuf, _, Option<_>) = args.args_into()?;

    let mut ctx = ctx.unwrap_or(ExecCtx::Tapscript); // TODO auto-detect `ctx` based on prevout/input
    let mut tx = None;
    let mut stack = vec![];
    let mut prevouts = vec![];
    let mut input_idx = 0;
    let mut scriptleaf_annex = (
        TapLeafHash::from_script(&script, LeafVersion::TapScript), // XXX can skip for non-tapscript ctx
        None,
    );
    let mut exec_opt = Options::default();

    match opt {
        // Provided as a tagged array with named fields
        Some(Value::Array(arr)) if arr.first().is_some_and(Value::is_array) => {
            arr.for_each_unique_tag(|tag, val| {
                match tag {
                    "ctx" => ctx = val.try_into()?,
                    "stack" => stack = val.try_into()?,
                    "tx" => tx = Some(val.try_into()?),
                    "utxos" => prevouts = val.try_into()?,
                    "input_index" => input_idx = val.try_into()?,

                    "psbt" => {
                        let psbt = Psbt::try_from(val)?;
                        prevouts = psbt
                            .iter_funding_utxos()
                            .map(|rtxo| Ok(rtxo?.clone()))
                            .collect::<Result<_>>()?;
                        tx = Some(psbt.unsigned_tx);
                    }

                    "script_leaf" => scriptleaf_annex.0 = val.try_into()?,
                    "annex" => scriptleaf_annex.1 = Some(val.try_into()?),

                    "verify_minimal_push" => exec_opt.require_minimal = val.try_into()?,
                    "verify_minimal_if" => exec_opt.verify_minimal_if = val.try_into()?,
                    "verify_csv" => exec_opt.verify_csv = val.try_into()?,
                    "verify_cltv" => exec_opt.verify_cltv = val.try_into()?,
                    "enforce_stack_limit" => exec_opt.enforce_stack_limit = val.try_into()?,
                    "enable_op_cat" => exec_opt.experimental.op_cat = val.try_into()?,

                    _ => bail!(Error::TagUnknown),
                }
                Ok(())
            })?;
        }

        // Provided as an array of stack elements
        Some(Value::Array(arr)) => stack = arr.try_into()?,

        // Provided as just the ExecCtx
        Some(Value::Symbol(sym)) => ctx = sym.try_into()?,

        Some(other) => bail!(Error::InvalidValue(other.into())),
        None => {}
    }

    Ok(Exec::new(
        ctx,
        exec_opt,
        TxTemplate {
            tx: tx.unwrap_or_else(|| Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            }),
            prevouts,
            input_idx,
            taproot_annex_scriptleaf: Some(scriptleaf_annex),
        },
        script,
        stack,
    )?)
}

fn exec_trace(exec: &mut Exec) -> ExecTrace {
    let init_stack = exec.stack().clone();
    let mut steps = Vec::new();
    let result = loop {
        // Record the op at the current position, prior to exec_next() advancing it
        let position = exec.script_position();
        let remaining_script = exec.remaining_script();
        let opcode = remaining_script.first_opcode();
        let push = match remaining_script.instructions().next() {
            Some(Ok(Instruction::PushBytes(push))) if !push.is_empty() => {
                Some(push.as_bytes().to_vec())
            }
            _ => None,
        };

        let pre_cond_state = exec.cond_stack().all_true();

        let exec_result = exec.exec_next().map_err(Clone::clone);

        if let Some(opcode) = opcode {
            // considered executed if cond_state was already true, or if
            // the executed opcode switched it to true (OP_ELSE/OP_ENDIF)
            let executed = pre_cond_state || exec.cond_stack().all_true();
            steps.push(ExecStep {
                position,
                opcode,
                unexecuted: !executed,
                push,
                stack: exec.stack().clone(),
                altstack: exec.altstack().clone(),
            });
        } // if it is a None, we reached the end of script and there was no step to trace

        // the Err variant indicates completion (end of script or an error)
        if let Err(result) = exec_result {
            break result;
        }
    };

    ExecTrace {
        init_stack,
        steps,
        result,
        stats: exec.stats().clone(),
    }
}
// TODO debug marker support

#[derive(Debug)]
pub struct ExecTrace {
    pub init_stack: Stack,
    pub steps: Vec<ExecStep>,
    pub result: ExecutionResult,
    pub stats: ExecStats,
}

#[derive(Debug)]
pub struct ExecStep {
    pub position: usize,
    pub opcode: Opcode,
    /// true when inside an unexecuted IF branch
    pub unexecuted: bool,
    pub push: Option<Vec<u8>>,
    pub stack: Stack,
    pub altstack: Stack,
}

#[rustfmt::skip]
impl_simple_to_value!(ExecTrace, trace, (
    ("init_stack", trace.init_stack),
    ("steps", trace.steps),
    ("result", trace.result),
    ("stats", trace.stats),
));

impl_simple_to_value!(ExecStep, step, {
    let mut tags: Array = (("opcode", step.opcode),).into();
    if step.unexecuted {
        tags.push(("unexecuted", true).into());
    }
    if let Some(push) = step.push {
        tags.push(("push", push).into());
    }
    tags.push(("stack", step.stack).into());
    if !step.altstack.is_empty() {
        tags.push(("altstack", step.altstack).into());
    }
    (step.position, tags)
});

// rust-bitcoin-scriptexec native structures

impl_simple_to_value!(ExecutionResult, res, {
    let mut tags: Array = (("success", res.success),).into();
    if let Some(err) = res.error {
        tags.push(("error", err).into());
    }
    if let Some(opcode) = res.opcode {
        tags.push(("failed_opcode", opcode).into());
    }
    tags.push(("stack", res.final_stack).into());
    tags
});

impl_simple_to_value!(ExecError, e, format!("{:?}", e));
impl_simple_to_value!(Stack, s, s.iter_str().collect::<Vec<_>>());

#[rustfmt::skip]
impl_simple_to_value!(ExecStats, s, (
    ("max_nb_stack_items", s.max_nb_stack_items),
    ("opcode_count", s.opcode_count),
    ("start_validation_weight", s.start_validation_weight),
    ("validation_weight", s.validation_weight),
));

impl TryFrom<Value> for ExecCtx {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Symbol::try_from(value)?.try_into()
    }
}
impl TryFrom<Symbol> for ExecCtx {
    type Error = Error;
    fn try_from(sym: Symbol) -> Result<Self> {
        Ok(if sym == *SYM_LEGACY {
            ExecCtx::Legacy
        } else if sym == *SYM_SEGWITV0 {
            ExecCtx::SegwitV0
        } else if sym == *SYM_TAPSCRIPT {
            ExecCtx::Tapscript
        } else {
            bail!(Error::InvalidValue(Box::new(sym.into())));
        })
    }
}
