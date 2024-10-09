use std::convert::{TryFrom, TryInto};
use std::fmt;

use bitcoin::hashes::Hash;
use bitcoin::script::{Builder as ScriptBuilder, Instruction, PushBytesBuf, Script, ScriptBuf};
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use bitcoin::{absolute::LockTime as AbsLockTime, relative::LockTime as RelLockTime};
use bitcoin::{
    address, hex::DisplayHex, Address, Amount, Network, Opcode, Sequence, SignedAmount, Txid,
};
use miniscript::psbt::PsbtExt;

use super::script_marker::{Marker, MarkerItem, ScriptMarker};
use crate::runtime::{
    eval_exprs, Array, Error, Evaluate, Execute, Float, Int, Mutable, Result, ScopeRef, Value,
};
use crate::util::{self, fmt_list, DescriptorExt, PrettyDisplay, TapInfoExt, EC};
use crate::{ast, time, Library};

lazy_static! {
    static ref BTC_STDLIB: Library = include_str!("btc.minsc").parse().unwrap();
}

// XXX should this be randomized?
const SCRIPT_MARKER_MAGIC_BYTES: &[u8] = "SCRIPT MARKER MAGIC BYTES".as_bytes();

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    {
        let mut scope = scope.borrow_mut();

        // Network types
        scope.set("signet", Network::Signet).unwrap();
        scope.set("testnet", Network::Testnet).unwrap();
        scope.set("regtest", Network::Regtest).unwrap();
        scope
            .set("_$$_RECKLESSLY_RISK_MY_BITCOINS_$$_", Network::Bitcoin)
            .unwrap();

        // Functions
        scope.set_fn("address", fns::address).unwrap();
        scope.set_fn("tx", fns::tx).unwrap();
        scope.set_fn("txid", fns::txid).unwrap();
        scope.set_fn("tx::id", fns::txid).unwrap(); // alias
        scope.set_fn("script", fns::script).unwrap();
        scope.set_fn("scriptPubKey", fns::scriptPubKey).unwrap();
        scope.set_fn("script::spk", fns::scriptPubKey).unwrap(); // alias
        scope.set_fn("script::strip", fns::script_strip).unwrap();
        scope.set_fn("script::wiz", fns::script_wiz).unwrap();
        scope.set_fn("script::bitide", fns::script_bitide).unwrap();

        // Constants
        scope.set("BLOCK_INTERVAL", time::BLOCK_INTERVAL).unwrap();
        scope
            .set("SCRIPT_MARKER_MAGIC", SCRIPT_MARKER_MAGIC_BYTES.to_vec())
            .unwrap();
    }

    BTC_STDLIB.exec(scope).unwrap();
}

impl Evaluate for ast::BtcAmount {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let amount_n = self.0.eval(scope)?.into_f64()?;
        let amount = SignedAmount::from_float_in(amount_n, self.1)?;
        Ok(Value::from(amount.to_sat()))
    }
}

impl Evaluate for ast::ScriptFrag {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
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
        Value::Number(Int(n)) => push_int(n),
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

        Value::Number(Float(n)) => bail!(Error::InvalidScriptFragIntOnly(n)),
        v => bail!(Error::InvalidScriptFrag(v.into())),
    })
    // XXX could reuse a single ScriptBuilder, if writing raw `ScriptBuf`s into it was possible
}

pub fn repeat_script(script: ScriptBuf, times: usize) -> ScriptBuf {
    let bytes = script.into_bytes();
    let bytes_n: Vec<u8> = (0..times).flat_map(|_| bytes.clone()).collect();
    ScriptBuf::from(bytes_n)
}

impl Evaluate for ast::Duration {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let seq_num = match self {
            ast::Duration::BlockHeight(num_blocks) => {
                let num_blocks = num_blocks.eval(scope)?.into_u32()?;
                time::relative_height_to_seq(num_blocks)?
            }
            ast::Duration::BlockTime { parts, heightwise } => {
                let block_interval = scope.borrow().builtin("BLOCK_INTERVAL").into_u32()?;

                let time_parts = parts
                    .iter()
                    .map(|(num, unit)| Ok((num.eval(scope)?.into_f64()?, *unit)))
                    .collect::<Result<Vec<_>>>()?;

                time::relative_time_to_seq(&time_parts[..], *heightwise, block_interval)?
            }
        };
        Ok(Value::from(seq_num as i64))
    }
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;

    /// Generate an address
    /// address(Script|Descriptor|PubKey|TapInfo|Address, Network=testnet) -> Address
    pub fn address(args: Array, _: &ScopeRef) -> Result<Value> {
        let (spk, network): (Value, Option<Network>) = args.args_into()?;
        let spk = spk.into_spk()?;
        let network = network.unwrap_or(Network::Testnet);

        Ok(Address::from_script(&spk, network)
            .map_err(|_| Error::NotAddressable(spk.into()))?
            .into())
    }

    /// tx(Bytes|Array<Tagged>|Transaction) -> Transaction
    pub fn tx(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::Transaction(args.arg_into()?))
    }

    /// txid(Transaction) -> Bytes
    pub fn txid(args: Array, _: &ScopeRef) -> Result<Value> {
        let mut txid = Transaction::compute_txid(&args.arg_into()?)
            .to_byte_array()
            .to_vec();
        // Reverse when converted to Bytes to match the standard display order,
        // reversed back in `TryFrom<Value> for Txid` (below).
        txid.reverse();
        Ok(Value::Bytes(txid))
    }

    /// script(Bytes|Script) -> Script
    pub fn script(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Script(script) => script.into(),
            Value::Bytes(bytes) => ScriptBuf::from(bytes).into(),
            other => bail!(Error::InvalidScriptConstructor(other.into())),
        })
    }

    /// scriptPubKey(Descriptor|TapInfo|PubKey|Address|Script) -> Script
    ///
    /// Descriptors are compiled into their scriptPubKey
    /// TapInfo are returned as their V1 witness program
    /// PubKeys are converted into a wpkh() script
    /// Scripts are returned as-is
    pub fn scriptPubKey(args: Array, _: &ScopeRef) -> Result<Value> {
        let spk = args.arg_into::<Value>()?.into_spk()?;
        Ok(spk.into())
    }

    /// script::strip(Script) -> Script
    /// Strip debug markers from the given Script
    pub fn script_strip(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args
            .arg_into::<ScriptBuf>()?
            .strip_markers(SCRIPT_MARKER_MAGIC_BYTES)?
            .into())
    }

    /// script::wiz(Script) -> String
    /// Encode the Script in a Scriptwiz-compatible format (newlines, stack labels & comments)
    pub fn script_wiz(args: Array, _: &ScopeRef) -> Result<Value> {
        let script = args.arg_into::<ScriptBuf>()?;
        let mut wiz_str = String::new();
        fmt_script(&mut wiz_str, &script, ScriptFmt::ScriptWiz, Some(0))?;
        Ok(wiz_str.into())
    }

    /// script::bitide(Script) -> String
    /// Encode the Script in a BitIDE-compatible format (newlines, stack labels & comments)
    pub fn script_bitide(args: Array, _: &ScopeRef) -> Result<Value> {
        let script = args.arg_into::<ScriptBuf>()?;
        let mut bitide_str = String::new();
        fmt_script(&mut bitide_str, &script, ScriptFmt::BitIde, Some(0))?;
        Ok(bitide_str.into())
    }
}

impl Value {
    /// Get the scriptPubKey representation of this Value
    pub fn into_spk(self) -> Result<ScriptBuf> {
        Ok(match self {
            // Raw scripts are returned as-is
            Value::Script(script) => script,
            // Descriptors/addresses are converted into their scriptPubKey
            Value::Descriptor(descriptor) => descriptor.to_script_pubkey()?,
            Value::Address(address) => address.script_pubkey(),
            // TapInfo returns the V1 witness program of the output key
            Value::TapInfo(tapinfo) => tapinfo.script_pubkey(),
            other => bail!(Error::NoSpkRepr(other.into())),
        })
    }
    pub fn is_script(&self) -> bool {
        matches!(self, Value::Script(_))
    }
}

// Convert from Value to Bitcoin types

impl_simple_into_variant!(ScriptBuf, Script, into_script, NotScript);
impl_simple_into_variant!(Network, Network, into_network, NotNetwork);

impl TryFrom<Value> for Address {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Address(address) => address,
            Value::String(addr_str) => {
                let addr: Address<address::NetworkUnchecked> = addr_str.parse()?;
                // XXX avoid assume_checked? we don't always know the network at the time the address is parsed.
                addr.assume_checked()
            }
            v => bail!(Error::NotAddress(v.into())),
        })
    }
}

impl TryFrom<Value> for Transaction {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Transaction(tx) => tx,
            Value::Bytes(bytes) => bitcoin::consensus::deserialize(&bytes)?,
            Value::Psbt(psbt) => psbt.extract(&EC)?,

            // From tagged [ "version": $version, "locktime": $locktime, "inputs": [ .. ], "outputs": [ .. ] ]
            Value::Array(_) => {
                let mut tx = Transaction {
                    version: Version(2),
                    lock_time: AbsLockTime::ZERO,
                    input: vec![],
                    output: vec![],
                };
                value.for_each_tag(|tag, val| {
                    match tag {
                        "version" => tx.version = val.try_into()?,
                        "locktime" => tx.lock_time = val.try_into()?,
                        "input" => tx.input.push(val.try_into()?),
                        "output" => tx.output.push(val.try_into()?),
                        "inputs" => tx.input.extend(val.into_vec_of()?),
                        "outputs" => tx.output.extend(val.into_vec_of()?),
                        _ => bail!(Error::TagUnknown),
                    }
                    Ok(())
                })?;
                tx
            }

            other => bail!(Error::NotTxLike(other.into())),
        })
    }
}

// From tagged [ "prevout": $txid:$vout, "sequence": $sequence, "script_sig": `0x00 0x01`, "witness": [ .. ] ]
//  or just the $txid:vout
impl TryFrom<Value> for TxIn {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        use Default as D;

        let (previous_output, sequence, script_sig, witness) = if value.is_tagged_or_empty() {
            value.tagged_into4_default("prevout", "sequence", "script_sig", "witness")?
        } else {
            (value.try_into()?, D::default(), D::default(), D::default())
        };

        Ok(TxIn {
            previous_output,
            sequence,
            script_sig,
            witness,
        })
    }
}

// From tagged [ "scriptPubKey": $address, "amount": $amount ] or $address:$amount
impl TryFrom<Value> for TxOut {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        let (spk, amount): (Value, Amount) = val.tagged_or_tuple("script_pubkey", "amount")?;
        Ok(TxOut {
            script_pubkey: spk.into_spk()?,
            value: amount,
        })
    }
}

// From [ "txid": $txid, "vout": $vout ] or $txid:$vout
impl TryFrom<Value> for OutPoint {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        let (txid, vout) = val.tagged_or_tuple("txid", "vout")?;
        Ok(OutPoint::new(txid, vout))
    }
}

impl TryFrom<Value> for Txid {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val {
            Value::Bytes(mut bytes) => {
                // Reverse back from the reversed order used for txid display.
                // fns::txid() (above) does the opposite.
                bytes.reverse();
                Txid::from_slice(&bytes)?
            }
            Value::Transaction(tx) => tx.compute_txid(),
            // The psbt unsigned_tx's txid is useless if there are any non-segwit inputs. Use with care. Should probably check :>
            // (Note however that Minsc itself does not support pre-segwit descriptors construction)
            Value::Psbt(psbt) => psbt.unsigned_tx.compute_txid(),
            other => bail!(Error::NotTxidLike(other.into())),
        })
    }
}
impl TryFrom<Value> for Amount {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Amount::from_sat(val.into_u64()?))
    }
}
impl TryFrom<Value> for AbsLockTime {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(AbsLockTime::from_consensus(val.into_u32()?))
    }
}
impl TryFrom<Value> for Version {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Version(val.into_i32()?))
    }
}
impl TryFrom<Value> for Sequence {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Sequence(match val {
            Value::Bytes(bytes) => u32::from_be_bytes(bytes.as_slice().try_into()?),
            Value::Number(num) => num.into_u32()?,
            other => bail!(Error::InvalidValue(other.into())),
        }))
    }
}
impl TryFrom<Value> for bitcoin::Witness {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        let items = val.map_array(Value::into_bytes)?;
        Ok(Self::from_slice(&items))
    }
}

// Display

impl PrettyDisplay for ScriptBuf {
    const AUTOFMT_ENABLED: bool = true;
    const MAX_ONELINER_LENGTH: usize = 300;
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        fmt_script(f, self, ScriptFmt::Minsc(true), indent)
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum ScriptFmt {
    Minsc(bool), // with or without wrapping backticks
    ScriptWiz,
    BitIde,
}
pub fn fmt_script<W: fmt::Write>(
    f: &mut W,
    script: &Script,
    format: ScriptFmt,
    indent: Option<usize>,
) -> fmt::Result {
    use crate::util::{quote_str as quote, LIST_INDENT_WIDTH as INDENT};
    use bitcoin::opcodes::all::{OP_ELSE, OP_ENDIF, OP_IF, OP_NOTIF};

    let mut indent_w = indent.map_or(0, |n| n * INDENT);
    let mut if_indent_w: usize = 0;

    match format {
        ScriptFmt::Minsc(true) => {
            write!(f, "`")?;
            if indent.is_some() {
                writeln!(f)?;
                indent_w += INDENT;
            }
        }
        ScriptFmt::Minsc(false) => (),
        ScriptFmt::ScriptWiz => {
            writeln!(f, "// ScriptWiz formatted")?;
        }
        ScriptFmt::BitIde => {
            writeln!(f, "// BitIDE formatted")?;
        }
    }

    let mut iter = script
        .iter_with_markers(SCRIPT_MARKER_MAGIC_BYTES)
        .peekable();

    while let Some(item) = iter.next() {
        if let (Ok(MarkerItem::Instruction(Instruction::Op(OP_ELSE | OP_ENDIF))), Some(_)) =
            (&item, indent)
        {
            if_indent_w = if_indent_w.saturating_sub(INDENT);
        }
        write!(f, "{:i$}", "", i = indent_w + if_indent_w)?;

        match item {
            Ok(MarkerItem::Instruction(inst)) => match inst {
                Instruction::PushBytes(push) if push.is_empty() => write!(f, "<0>")?,
                Instruction::PushBytes(push) => write!(f, "<0x{}>", push.as_bytes().as_hex())?,
                Instruction::Op(opcode) => {
                    write!(f, "{}", opcode.pretty(None))?;

                    if let (OP_IF | OP_NOTIF | OP_ELSE, Some(_)) = (opcode, indent) {
                        if_indent_w += INDENT;
                    }
                }
            },
            // Format debug markers encoded within the Script
            Ok(MarkerItem::Marker(Marker { kind, body })) => {
                match (format, kind) {
                    // Minsc formatting, as Minsc code that can re-construct the markers
                    (ScriptFmt::Minsc(_), "label") if is_valid_ident(body) => {
                        write!(f, "@{}", body)?
                    }
                    (ScriptFmt::Minsc(_), "label") => write!(f, "@{{{}}}", quote(body))?,
                    (ScriptFmt::Minsc(_), "comment") => {
                        write!(f, "#{}{}", iif!(indent.is_some(), " ", ""), quote(body))?
                    }
                    (ScriptFmt::Minsc(_), kind) if is_valid_ident(kind) => {
                        if body.is_empty() {
                            write!(f, "@{}()", kind)?
                        } else {
                            write!(f, "@{}({})", kind, quote(body))?
                        }
                    }
                    (ScriptFmt::Minsc(_), kind) => {
                        write!(f, "@({}, {})", quote(kind), quote(body))?
                    }

                    // ScriptWiz formatting
                    // Uses the "$<label>" format to assign a label names to the top stack element
                    (ScriptFmt::ScriptWiz, "label") => write!(f, "${}", encode_label(body))?,

                    // BitIDE formatting
                    // Uses the "#<label>" format for labels
                    (ScriptFmt::BitIde, "label") => write!(f, "#{}", encode_label(body))?,
                    // BitIDE-only features: {NAME} to move the stack element identified by NAME
                    // to the top, or [NAME] to copy it.
                    (ScriptFmt::BitIde, "bitide::copy") => {
                        write!(f, " {{{}}}", encode_label(body))?
                    }
                    (ScriptFmt::BitIde, "bitide::move") => write!(f, "[{}]", encode_label(body))?,

                    // Standard // comment format, ScriptWiz & BitIDE
                    (ScriptFmt::ScriptWiz | ScriptFmt::BitIde, "comment") => {
                        let newline_indent = format!("\n{:i$}// ", "", i = indent_w + if_indent_w);
                        write!(f, "// {}", body.replace('\n', &newline_indent))?
                    }
                    (ScriptFmt::ScriptWiz | ScriptFmt::BitIde, kind) => {
                        write!(f, "// Mark {}: {}", quote(kind), quote(body))?
                    }
                }
            }
            Err(e) => write!(f, "Err(\"{}\")", e)?,
        }
        match format {
            ScriptFmt::Minsc(backticks) => {
                let has_more = iter.peek().is_some();
                if indent.is_none() && has_more {
                    write!(f, " ")?; // add space before the next item
                } else if indent.is_some() && (has_more || backticks) {
                    writeln!(f)?; // add newline before the next item or the closing backtick
                }
            }

            // Always add newlines, these are never rendered as a single line
            ScriptFmt::ScriptWiz | ScriptFmt::BitIde => writeln!(f)?,
        }
    }
    if format == ScriptFmt::Minsc(true) {
        if indent.is_some() {
            write!(f, "{:i$}`", "", i = indent_w - INDENT)?;
        } else {
            write!(f, "`")?;
        }
    }
    Ok(())
}

// ScriptWiz only allows alphanumeric characters and underscores in label names
fn encode_label(input: &str) -> String {
    input
        .chars()
        .map(|c| iif!(c.is_alphanumeric(), c, '_'))
        .collect()
}
fn is_valid_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_')
}
impl PrettyDisplay for Transaction {
    const AUTOFMT_ENABLED: bool = true;
    const MAX_ONELINER_LENGTH: usize = 200;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        let (newline_or_space, inner_indent, indent_w, inner_indent_w) =
            util::indentation_params(indent);
        let field_sep = format!("{newline_or_space}{:inner_indent_w$}", "");
        write!(f, r#"tx [{field_sep}"version": {}"#, self.version.0)?;
        if self.lock_time != AbsLockTime::ZERO {
            write!(
                f,
                ",{field_sep}\"locktime\": {}",
                self.lock_time.pretty(None)
            )?;
        }
        if !self.input.is_empty() {
            write!(f, r#",{field_sep}"inputs": "#)?;
            fmt_list(f, &mut self.input.iter(), inner_indent, |f, input, ind| {
                write!(f, "{}", input.pretty(ind))
            })?;
        }
        if !self.output.is_empty() {
            write!(f, r#",{field_sep}"outputs": "#)?;
            fmt_list(f, self.output.iter(), inner_indent, |f, output, _| {
                // Individual outputs are always displayed as one-liners
                write!(f, "{}", output.pretty(None))
            })?;
        }
        write!(f, "{newline_or_space}{:indent_w$}]", "")
    }

    fn prefer_multiline_anyway(&self) -> bool {
        (self.input.len() + self.output.len()) > 2
    }
}

impl PrettyDisplay for bitcoin::TxIn {
    const AUTOFMT_ENABLED: bool = true;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        if self.sequence == Sequence::default()
            && self.script_sig == ScriptBuf::default()
            && self.witness.is_empty()
        {
            write!(f, "{}", self.previous_output)
        } else {
            let (newline_or_space, _inner_indent, indent_w, inner_indent_w) =
                util::indentation_params(indent);
            let sep = format!("{newline_or_space}{:inner_indent_w$}", "");

            write!(f, "[{sep}\"prevout\": {}", self.previous_output)?;
            if self.sequence != Sequence::default() {
                write!(f, ",{sep}\"sequence\": {}", self.sequence.pretty(None))?;
            }
            if !self.script_sig.is_empty() {
                write!(f, ",{sep}\"script_sig\": {}", self.script_sig.pretty(None))?;
            }
            if !self.witness.is_empty() {
                write!(f, ",{sep}\"witness\": {}", self.witness.pretty(None))?;
            }
            write!(f, "{newline_or_space}{:indent_w$}]", "")
        }
    }

    fn prefer_multiline_anyway(&self) -> bool {
        !self.witness.is_empty() || !self.script_sig.is_empty()
    }
}

impl PrettyDisplay for bitcoin::TxOut {
    const AUTOFMT_ENABLED: bool = false;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        if let Ok(address) = Address::from_script(&self.script_pubkey, Network::Testnet) {
            // XXX always uses the Testnet version bytes
            write!(f, "{}", address)?;
        } else {
            write!(f, "{}", self.script_pubkey.pretty(None))?;
        }
        write!(f, ":{} BTC", self.value.to_btc())
    }
}

impl PrettyDisplay for bitcoin::Witness {
    const AUTOFMT_ENABLED: bool = true;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        fmt_list(f, &mut self.iter(), indent, |f, wit_item: &[u8], _| {
            write!(f, "0x{}", wit_item.as_hex())
        })
    }
}

impl PrettyDisplay for bitcoin::Sequence {
    const AUTOFMT_ENABLED: bool = false;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        if *self == Self::ENABLE_RBF_NO_LOCKTIME {
            write!(f, "ENABLE_RBF")
        } else {
            match self.to_relative_lock_time() {
                None => write!(f, "{:#010x}", self.to_consensus_u32()),
                Some(RelLockTime::Blocks(blocks)) => write!(f, "{blocks} blocks"),
                Some(RelLockTime::Time(time)) => {
                    write!(f, "{} seconds", (time.value() as usize) * 512)
                }
            }
        }
    }
}

impl PrettyDisplay for AbsLockTime {
    const AUTOFMT_ENABLED: bool = false;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        match self {
            AbsLockTime::Blocks(height) => write!(f, "{height}"),
            AbsLockTime::Seconds(timestamp) => {
                write!(f, "{}", time::fmt_timestamp(timestamp.to_consensus_u32()))
            }
        }
    }
}

impl PrettyDisplay for Opcode {
    const AUTOFMT_ENABLED: bool = false;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        use bitcoin::opcodes::{all as ops, Class, ClassifyContext};
        // XXX always uses TapScript as the ClassifyContext
        match (*self, self.classify(ClassifyContext::TapScript)) {
            (_, Class::PushNum(num)) => write!(f, "<{}>", num),
            // special-case for unofficial opcodes
            (ops::OP_NOP4, _) => write!(f, "OP_CHECKTEMPLATEVERIFY"),
            (ops::OP_RETURN_215, _) => write!(f, "OP_ADD64"),
            (ops::OP_RETURN_218, _) => write!(f, "OP_DIV64"),
            (ops::OP_RETURN_227, _) => write!(f, "OP_ECMULSCALARVERIFY"),
            (ops::OP_RETURN_222, _) => write!(f, "OP_GREATERTHAN64"),
            (ops::OP_RETURN_223, _) => write!(f, "OP_GREATERTHANOREQUAL64"),
            (ops::OP_RETURN_200, _) => write!(f, "OP_INSPECTINPUTASSET"),
            (ops::OP_RETURN_204, _) => write!(f, "OP_INSPECTINPUTISSUANCE"),
            (ops::OP_RETURN_199, _) => write!(f, "OP_INSPECTINPUTOUTPOINT"),
            (ops::OP_RETURN_202, _) => write!(f, "OP_INSPECTINPUTSCRIPTPUBKEY"),
            (ops::OP_RETURN_203, _) => write!(f, "OP_INSPECTINPUTSEQUENCE"),
            (ops::OP_RETURN_201, _) => write!(f, "OP_INSPECTINPUTVALUE"),
            (ops::OP_RETURN_211, _) => write!(f, "OP_INSPECTLOCKTIME"),
            (ops::OP_RETURN_212, _) => write!(f, "OP_INSPECTNUMINPUTS"),
            (ops::OP_RETURN_213, _) => write!(f, "OP_INSPECTNUMOUTPUTS"),
            (ops::OP_RETURN_206, _) => write!(f, "OP_INSPECTOUTPUTASSET"),
            (ops::OP_RETURN_208, _) => write!(f, "OP_INSPECTOUTPUTNONCE"),
            (ops::OP_RETURN_209, _) => write!(f, "OP_INSPECTOUTPUTSCRIPTPUBKEY"),
            (ops::OP_RETURN_207, _) => write!(f, "OP_INSPECTOUTPUTVALUE"),
            (ops::OP_RETURN_210, _) => write!(f, "OP_INSPECTVERSION"),
            (ops::OP_RETURN_226, _) => write!(f, "OP_LE32TOLE64"),
            (ops::OP_RETURN_225, _) => write!(f, "OP_LE64TOSCRIPTNUM"),
            (ops::OP_RETURN_220, _) => write!(f, "OP_LESSTHAN64"),
            (ops::OP_RETURN_221, _) => write!(f, "OP_LESSTHANOREQUAL64"),
            (ops::OP_RETURN_217, _) => write!(f, "OP_MUL64"),
            (ops::OP_RETURN_219, _) => write!(f, "OP_NEG64"),
            (ops::OP_RETURN_205, _) => write!(f, "OP_PUSHCURRENTINPUTINDEX"),
            (ops::OP_RETURN_224, _) => write!(f, "OP_SCRIPTNUMTOLE64"),
            (ops::OP_RETURN_198, _) => write!(f, "OP_SHA256FINALIZE"),
            (ops::OP_RETURN_196, _) => write!(f, "OP_SHA256INITIALIZE"),
            (ops::OP_RETURN_197, _) => write!(f, "OP_SHA256UPDATE"),
            (ops::OP_RETURN_216, _) => write!(f, "OP_SUB64"),
            (ops::OP_RETURN_228, _) => write!(f, "OP_TWEAKVERIFY"),
            (ops::OP_RETURN_214, _) => write!(f, "OP_TXWEIGHT"),
            // use full 'OP_CHECKSEQUENCEVERIFY' rather than 'OP_CSV' so that its recognized by scriptwiz
            (ops::OP_CSV, _) => write!(f, "OP_CHECKSEQUENCEVERIFY"),
            (opcode, _) => write!(f, "{}", opcode),
        }
    }
}
