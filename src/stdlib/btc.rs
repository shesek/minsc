use std::convert::{TryFrom, TryInto};
use std::fmt;

use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::script::{Builder as ScriptBuilder, Instruction, PushBytesBuf, Script, ScriptBuf};
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use miniscript::bitcoin::{
    self, absolute::LockTime, address, hex::DisplayHex, taproot::TaprootSpendInfo, Address, Amount,
    Network, Opcode, Sequence, SignedAmount, Txid, WitnessProgram, WitnessVersion,
};

use super::script_marker::{Marker, MarkerItem, ScriptMarker};
use crate::runtime::{
    eval_exprs, Array, Error, Evaluate, Float, Int, Result, Scope, Symbol, Value,
};
use crate::util::{self, fmt_list, DeriveExt, DescriptorExt, PrettyDisplay, EC};
use crate::{ast, time};

// XXX should this be randomized? is there a way this could be abused when viewing untrusted scripts?
const SCRIPT_MARKER_MAGIC_BYTES: &[u8] = "SCRIPT MARKER MAGIC BYTES".as_bytes();

pub fn attach_stdlib(scope: &mut Scope) {
    // Network types
    scope.set("signet", Network::Signet).unwrap();
    scope.set("testnet", Network::Testnet).unwrap();
    scope.set("regtest", Network::Regtest).unwrap();
    scope
        .set("_$$_RECKLESSLY_RISK_MY_BITCOINS_$$_", Network::Bitcoin)
        .unwrap();

    // Functions
    scope.set_fn("address", fns::address).unwrap();
    scope.set_fn("transaction", fns::transaction).unwrap();
    scope.set_fn("script", fns::script).unwrap();
    scope.set_fn("scriptPubKey", fns::scriptPubKey).unwrap();
    scope.set_fn("script::strip", fns::scriptStrip).unwrap();
    scope.set_fn("script::wiz", fns::scriptWiz).unwrap();

    scope
        .set("SCRIPT_MARKER_MAGIC", SCRIPT_MARKER_MAGIC_BYTES.to_vec())
        .unwrap();
}

impl Evaluate for ast::BtcAmount {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let amount_n = self.0.eval(scope)?.into_f64()?;
        let amount = SignedAmount::from_float_in(amount_n, self.1)?;
        Ok(Value::from(amount.to_sat()))
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
    let bytes_n: Vec<u8> = (0..times).map(|_| bytes.clone()).flatten().collect();
    ScriptBuf::from(bytes_n)
}

impl Evaluate for ast::ChildDerive {
    fn eval(&self, scope: &Scope) -> Result<Value> {
        let mut node = self.parent.eval(scope)?;

        // Temporary fix to make number division work. Should be refactored to make
        // ChildDerive work as another InfixOp.
        if node.is_number() {
            ensure!(!self.is_wildcard, Error::InvalidArguments);
            let mut result = node.into_number()?;
            for num in &self.path {
                result = match (result, num.eval(&scope)?.into_number()?) {
                    (Int(a), Int(b)) => Int(a.checked_div(b).ok_or(Error::Overflow)?),
                    (Float(a), Float(b)) => Float(a / b),
                    (a, b) => bail!(Error::InfixOpMixedNum(
                        Box::new(a.into()),
                        Box::new(b.into())
                    )),
                };
            }
            return Ok(Value::Number(result));
        }

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
        if self.path.is_empty() {
            // If there was no path, derive once with an empty path so that is_wildcard is set.
            node = node.derive_path(&[][..], self.is_wildcard)?;
        }
        Ok(node)
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

#[allow(non_snake_case)]
pub mod fns {
    use super::*;

    /// Generate an address
    /// address(Script|Descriptor|PubKey|TapInfo|String|Address, Network=Signet) -> Address
    pub fn address(args: Array, _: &Scope) -> Result<Value> {
        let (spk, network): (Value, Option<Network>) = args.args_into()?;
        let spk = spk.into_spk()?;
        let network = network.unwrap_or(Network::Signet);

        Ok(Address::from_script(&spk, network)
            .map_err(|_| Error::NotAddressable(spk.into()))?
            .into())
    }

    /// script(Bytes|Address) -> Script
    pub fn script(args: Array, _: &Scope) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Script(script) => script.into(),
            Value::Bytes(bytes) => ScriptBuf::from(bytes).into(),
            other => bail!(Error::InvalidScriptConstructor(other.into())),
        })
    }

    /// transaction(Bytes|TaggedArray|Transaction) -> Transaction
    pub fn transaction(args: Array, _: &Scope) -> Result<Value> {
        let tx: Transaction = args.arg_into()?;
        Ok(tx.into())
    }

    /// scriptPubKey(Descriptor|TapInfo|PubKey|Address|Script) -> Script
    ///
    /// Descriptors are compiled into their scriptPubKey
    /// TapInfo are returned as their V1 witness program
    /// PubKeys are converted into a wpkh() scripts
    /// Scripts are returned as-is
    pub fn scriptPubKey(args: Array, _: &Scope) -> Result<Value> {
        let spk = args.arg_into::<Value>()?.into_spk()?;
        Ok(spk.into())
    }

    /// script::strip(Script) -> Script
    /// Strip debug markers from the given Script
    pub fn scriptStrip(args: Array, _: &Scope) -> Result<Value> {
        Ok(args
            .arg_into::<ScriptBuf>()?
            .strip_markers(SCRIPT_MARKER_MAGIC_BYTES)?
            .into())
    }

    /// script::wiz(Script) -> Symbol
    /// Encode the Script in a Scriptwiz-Compatible format (newlines, stack labels & comments)
    pub fn scriptWiz(args: Array, _: &Scope) -> Result<Value> {
        let script = args.arg_into::<ScriptBuf>()?;
        let mut wiz_str = String::new();
        fmt_script(&mut wiz_str, &script, ScriptFmt::ScriptWiz, None)?;
        // Uses Symbol for the same reason described in `stdlib::fns::debug()`
        Ok(Symbol::new(Some(wiz_str)).into())
    }
}

impl Value {
    /// Get the scriptPubKey representation of this Value
    pub fn into_spk(self) -> Result<ScriptBuf> {
        Ok(match self {
            // Raw scripts are returned as-is
            Value::Script(script) => script,
            // Descriptors (or values coercible into them) are converted into their scriptPubKey
            Value::Descriptor(_) | Value::PubKey(_) => self.into_desc()?.to_script_pubkey()?,
            // TapInfo returns the output V1 witness program of the output key
            Value::TapInfo(tapinfo) => ScriptBuf::new_witness_program(&WitnessProgram::new(
                WitnessVersion::V1,
                &tapinfo.output_key().serialize(),
            )?),
            // Addresses can be provided as an Address or String
            Value::Address(_) | Value::String(_) => self.into_address()?.script_pubkey(),
            other => bail!(Error::NoSpkRepr(other.into())),
        })
    }
    pub fn into_address(self) -> Result<Address> {
        self.try_into()
    }
    pub fn into_tapinfo(self) -> Result<TaprootSpendInfo> {
        self.try_into()
    }
    pub fn into_tx(self) -> Result<Transaction> {
        self.try_into()
    }
    pub fn is_script(&self) -> bool {
        matches!(self, Value::Script(_))
    }
}

// Convert from Value to Bitcoin types

impl TryFrom<Value> for TaprootSpendInfo {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::TapInfo(tapinfo) => tapinfo,
            Value::Descriptor(desc) => match desc.at_derivation_index(0)? {
                miniscript::Descriptor::Tr(tr_desc) => (*tr_desc.spend_info()).clone(),
                _ => bail!(Error::NotTapInfoLike(Value::Descriptor(desc).into())),
            },
            v => bail!(Error::NotTapInfoLike(v.into())),
        })
    }
}
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

            // From tagged [ "version": $version, "locktime": $locktime, "inputs": [ .. ], "outputs": [ .. ] ]
            Value::Array(_) => {
                let mut tx = Transaction {
                    version: Version(2),
                    lock_time: LockTime::ZERO,
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
        // Bitcoin's txid bytes needs to be reversed to match how they're commonly presented
        // XXX Could this result in the wrong behavior?
        let mut bytes = val.into_bytes()?;
        bytes.reverse();
        Ok(Txid::from_raw_hash(sha256d::Hash::from_slice(&bytes)?))
    }
}
impl TryFrom<Value> for Amount {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Amount::from_sat(val.into_u64()?))
    }
}
impl TryFrom<Value> for LockTime {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(LockTime::from_consensus(val.into_u32()?))
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
            Value::Bytes(bytes) => u32::from_le_bytes(bytes.as_slice().try_into()?),
            Value::Number(num) => num.into_u32()?,
            other => bail!(Error::InvalidValue(other.into())),
        }))
    }
}
impl TryFrom<Value> for bitcoin::Witness {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        let items = val.map_array(Value::into_bytes)?;
        Ok(bitcoin::Witness::from_slice(&items))
    }
}

impl PrettyDisplay for ScriptBuf {
    const SUPPORTS_MULTILINE: bool = false;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        fmt_script(f, self, ScriptFmt::Minsc, indent)
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum ScriptFmt {
    Minsc,
    ScriptWiz,
}
fn fmt_script<W: fmt::Write>(
    f: &mut W,
    script: &Script,
    format: ScriptFmt,
    indent: Option<usize>,
) -> fmt::Result {
    use crate::util::quote_str;

    match format {
        ScriptFmt::Minsc => write!(f, "`")?,
        ScriptFmt::ScriptWiz => write!(f, "\n")?,
    }
    let inner_indent_w = indent.map_or(0, |n| (n + 1) * 2);

    let mut iter = script
        .iter_with_markers(SCRIPT_MARKER_MAGIC_BYTES)
        .peekable();

    while let Some(item) = iter.next() {
        if format == ScriptFmt::ScriptWiz {
            write!(f, "{:i$}", "", i = inner_indent_w)?;
        }
        match item {
            Ok(item) => match item {
                MarkerItem::Instruction(inst) => match inst {
                    Instruction::PushBytes(push) if push.is_empty() => write!(f, "<0>")?,
                    Instruction::PushBytes(push) => write!(f, "<0x{}>", push.as_bytes().as_hex())?,
                    Instruction::Op(opcode) => write!(f, "{}", opcode.pretty(None))?,
                },
                // Format debug markers encoded within the Script
                MarkerItem::Marker(Marker { kind, body }) => match (format, kind) {
                    // Minsc formatting, as Minsc code that can re-construct the markers
                    (ScriptFmt::Minsc, "label") => write!(f, "mark::l({})", quote_str(body))?,
                    (ScriptFmt::Minsc, "comment") => write!(f, "mark::c({})", quote_str(body))?,
                    (ScriptFmt::Minsc, "breakpoint") => {
                        write!(f, "breakpoint({})", quote_str(body))?
                    }
                    (ScriptFmt::Minsc, kind) => {
                        write!(f, "mark({}, {})", quote_str(kind), quote_str(body))?
                    }

                    // ScriptWiz formatting
                    // The "$<label>" format is used by ScriptWiz to assign a label name to the top stack element
                    (ScriptFmt::ScriptWiz, "label") => write!(f, "${}", scriptwiz_label(body))?,
                    (ScriptFmt::ScriptWiz, "comment") => {
                        write!(f, "// {}", body.replace("\n", "\n// "))?
                    }
                    (ScriptFmt::ScriptWiz, kind) => {
                        write!(f, "// {} mark: {}", quote_str(kind), quote_str(body))?
                    }
                },
            },
            Err(e) => write!(f, "Err(\"{}\")", e)?,
        }
        match format {
            ScriptFmt::Minsc if iter.peek().is_some() => write!(f, " ")?,
            // ScriptWiz requires newlines between opcodes. Include one at the end too.
            ScriptFmt::ScriptWiz => write!(f, "\n")?,
            _ => (),
        }
    }
    if format == ScriptFmt::Minsc {
        write!(f, "`")?;
    }
    Ok(())
}

// ScriptWiz only allows alphanumeric characters and underscores in label names
fn scriptwiz_label(input: &str) -> String {
    input
        .chars()
        .map(|c| iif!(c.is_alphanumeric(), c, '_'))
        .collect()
}
impl PrettyDisplay for Transaction {
    const SUPPORTS_MULTILINE: bool = true;
    const MAX_ONELINER_LENGTH: usize = 200;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        let (newline_or_space, inner_indent, indent_w, inner_indent_w) =
            util::indentation_params(indent);
        let field_sep = format!("{newline_or_space}{:inner_indent_w$}", "");
        write!(f, r#"tx([{field_sep}"version": {}"#, self.version.0)?;
        if self.lock_time != LockTime::ZERO {
            write!(f, r#",{field_sep}"locktime": {}"#, self.lock_time)?;
        }
        if !self.input.is_empty() {
            write!(f, r#",{field_sep}"inputs": "#)?;
            fmt_list(f, &mut self.input.iter(), inner_indent, |f, input, _| {
                // Individual inputs are always displayed as one-liners
                if input.sequence == Sequence::default()
                    && input.script_sig == ScriptBuf::default()
                    && input.witness.is_empty()
                {
                    write!(f, "{}", input.previous_output)
                } else {
                    write!(f, r#"[ "prevout": {}"#, input.previous_output)?;
                    if input.sequence != Sequence::default() {
                        write!(f, r#", "sequence": {}"#, input.sequence)?;
                    }
                    if input.script_sig != ScriptBuf::default() {
                        write!(f, r#", "script_sig": {}"#, &input.script_sig.pretty(None))?;
                    }
                    if !input.witness.is_empty() {
                        write!(f, r#", "witness": {}"#, input.witness.pretty(None))?;
                    }
                    write!(f, r#" ]"#)
                }
            })?;
        }
        if !self.output.is_empty() {
            write!(f, r#",{field_sep}"outputs": "#)?;
            fmt_list(
                f,
                self.output.iter(),
                inner_indent,
                |f, output, _inner_indent| {
                    // Individual outputs are always displayed as one-liners
                    if let Ok(address) =
                        Address::from_script(&output.script_pubkey, Network::Signet)
                    {
                        // XXX always uses the Signet version bytes
                        write!(f, "{}", address)?;
                    } else {
                        write!(f, "{}", output.script_pubkey.pretty(None))?;
                    }
                    write!(f, r#": {} BTC"#, output.value.to_btc())
                },
            )?;
        }
        write!(f, "{newline_or_space}{:indent_w$}])", "")
    }

    fn should_prefer_multiline(&self) -> bool {
        (self.input.len() + self.output.len()) > 2
    }
}

impl PrettyDisplay for bitcoin::Witness {
    const SUPPORTS_MULTILINE: bool = true;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        fmt_list(f, &mut self.iter(), indent, |f, wit_item: &[u8], _| {
            write!(f, "0x{}", wit_item.as_hex())
        })
    }
}

impl PrettyDisplay for Opcode {
    const SUPPORTS_MULTILINE: bool = false;

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
            (opcode, _) => write!(f, "{:}", opcode),
        }
    }
}
