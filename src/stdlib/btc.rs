use std::convert::{TryFrom, TryInto};
use std::fmt;

use bitcoin::hashes::Hash;
use bitcoin::opcodes::{Class, ClassifyContext};
use bitcoin::script::{Builder as ScriptBuilder, Instruction, PushBytesBuf, Script, ScriptBuf};
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use bitcoin::{
    absolute::LockTime as AbsLockTime, address, consensus, hex::DisplayHex,
    relative::LockTime as RelLockTime, script, Address, Amount, Network, Opcode, Sequence,
    SignedAmount, Txid, Witness,
};
use miniscript::psbt::PsbtExt;

use super::script_marker::{Marker, MarkerItem, ScriptMarker};
use crate::display::{fmt_list, indentation_params, PrettyDisplay};
use crate::runtime::{
    eval_exprs, Array, Error, Evaluate, Execute, FieldAccess, Float, Int, Mutable, Result,
    ScopeRef, Value,
};
use crate::util::{DescriptorExt, ScriptBuilderExt, TapInfoExt, EC};
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
        scope
            .set_fn("tx::with_witness", fns::tx_with_witness)
            .unwrap();
        scope.set_fn("script", fns::script).unwrap();
        scope.set_fn("scriptPubKey", fns::scriptPubKey).unwrap();
        scope.set_fn("explicitScript", fns::explicitScript).unwrap();
        scope.set_fn("script::spk", fns::scriptPubKey).unwrap(); // alias
        scope
            .set_fn("script::explicit", fns::explicitScript)
            .unwrap(); // alias
        scope.set_fn("script::strip", fns::script_strip).unwrap();
        scope.set_fn("script::wiz", fns::script_wiz).unwrap();
        scope.set_fn("script::bitide", fns::script_bitide).unwrap();
        scope.set_fn("scriptnum", fns::scriptnum).unwrap();
        scope.set_fn("compactsize", fns::compactsize).unwrap();
        scope.set_fn("varint", fns::compactsize).unwrap(); // alias

        // Script Opcodes
        for op in 0x00..=0xff {
            let script = ScriptBuf::from_bytes(vec![op]);
            scope.set(Opcode::from(op).to_string(), script).unwrap();
        }

        // Constants
        scope.set("BLOCK_INTERVAL", time::BLOCK_INTERVAL).unwrap();
        scope
            .set("SCRIPT_MARKER_MAGIC", SCRIPT_MARKER_MAGIC_BYTES.to_vec())
            .unwrap();
    }

    BTC_STDLIB.exec(scope).unwrap();
}

/// A 'descriptor-like' for raw (non-Miniscript) Script in wsh() (cannot be represented as a miniscript::Descriptor)
#[derive(Clone, Debug, PartialEq)]
pub struct WshScript(pub ScriptBuf);

impl Evaluate for ast::BtcAmount {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let amount_n = self.0.eval(scope)?.into_f64()?;
        Ok(SignedAmount::from_float_in(amount_n, self.1)?.into())
    }
}

impl Evaluate for ast::ScriptFrag {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let frags = eval_exprs(scope, &self.fragments)?;
        Ok(script_frag(Value::array(frags))?.into())
    }
}

fn script_frag(value: Value) -> Result<ScriptBuf> {
    use crate::util::DescriptorPubKeyExt;
    use miniscript::descriptor::{DescriptorPublicKey, SinglePub, SinglePubKey};

    let push_int = |num| ScriptBuilder::new().push_int(num).into_script();
    let push_slice = |slice| -> Result<_> {
        Ok(ScriptBuilder::new()
            .push_slice_minimal(PushBytesBuf::try_from(slice)?)
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
        Value::PubKey(pubkey) => match pubkey {
            // Handle single x-only pubkeys
            DescriptorPublicKey::Single(SinglePub {
                origin: _,
                key: SinglePubKey::XOnly(xonly_pk),
            }) => ScriptBuilder::new().push_x_only_key(&xonly_pk),

            // Xpubs are always encoded as full keys (x-only xpubs cannot be represented as an Xpub/DescriptorPublicKey)
            // To encode them as x-only, use xonly() convert into a single x-only first
            non_xonly => ScriptBuilder::new().push_key(&non_xonly.derive_definite()?),
        }
        .into_script(),

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

pub fn scriptnum_encode(num: i64) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let len = script::write_scriptint(&mut buf, num);
    buf[..len].to_vec()
}
pub fn scriptnum_decode(bytes: &[u8]) -> Result<i64> {
    Ok(script::read_scriptint_non_minimal(bytes)?)
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
    /// `address(Script|Descriptor|PubKey|TapInfo|Address, Network with_network=testnet) -> Address`
    ///
    /// Parse an address, optionally verifying that it matches the given network  
    /// `address(String, verify_network Network=None) -> Address`
    pub fn address(args: Array, _: &ScopeRef) -> Result<Value> {
        let (addr_or_spk, network): (Value, Option<Network>) = args.args_into()?;
        Ok(match addr_or_spk {
            Value::String(address_str) => {
                let address: Address<_> = address_str.parse()?;
                match network {
                    Some(network) => address.require_network(network)?,
                    None => address.assume_checked(),
                }
            }
            spk => {
                let spk = spk.into_spk()?;
                Address::from_script(&spk, network.unwrap_or(Network::Testnet))
                    .map_err(|e| Error::NotAddressable(e, spk.into()))?
            }
        }
        .into())
    }

    /// tx(Bytes|Array<Tagged>|Transaction) -> Transaction
    pub fn tx(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::Transaction(args.arg_into()?))
    }

    /// Get the TXID of the Transaction or PSBT
    ///
    /// For PSBTs the TXID of the unsigned_tx is returned, which is *only safe to
    /// use when all inputs are segwit inputs*.
    ///
    /// `txid(Transaction|Bytes|Array<Tagged>) -> Bytes`
    /// `txid(Psbt) -> Bytes`
    pub fn txid(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Psbt(psbt) => psbt.unsigned_tx.compute_txid(),
            Value::Transaction(tx) => tx.compute_txid(),
            tx_like => Transaction::try_from(tx_like)?.compute_txid(),
        }
        .into())
    }

    /// Attach input witnesses, returning a new modified Transaction with them
    ///
    /// Can provide an array of all input witnesses, or an array mapping from
    /// specific input indexes to their witness.
    ///
    /// `tx::with_witness(Transaction, Array<Witness>) -> Transaction`
    /// `tx::with_witness(Transaction, Array<Int:Witness>) -> Transaction`
    pub fn tx_with_witness(args: Array, _: &ScopeRef) -> Result<Value> {
        let (mut tx, witnesses): (Transaction, Array) = args.args_into()?;
        for (vin, witness) in witnesses.mapped_or_all(tx.input.len())? {
            tx.input
                .get_mut(vin)
                .ok_or(Error::TxInputNotFound(vin))?
                .witness = witness;
        }
        Ok(Value::Transaction(tx))
    }

    /// script(Bytes|Script) -> Script
    pub fn script(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::Script(args.arg_into()?))
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

    /// explicitScript(Descriptor|WshScript) -> Script
    /// Get the underlying Script before any hashing is done - AKA the witnessScript for Wsh,
    /// scriptPubKey for Wpkh, or the redeemScript for ShWpkh. Tr descriptors don't have an explicitScript.
    /// To get the scriptPubKey of descriptors, use scriptPubKey().
    pub fn explicitScript(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Descriptor(desc) => desc.to_explicit_script()?,
            Value::WshScript(wsh) => wsh.0,
            other => bail!(Error::InvalidValue(other.into())),
        }
        .into())
    }

    /// compactsize(Number) -> Bytes
    /// Aliased as varint()
    pub fn compactsize(args: Array, _: &ScopeRef) -> Result<Value> {
        let varint = bitcoin::VarInt(args.arg_into()?);
        Ok(consensus::serialize(&varint).into())
    }

    /// scriptnum(Number) -> Bytes
    pub fn scriptnum(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(scriptnum_encode(args.arg_into()?).into())
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
            // Descriptors/Addresses/WshScript are converted into their scriptPubKey
            Value::Descriptor(descriptor) => descriptor.to_script_pubkey()?,
            Value::Address(address) => address.script_pubkey(),
            Value::WshScript(wsh) => wsh.0.to_p2wsh(),
            // TapInfo returns the V1 witness program of the output key
            Value::TapInfo(tapinfo) => tapinfo.script_pubkey(),
            other => bail!(Error::NoSpkRepr(other.into())),
        })
    }
    pub fn is_script(&self) -> bool {
        matches!(self, Value::Script(_))
    }
    pub fn into_script(self) -> Result<ScriptBuf> {
        self.try_into()
    }
}

// Convert from Value to Bitcoin types

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

impl TryFrom<Value> for ScriptBuf {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val {
            Value::Script(script) => script,
            Value::Bytes(bytes) => bytes.into(),
            other => bail!(Error::NotScriptLike(other.into())),
        })
    }
}

impl TryFrom<Value> for Transaction {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Transaction(tx) => tx,
            Value::Bytes(bytes) => consensus::deserialize(&bytes)?,
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
                // impl_simple_to_value!(Txid) (below) does the opposite
                bytes.reverse();
                Txid::from_slice(&bytes)?
            }
            Value::Transaction(tx) => tx.compute_txid(),
            // The psbt unsigned_tx's txid is useless if there are any non-segwit inputs. Use with care. Should probably check :>
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
impl TryFrom<Value> for Witness {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(val.map_array(Value::into_bytes)?.into())
    }
}

// Convert from Bitcoin types to Value

impl_simple_to_value!(Version, ver, ver.0);
impl_simple_to_value!(Sequence, seq, seq.to_consensus_u32());
impl_simple_to_value!(AbsLockTime, time, time.to_consensus_u32());
impl_simple_to_value!(Witness, wit, wit.to_vec());
impl_simple_to_value!(bitcoin::WitnessVersion, ver, ver.to_num() as i64);
impl_simple_to_value!(bitcoin::AddressType, t, t.to_string());
impl_simple_to_value!(bitcoin::WitnessProgram, w, (w.version(), w.program()));
impl_simple_to_value!(&script::PushBytes, p, p.as_bytes().to_vec());
impl_simple_to_value!(Opcode, op, ScriptBuf::from_bytes(vec![op.to_u8()]));
impl_simple_to_value!(SignedAmount, amt, amt.to_sat());
// Panics for out-of-range `Amount`s (i64 can represent up to ~92 billion BTC, ~4400x more than can exists),
// which should be impossible to construct within Minsc (but can be passed from Rust code).
// Uses to_signed() to convert from u64 to i64 with a useful OutOfRangeError message.
impl_simple_to_value!(Amount, amt, amt.to_signed().unwrap());


#[rustfmt::skip]
impl_simple_to_value!(OutPoint, outpoint, (
    ("txid", outpoint.txid),
    ("vout", outpoint.vout),
));

#[rustfmt::skip]
impl_simple_to_value!(bitcoin::transaction::TxOut, txout, (
    ("script_pubkey", txout.script_pubkey),
    ("amount", txout.value),
));

#[rustfmt::skip]
impl_simple_to_value!(bitcoin::transaction::TxIn, txin, (
    ("prevout", txin.previous_output),
    ("sequence", txin.sequence),
    ("witness", txin.witness),
    ("script_sig", txin.script_sig),
));

impl_simple_to_value!(Txid, txid, {
    let mut txid = txid.to_byte_array().to_vec();
    // Reverse when converted to Bytes to match the standard display order,
    // reversed back in `TryFrom<Value> for Txid`. FIXME find a better way to handle this
    txid.reverse();
    txid
});
impl_simple_to_value!(bitcoin::Wtxid, wtxid, {
    let mut wtxid = wtxid.to_byte_array().to_vec();
    wtxid.reverse();
    wtxid
});
// Panics for out-of-range `Weight`s, which should be impossible to construct
impl_simple_to_value!(
    bitcoin::Weight,
    w,
    i64::try_from(w.to_wu()).expect("out of range weight")
);
#[rustfmt::skip]
impl_simple_to_value!(script::Instructions<'_>, insts, insts
    .map(|inst| match inst {
        Err(err) => err.to_string().into(),
        // XXX always uses TapScript
        Ok(Instruction::Op(op)) => match op.classify(ClassifyContext::TapScript) {
            Class::PushNum(num) => num.into(),
            _ => op.into(),
        },
        Ok(Instruction::PushBytes(push)) if push.is_empty() => 0.into(),
        Ok(Instruction::PushBytes(push)) => push.into(),
    })
    .collect::<Vec<Value>>()
    // Returns an array of opcodes (as Script), 0-16 number pushes (as Int), data pushes (as Bytes), and errors (as String)
);

// Field accessors

impl FieldAccess for Transaction {
    fn get_field(self, field: &Value) -> Option<Value> {
        Some(match field.as_str()? {
            "version" => self.version.into(),
            "locktime" => self.lock_time.into(),
            "input" | "inputs" => self.input.into(),
            "output" | "outputs" => self.output.into(),

            "txid" => self.compute_txid().into(),
            "wtxid" => self.compute_wtxid().into(),
            "weight" => self.weight().into(),
            "vsize" => self.vsize().into(),
            "size" => self.total_size().into(),
            _ => {
                return None;
            }
        })
    }
}

impl FieldAccess for Address {
    fn get_field(self, field: &Value) -> Option<Value> {
        Some(match field.as_str()? {
            "script_pubkey" => self.script_pubkey().into(),
            "address_type" => self.address_type()?.into(),
            "witness_program" => self.witness_program()?.into(),
            "qr_uri" => self.to_qr_uri().into(),
            _ => {
                return None;
            }
        })
    }
}

impl FieldAccess for ScriptBuf {
    fn get_field(self, field: &Value) -> Option<Value> {
        Some(match field.as_str()? {
            // Returns an array of opcodes (as Script), 0-16 number pushes (as Int), data pushes (as Bytes), and errors (as String)
            // TODO script marker support
            "instructions" => self.instructions().into(),
            "instructions_minimal" => self.instructions_minimal().into(),

            "is_multisig" => self.is_multisig().into(),
            "is_op_return" => self.is_op_return().into(),
            "is_p2pk" => self.is_p2pk().into(),
            "is_p2pkh" => self.is_p2pkh().into(),
            "is_p2sh" => self.is_p2pkh().into(),
            "is_p2tr" => self.is_p2tr().into(),
            "is_p2wpkh" => self.is_p2wpkh().into(),
            "is_p2wsh" => self.is_p2wsh().into(),
            "is_push_only" => self.is_push_only().into(),
            "is_witness_program" => self.is_witness_program().into(),

            "dust_value" | "minimal_non_dust" => self.minimal_non_dust().into(),
            "count_sigops" => self.count_sigops().into(),
            "count_sigops_legacy" => self.count_sigops_legacy().into(),

            "witness_version" => self.witness_version()?.into(),
            _ => {
                return None;
            }
        })
    }
}

impl FieldAccess for WshScript {
    fn get_field(self, field: &Value) -> Option<Value> {
        Some(match field.as_str()? {
            "script_pubkey" => self.script_pubkey().into(),
            "explicit_script" => self.0.into(),
            "address_type" => bitcoin::AddressType::P2wsh.into(),
            "witness_program" => bitcoin::WitnessProgram::p2wsh(&self.0).into(),
            "is_definite" => true.into(), // Always definite
            _ => {
                return None;
            }
        })
    }
}

impl WshScript {
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.0.to_p2wsh()
    }
    pub fn explicit_script(&self) -> ScriptBuf {
        self.0.clone()
    }
    pub fn explicit_script_ref(&self) -> &Script {
        self.0.as_script()
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
    use crate::display::{quote_str as quote, INDENT_WIDTH as INDENT};
    use bitcoin::opcodes::all::{OP_ELSE, OP_ENDIF, OP_IF, OP_NOTIF};

    // Encode single-opcode scripts as just the opcode name, without parsing it as scripts instructions
    // (which would fail with 'unexpected end of script' for PUSHBYTE opcodes with no trailing bytes).
    // This also avoids the `` wrappers, which are unnecessary (all opcodes are available as vars).
    if script.len() == 1 {
        let opcode = script.first_opcode().expect("checked size");
        return write!(f, "{}", opcode.pretty(None));
    }

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
            writeln!(f, "// ScriptWiz formatted\n")?;
        }
        ScriptFmt::BitIde => {
            writeln!(f, "// BitIDE formatted\n")?;
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
                // XXX always uses TapScript as the ClassifyContext
                Instruction::Op(opcode) => match opcode.classify(ClassifyContext::TapScript) {
                    Class::PushNum(num) => write!(f, "<{}>", num)?,
                    _ => {
                        write!(f, "{}", opcode.pretty(None))?;

                        if let (OP_IF | OP_NOTIF | OP_ELSE, Some(_)) = (opcode, indent) {
                            if_indent_w += INDENT;
                        }
                    }
                },
            },
            // Format debug markers encoded within the Script
            Ok(MarkerItem::Marker(Marker { kind, body })) => {
                match (format, kind) {
                    // Minsc formatting, as Minsc code that can re-construct the markers
                    (ScriptFmt::Minsc(_), "label") if is_valid_ident(body) => {
                        write!(f, "@{}", body)?
                    }
                    (ScriptFmt::Minsc(_), "label") => write!(f, "@({})", quote(body))?,
                    (ScriptFmt::Minsc(_), "comment") => {
                        if indent.is_none() {
                            write!(f, "#{}", quote(body))?;
                        } else if !body.contains('\n') {
                            write!(f, "# {}", quote(body))?;
                        } else {
                            let mut lines = body.split_inclusive('\n');
                            write!(f, "#({}", quote(lines.next().unwrap()))?;
                            for line in lines {
                                write!(f, " +\n{:i$}{}", "", quote(line), i = indent_w + 2)?;
                            }
                            write!(f, ")")?;
                        }
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
                    (ScriptFmt::BitIde, "bitide::copy") => write!(f, "{{{}}}", encode_label(body))?,
                    (ScriptFmt::BitIde, "bitide::move") => write!(f, "[{}]", encode_label(body))?,

                    // Standard // comment format, ScriptWiz & BitIDE
                    (ScriptFmt::ScriptWiz | ScriptFmt::BitIde, "comment") => {
                        let newline_sep = format!("\n{:i$}// ", "", i = indent_w + if_indent_w);
                        write!(f, "// {}", body.replace('\n', &newline_sep))?
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
    // TODO allow idents with ::
    !s.is_empty()
        && s.chars().enumerate().all(|(idx, c)| {
            (if idx == 0 {
                c.is_ascii_alphabetic()
            } else {
                c.is_ascii_alphanumeric()
            }) || matches!(c, '_' | '$')
        })
}
impl PrettyDisplay for Transaction {
    const AUTOFMT_ENABLED: bool = true;
    const MAX_ONELINER_LENGTH: usize = 180;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        let (newline_or_space, inner_indent, indent_w, inner_indent_w) = indentation_params(indent);
        let field_sep = format!("{newline_or_space}{:inner_indent_w$}", "");
        write!(f, r#"tx[{field_sep}"version": {}"#, self.version.0)?;
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
                indentation_params(indent);
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
        match Address::from_script(&self.script_pubkey, Network::Testnet) {
            // XXX always uses the Testnet version bytes
            Ok(address) if address.address_type().is_some() => write!(f, "{}", address)?,
            _ => write!(f, "{}", self.script_pubkey.pretty(None))?,
        }
        write!(f, ":{} BTC", self.value.to_btc())
    }
}

impl PrettyDisplay for Address {
    const AUTOFMT_ENABLED: bool = false;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        if self.address_type().is_some() {
            // Use the base58/bech32 encoded string if its a standard address type (known witness program/length),
            write!(f, "{}", self)
        } else {
            // Otherwise, encode as a `address(scriptPubKey)` call
            write!(f, "address({})", self.script_pubkey().pretty(None))
        }
    }
}

impl PrettyDisplay for Witness {
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

impl PrettyDisplay for WshScript {
    const AUTOFMT_ENABLED: bool = false;
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        write!(f, "wsh({})", self.0.pretty(indent))
    }
}

impl PrettyDisplay for Opcode {
    const AUTOFMT_ENABLED: bool = false;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        use bitcoin::opcodes::all as ops;
        match *self {
            // special-case for unofficial opcodes
            ops::OP_NOP4 => write!(f, "OP_CHECKTEMPLATEVERIFY"),
            // Elements opcodes
            ops::OP_RETURN_215 => write!(f, "OP_ADD64"),
            ops::OP_RETURN_218 => write!(f, "OP_DIV64"),
            ops::OP_RETURN_227 => write!(f, "OP_ECMULSCALARVERIFY"),
            ops::OP_RETURN_222 => write!(f, "OP_GREATERTHAN64"),
            ops::OP_RETURN_223 => write!(f, "OP_GREATERTHANOREQUAL64"),
            ops::OP_RETURN_200 => write!(f, "OP_INSPECTINPUTASSET"),
            ops::OP_RETURN_204 => write!(f, "OP_INSPECTINPUTISSUANCE"),
            ops::OP_RETURN_199 => write!(f, "OP_INSPECTINPUTOUTPOINT"),
            ops::OP_RETURN_202 => write!(f, "OP_INSPECTINPUTSCRIPTPUBKEY"),
            ops::OP_RETURN_203 => write!(f, "OP_INSPECTINPUTSEQUENCE"),
            ops::OP_RETURN_201 => write!(f, "OP_INSPECTINPUTVALUE"),
            ops::OP_RETURN_211 => write!(f, "OP_INSPECTLOCKTIME"),
            ops::OP_RETURN_212 => write!(f, "OP_INSPECTNUMINPUTS"),
            ops::OP_RETURN_213 => write!(f, "OP_INSPECTNUMOUTPUTS"),
            ops::OP_RETURN_206 => write!(f, "OP_INSPECTOUTPUTASSET"),
            ops::OP_RETURN_208 => write!(f, "OP_INSPECTOUTPUTNONCE"),
            ops::OP_RETURN_209 => write!(f, "OP_INSPECTOUTPUTSCRIPTPUBKEY"),
            ops::OP_RETURN_207 => write!(f, "OP_INSPECTOUTPUTVALUE"),
            ops::OP_RETURN_210 => write!(f, "OP_INSPECTVERSION"),
            ops::OP_RETURN_226 => write!(f, "OP_LE32TOLE64"),
            ops::OP_RETURN_225 => write!(f, "OP_LE64TOSCRIPTNUM"),
            ops::OP_RETURN_220 => write!(f, "OP_LESSTHAN64"),
            ops::OP_RETURN_221 => write!(f, "OP_LESSTHANOREQUAL64"),
            ops::OP_RETURN_217 => write!(f, "OP_MUL64"),
            ops::OP_RETURN_219 => write!(f, "OP_NEG64"),
            ops::OP_RETURN_205 => write!(f, "OP_PUSHCURRENTINPUTINDEX"),
            ops::OP_RETURN_224 => write!(f, "OP_SCRIPTNUMTOLE64"),
            ops::OP_RETURN_198 => write!(f, "OP_SHA256FINALIZE"),
            ops::OP_RETURN_196 => write!(f, "OP_SHA256INITIALIZE"),
            ops::OP_RETURN_197 => write!(f, "OP_SHA256UPDATE"),
            ops::OP_RETURN_216 => write!(f, "OP_SUB64"),
            ops::OP_RETURN_228 => write!(f, "OP_TWEAKVERIFY"),
            ops::OP_RETURN_214 => write!(f, "OP_TXWEIGHT"),
            // use full 'OP_CHECKSEQUENCEVERIFY' rather than 'OP_CSV' so that its recognized by scriptwiz
            ops::OP_CSV => write!(f, "OP_CHECKSEQUENCEVERIFY"),
            // use 'OP_0' for improved readability
            ops::OP_PUSHBYTES_0 => write!(f, "OP_0"),
            opcode => write!(f, "{}", opcode),
        }
    }
}
