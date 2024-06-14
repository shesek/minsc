use std::convert::{TryFrom, TryInto};
use std::fmt;

use bitcoin::bip32::{self, ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::key::{PublicKey, TweakedPublicKey, XOnlyPublicKey};
use bitcoin::script::{Builder as ScriptBuilder, Instruction, PushBytesBuf, Script, ScriptBuf};
use bitcoin::secp256k1::rand::{thread_rng, Rng};
use bitcoin::transaction::{OutPoint, Transaction, TxIn, TxOut, Version};
use bitcoin::{
    absolute::LockTime, address, hex::DisplayHex, secp256k1, Address, Amount, Network, Opcode,
    Sequence, SignedAmount, Txid, WitnessProgram, WitnessVersion,
};
use miniscript::descriptor::{
    self, Descriptor, DescriptorPublicKey, DescriptorSecretKey, DescriptorXKey, SinglePriv,
    SinglePub, SinglePubKey,
};
use miniscript::psbt::PsbtExt;

use super::script_marker::{Marker, MarkerItem, ScriptMarker};
use crate::runtime::scope::{Mutable, ScopeRef};
use crate::runtime::{eval_exprs, Array, Error, Evaluate, Float, Int, Result, Symbol, Value};
use crate::util::{self, fmt_list, DeriveExt, DescriptorExt, PrettyDisplay, EC};
use crate::{ast, time};

// XXX should this be randomized? is there a way this could be abused when viewing untrusted scripts?
const SCRIPT_MARKER_MAGIC_BYTES: &[u8] = "SCRIPT MARKER MAGIC BYTES".as_bytes();

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
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
    scope.set_fn("transaction", fns::transaction).unwrap();
    scope.set_fn("script", fns::script).unwrap();
    scope.set_fn("pubkey", fns::pubkey).unwrap();

    scope.set_fn("seckey", fns::seckey).unwrap();
    scope.set_fn("genkey", fns::genkey).unwrap();
    scope.set_fn("sign::ecdsa", fns::signEcdsa).unwrap();
    scope.set_fn("sign::schnorr", fns::signSchnorr).unwrap();
    scope.set_fn("verify::ecdsa", fns::verifyEcdsa).unwrap();
    scope.set_fn("verify::schnorr", fns::verifySchnorr).unwrap();

    scope.set_fn("scriptPubKey", fns::scriptPubKey).unwrap();
    scope.set_fn("script::strip", fns::scriptStrip).unwrap();
    scope.set_fn("script::wiz", fns::scriptWiz).unwrap();
    scope.set_fn("script::bitide", fns::scriptBitIde).unwrap();

    // Constants
    scope
        .set("SCRIPT_MARKER_MAGIC", SCRIPT_MARKER_MAGIC_BYTES.to_vec())
        .unwrap();
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
    let bytes_n: Vec<u8> = (0..times).map(|_| bytes.clone()).flatten().collect();
    ScriptBuf::from(bytes_n)
}

impl Evaluate for ast::ChildDerive {
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let mut node = self.parent.eval(scope)?;

        // Temporary fix to make number division work. Should be refactored to make
        // ChildDerive work as another InfixOp.
        if node.is_number() {
            ensure!(!self.is_wildcard, Error::InvalidArguments);
            let mut result = node.into_number()?;
            for num in &self.path {
                result = match (result, num.eval(scope)?.into_number()?) {
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
    fn eval(&self, scope: &ScopeRef) -> Result<Value> {
        let seq_num = match self {
            ast::Duration::BlockHeight(num_blocks) => {
                let num_blocks = num_blocks.eval(scope)?.into_u32()?;
                time::relative_height_to_seq(num_blocks)?
            }
            ast::Duration::BlockTime { parts, heightwise } => {
                let block_interval = scope.borrow().builtin("BLOCK_INTERVAL").into_u32()?;

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
    pub fn address(args: Array, _: &ScopeRef) -> Result<Value> {
        let (spk, network): (Value, Option<Network>) = args.args_into()?;
        let spk = spk.into_spk()?;
        let network = network.unwrap_or(Network::Signet);

        Ok(Address::from_script(&spk, network)
            .map_err(|_| Error::NotAddressable(spk.into()))?
            .into())
    }

    /// script(Bytes|Script) -> Script
    pub fn script(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Script(script) => script.into(),
            Value::Bytes(bytes) => ScriptBuf::from(bytes).into(),
            other => bail!(Error::InvalidScriptConstructor(other.into())),
        })
    }

    /// Cast SecKey/Bytes into a PubKey
    /// pubkey(SecKey|Bytes|PubKey) -> PubKey
    pub fn pubkey(args: Array, _: &ScopeRef) -> Result<Value> {
        let pubkey: DescriptorPublicKey = args.arg_into()?;
        Ok(pubkey.into())
    }

    /// transaction(Bytes|TaggedArray|Transaction) -> Transaction
    pub fn transaction(args: Array, _: &ScopeRef) -> Result<Value> {
        let tx: Transaction = args.arg_into()?;
        Ok(tx.into())
    }

    /// seckey(Bytes|SecKey) -> SecKey
    pub fn seckey(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::SecKey(args.arg_into()?))
    }

    /// Generate a new random Xpriv
    /// genkey(Network = Signet) -> SecKey
    pub fn genkey(args: Array, _: &ScopeRef) -> Result<Value> {
        let network = args
            .arg_into::<Option<Network>>()?
            .unwrap_or(Network::Signet);
        let seed: [u8; 32] = thread_rng().gen();

        Ok(Xpriv::new_master(network, &seed).unwrap().into())
    }

    /// Sign the given message (hash) using ECDSA
    /// sign::ecdsa(SecKey, Bytes, Bool compact_sig=false)
    pub fn signEcdsa(args: Array, _: &ScopeRef) -> Result<Value> {
        let (seckey, msg, compact_sig): (_, _, Option<bool>) = args.args_into()?;
        let sig = EC.sign_ecdsa(&msg, &seckey);

        Ok(if compact_sig.unwrap_or(false) {
            sig.serialize_compact().to_vec()
        } else {
            sig.serialize_der().to_vec()
        }
        .into())
    }

    /// Sign the given message (hash) using Schnorr
    /// sign::schnorr(SecKey, Bytes)
    pub fn signSchnorr(args: Array, _: &ScopeRef) -> Result<Value> {
        let (keypair, msg): (secp256k1::Keypair, secp256k1::Message) = args.args_into()?;

        let sig = EC.sign_schnorr_with_rng(&msg, &keypair, &mut thread_rng());
        Ok(sig.serialize().to_vec().into())
    }

    /// verify::ecdsa(PubKey, Bytes msg, Bytes signature)
    pub fn verifyEcdsa(args: Array, _: &ScopeRef) -> Result<Value> {
        let (pk, msg, sig) = args.args_into()?;
        Ok(EC.verify_ecdsa(&msg, &sig, &pk).is_ok().into())
    }

    /// verify::schnorr(PubKey, Bytes msg, Bytes signature)
    pub fn verifySchnorr(args: Array, _: &ScopeRef) -> Result<Value> {
        let (pk, msg, sig) = args.args_into()?;
        Ok(EC.verify_schnorr(&sig, &msg, &pk).is_ok().into())
    }

    /// scriptPubKey(Descriptor|TapInfo|PubKey|Address|Script) -> Script
    ///
    /// Descriptors are compiled into their scriptPubKey
    /// TapInfo are returned as their V1 witness program
    /// PubKeys are converted into a wpkh() scripts
    /// Scripts are returned as-is
    pub fn scriptPubKey(args: Array, _: &ScopeRef) -> Result<Value> {
        let spk = args.arg_into::<Value>()?.into_spk()?;
        Ok(spk.into())
    }

    /// script::strip(Script) -> Script
    /// Strip debug markers from the given Script
    pub fn scriptStrip(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args
            .arg_into::<ScriptBuf>()?
            .strip_markers(SCRIPT_MARKER_MAGIC_BYTES)?
            .into())
    }

    /// script::wiz(Script) -> Symbol
    /// Encode the Script in a Scriptwiz-compatible format (newlines, stack labels & comments)
    pub fn scriptWiz(args: Array, _: &ScopeRef) -> Result<Value> {
        let script = args.arg_into::<ScriptBuf>()?;
        let mut wiz_str = String::new();
        fmt_script(&mut wiz_str, &script, ScriptFmt::ScriptWiz, Some(0))?;
        // Uses Symbol for the same reason described in `stdlib::fns::debug()`
        Ok(Symbol::new(Some(wiz_str)).into())
    }

    /// script::bitide(Script) -> Symbol
    /// Encode the Script in a BitIDE-compatible format (newlines, stack labels & comments)
    pub fn scriptBitIde(args: Array, _: &ScopeRef) -> Result<Value> {
        let script = args.arg_into::<ScriptBuf>()?;
        let mut bitide_str = String::new();
        fmt_script(&mut bitide_str, &script, ScriptFmt::BitIde, Some(0))?;
        Ok(Symbol::new(Some(bitide_str)).into())
    }
}

impl Value {
    /// Get the scriptPubKey representation of this Value
    pub fn into_spk(self) -> Result<ScriptBuf> {
        Ok(match self {
            // Raw scripts are returned as-is
            Value::Script(script) => script,
            // Descriptors (or values coercible into them) are converted into their scriptPubKey
            Value::Descriptor(descriptor) => descriptor.to_script_pubkey()?,
            Value::PubKey(_) => Descriptor::try_from(self)?.to_script_pubkey()?,
            // TapInfo returns the output V1 witness program of the output key
            Value::TapInfo(tapinfo) => ScriptBuf::new_witness_program(&WitnessProgram::new(
                WitnessVersion::V1,
                &tapinfo.output_key().serialize(),
            )?),
            // Addresses can be provided as an Address or String
            Value::Address(address) => address.script_pubkey(),
            Value::String(_) => Address::try_from(self)?.script_pubkey(),
            other => bail!(Error::NoSpkRepr(other.into())),
        })
    }
    pub fn is_script(&self) -> bool {
        matches!(self, Value::Script(_))
    }
}

// Convert from Bitcoin types to Value

impl From<XOnlyPublicKey> for Value {
    fn from(pk: XOnlyPublicKey) -> Self {
        Value::PubKey(DescriptorPublicKey::Single(SinglePub {
            key: SinglePubKey::XOnly(pk),
            origin: None,
        }))
    }
}
impl From<TweakedPublicKey> for Value {
    fn from(pk: TweakedPublicKey) -> Self {
        pk.to_inner().into()
    }
}

impl From<bitcoin::PublicKey> for Value {
    fn from(pk: bitcoin::PublicKey) -> Self {
        Value::PubKey(DescriptorPublicKey::Single(SinglePub {
            key: SinglePubKey::FullKey(pk),
            origin: None,
        }))
    }
}

impl From<Xpub> for Value {
    fn from(xpub: Xpub) -> Self {
        Value::PubKey(DescriptorPublicKey::XPub(DescriptorXKey {
            xkey: xpub,
            derivation_path: DerivationPath::master(),
            wildcard: descriptor::Wildcard::None,
            origin: if xpub.depth > 0 {
                Some((xpub.parent_fingerprint, [xpub.child_number][..].into()))
            } else {
                None
            },
        }))
    }
}

impl From<Xpriv> for Value {
    fn from(xprv: Xpriv) -> Self {
        Value::SecKey(DescriptorSecretKey::XPrv(DescriptorXKey {
            xkey: xprv,
            derivation_path: DerivationPath::master(),
            wildcard: descriptor::Wildcard::None,
            origin: if xprv.depth > 0 {
                Some((xprv.parent_fingerprint, [xprv.child_number][..].into()))
            } else {
                None
            },
        }))
    }
}

// Convert from Value to secp256k1 types

impl TryFrom<Value> for secp256k1::SecretKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value.try_into()? {
            DescriptorSecretKey::Single(single_priv) => single_priv.key.inner,
            DescriptorSecretKey::XPrv(xprv) => {
                // TODO derive wildcards (similarly to pubkeys via at_derivation_index)
                xprv.xkey
                    .derive_priv(&EC, &xprv.derivation_path)?
                    .private_key
            }
            DescriptorSecretKey::MultiXPrv(_) => bail!(Error::InvalidMultiXprv),
        })
    }
}
impl TryFrom<Value> for secp256k1::PublicKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(bitcoin::PublicKey::try_from(val)?.inner)
    }
}
impl TryFrom<Value> for secp256k1::Keypair {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(secp256k1::SecretKey::try_from(value)?.keypair(&EC))
    }
}
impl TryFrom<Value> for secp256k1::Message {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(Self::from_digest_slice(&value.into_bytes()?)?)
    }
}
impl TryFrom<Value> for secp256k1::ecdsa::Signature {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        let bytes = value.into_bytes()?;
        Ok(if bytes.len() == 64 {
            Self::from_compact(&bytes)?
        } else {
            Self::from_der(&bytes)?
        })
    }
}

// Convert from Value to Bitcoin types

impl_simple_into_variant!(ScriptBuf, Script, into_script, NotScript);
impl_simple_into_variant!(Network, Network, into_network, NotNetwork);

impl TryFrom<Value> for DescriptorPublicKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::PubKey(pubkey) => Ok(pubkey),
            Value::SecKey(seckey) => Ok(seckey.to_public(&EC)?),
            // Bytes are coerced into a single PubKey if they are 33 or 32 bytes long,
            // or to an Xpub if they're 78 bytes long
            Value::Bytes(bytes) => Ok(match bytes.len() {
                33 | 32 => DescriptorPublicKey::Single(SinglePub {
                    origin: None,
                    key: match bytes.len() {
                        33 => SinglePubKey::FullKey(PublicKey::from_slice(&bytes)?),
                        32 => SinglePubKey::XOnly(XOnlyPublicKey::from_slice(&bytes)?),
                        _ => unreachable!(),
                    },
                }),
                78 => Value::from(Xpub::decode(&bytes)?).try_into()?,
                len => bail!(Error::InvalidPubKeyLen(len)),
            }),
            v => Err(Error::NotPubKey(v.into())),
        }
    }
}
impl TryFrom<Value> for DescriptorSecretKey {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        match value {
            Value::SecKey(seckey) => Ok(seckey),
            Value::Bytes(bytes) => Ok(match bytes.len() {
                32 => DescriptorSecretKey::Single(SinglePriv {
                    // XXX not fully round-trip-able - the (un)compressed flag is lost (bitcoin::PrivateKey::to_bytes()
                    // does not encode it and PrivateKey::from_slice() always constructs compressed keys) and the
                    // network is always set to Signet.
                    key: bitcoin::PrivateKey::from_slice(&bytes, Network::Signet)?,
                    origin: None,
                }),
                78 => Value::from(Xpriv::decode(&bytes)?).try_into()?,
                len => bail!(Error::InvalidSecKeyLen(len)),
            }),
            v => Err(Error::NotSecKey(v.into())),
        }
    }
}

impl TryFrom<Value> for bitcoin::PublicKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(DescriptorPublicKey::try_from(val)?
            .at_derivation_index(0)?
            .derive_public_key(&EC)?)
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
            Value::Psbt(psbt) => psbt.extract(&EC)?,

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
        Ok(Self::from_slice(&items))
    }
}
impl TryFrom<Value> for bitcoin::PrivateKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        // XXX always uses Signet
        Ok(Self::new(val.try_into()?, Network::Signet))
    }
}
impl TryFrom<Value> for bitcoin::ecdsa::Signature {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Self::from_slice(&val.into_bytes()?)?)
    }
}
impl TryFrom<Value> for Xpub {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val.try_into()? {
            DescriptorPublicKey::XPub(dxpub) => {
                dxpub.xkey.derive_pub(&EC, &dxpub.derivation_path)?
            }
            other => bail!(Error::NotSingleXpub(other.into())),
        })
    }
}
impl TryFrom<Value> for Xpriv {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val.try_into()? {
            DescriptorSecretKey::XPrv(dxprv) => {
                dxprv.xkey.derive_priv(&EC, &dxprv.derivation_path)?
            }
            other => bail!(Error::NotSingleXpriv(other.into())),
        })
    }
}
impl TryFrom<Value> for bip32::Fingerprint {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val {
            Value::Bytes(ref bytes) => match bytes.len() {
                // Use 4 bytes long values as an explicit BIP32 fingerprint
                4 => bytes.as_slice().try_into()?,
                // Convert 32/33/78 bytes (ecdsa/xonly/xpub) into a PubKey first, then get their fingerprint
                32 | 33 | 78 => Value::PubKey(val.try_into()?).try_into()?,
                _ => bail!(Error::NotFingerprintLike(val.into())),
            },
            Value::PubKey(ref dpk) => match dpk {
                // For xpubs, get the fingerprint of the final derivation key (not the master_fingerprint()'s)
                DescriptorPublicKey::XPub(_) => Xpub::try_from(val)?.fingerprint(),
                // For single keys the master_fingerprint() is the same as the final fingerprint
                DescriptorPublicKey::Single(_) => dpk.master_fingerprint(),
                DescriptorPublicKey::MultiXPub(_) => bail!(Error::InvalidMultiXpub),
            },
            // Convert SecKey to PubKey, then get its Fingerprint
            Value::SecKey(_) => Value::PubKey(val.try_into()?).try_into()?,
            other => bail!(Error::NotFingerprintLike(other.into())),
        })
    }
}
impl TryFrom<Value> for DerivationPath {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(val.into_vec_of::<ChildNumber>()?.into())
    }
}
impl TryFrom<Value> for ChildNumber {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(val.into_u32()?.into())
    }
}

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
                write!(f, "\n")?;
                indent_w += INDENT;
            }
        }
        ScriptFmt::Minsc(false) => (),
        ScriptFmt::ScriptWiz => {
            write!(f, "// ScriptWiz formatted\n")?;
        }
        ScriptFmt::BitIde => {
            write!(f, "// BitIDE formatted\n")?;
        }
    }

    let mut iter = script
        .iter_with_markers(SCRIPT_MARKER_MAGIC_BYTES)
        .peekable();

    while let Some(item) = iter.next() {
        if let (Ok(MarkerItem::Instruction(Instruction::Op(OP_ELSE | OP_ENDIF))), Some(_)) =
            (&item, indent)
        {
            if_indent_w = if_indent_w.checked_sub(INDENT).unwrap_or(0);
        }
        write!(f, "{:i$}", "", i = indent_w + if_indent_w)?;

        match item {
            Ok(MarkerItem::Instruction(inst)) => match inst {
                Instruction::PushBytes(push) if push.is_empty() => write!(f, "<0>")?,
                Instruction::PushBytes(push) => write!(f, "<0x{}>", push.as_bytes().as_hex())?,
                Instruction::Op(opcode) => {
                    write!(f, "{}", opcode.pretty(None))?;

                    if let (OP_IF | OP_NOTIF | OP_ELSE, Some(_)) = (opcode, indent) {
                        if_indent_w = if_indent_w + INDENT;
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
                        write!(f, "// {}", body.replace("\n", &newline_indent))?
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
                    write!(f, "\n")?; // add newline before the next item or the closing backtick
                }
            }

            // Always add newlines, these are never rendered as a single line
            ScriptFmt::ScriptWiz | ScriptFmt::BitIde => write!(f, "\n")?,
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
        write!(f, "{newline_or_space}{:indent_w$}]", "")
    }

    fn prefer_multiline_anyway(&self) -> bool {
        (self.input.len() + self.output.len()) > 2
    }
}

impl PrettyDisplay for miniscript::DescriptorPublicKey {
    const AUTOFMT_ENABLED: bool = false;
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, _indent: Option<usize>) -> fmt::Result {
        use miniscript::DescriptorPublicKey::{MultiXPub, Single, XPub};
        match self {
            XPub(_) | MultiXPub(_) => write!(f, "{}", self),
            Single(_) => write!(f, "pubkey({})", self),
        }
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
            (opcode, _) => write!(f, "{:}", opcode),
        }
    }
}
