use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv};
use bitcoin::psbt::{self, Psbt};
use bitcoin::{secp256k1, PrivateKey, PublicKey, TxIn, TxOut};
use miniscript::psbt::{PsbtExt, PsbtInputExt, PsbtOutputExt};

use crate::error::ResultExt;
use crate::runtime::{Array, Error, FromValue, Mutable, Number::Int, Result, ScopeRef, Value};
use crate::util::EC;

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();
    scope.set_fn("psbt", fns::psbt).unwrap();
    scope.set_fn("psbt::create", fns::psbt).unwrap();
    scope.set_fn("psbt::update", fns::update).unwrap();
    scope.set_fn("psbt::combine", fns::combine).unwrap();
    scope.set_fn("psbt::finalize", fns::finalize).unwrap();
    scope.set_fn("psbt::extract", fns::extract).unwrap();
    scope.set_fn("psbt::sighash", fns::sighash).unwrap();
    scope.set_fn("psbt::fee", fns::fee).unwrap();
    scope.set_fn("psbt::sign", fns::sign).unwrap();
}

impl TryFrom<Value> for Psbt {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Psbt(psbt) => psbt,
            Value::Bytes(bytes) => Psbt::deserialize(&bytes)?,
            Value::Transaction(tx) => Psbt::from_unsigned_tx(tx)?,
            Value::Array(array) => psbt_from_tags(array)?,
            other => bail!(Error::NotPsbtLike(other.into())),
        })
    }
}

#[allow(non_snake_case)]
pub mod fns {
    use std::collections::BTreeMap;

    use super::*;

    /// psbt(Transaction|Bytes|Array<Tagged>) -> Psbt
    pub fn psbt(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::Psbt(args.arg_into()?))
    }

    /// psbt::update(Psbt, Array<Tagged>) -> Psbt
    pub fn update(args: Array, _: &ScopeRef) -> Result<Value> {
        let (mut psbt, tags) = args.args_into()?;
        update_psbt(&mut psbt, tags)?;
        Ok(Value::Psbt(psbt))
    }

    /// psbt::combine(Array<Psbt>) -> Psbt
    pub fn combine(args: Array, _: &ScopeRef) -> Result<Value> {
        let mut psbts: Vec<Psbt> = args.arg_into()?;
        ensure!(!psbts.is_empty(), Error::InvalidArguments);
        let mut psbt = psbts.swap_remove(0); // OK to swap because combine is commutative
        for other_psbt in psbts {
            psbt.combine(other_psbt)?;
        }
        Ok(Value::Psbt(psbt))
    }

    /// psbt::finalize(Psbt) -> Psbt
    ///
    /// Finalize the PSBT, raising an error if any of the inputs failed to finalize
    pub fn finalize(args: Array, _: &ScopeRef) -> Result<Value> {
        let mut psbt: Psbt = args.arg_into()?;
        psbt.finalize_mut(&EC).map_err(Error::PsbtFinalize)?;
        Ok(psbt.into())
    }

    /// psbt::try_finalize(Psbt) -> [Psbt, Array<String>]
    ///
    /// Try finalizing the PSBT, returning it with all the inputs that could be finalized
    /// an an array of errors for the input that couldn't.
    pub fn try_finalize(args: Array, _: &ScopeRef) -> Result<Value> {
        let mut psbt: Psbt = args.arg_into()?;
        let errors = match psbt.finalize_mut(&EC) {
            Ok(()) => vec![],
            Err(errors) => errors.iter().map(|e| Value::from(e.to_string())).collect(),
        };
        Ok(Value::array_of((psbt, errors)))
    }

    /// psbt::extract(Psbt, Bool finalize=false) -> Transaction
    /// Also available as `tx(Psbt)` (without `finalize`, for pre-finalized PSBT only)
    pub fn extract(args: Array, _: &ScopeRef) -> Result<Value> {
        let (mut psbt, finalize): (Psbt, Option<bool>) = args.args_into()?;
        if finalize.unwrap_or(false) {
            psbt.finalize_mut(&EC).map_err(Error::PsbtFinalize)?;
        }
        Ok(psbt.extract(&EC)?.into())
    }

    /// psbt::sighash(Psbt, Int input_index, Bytes tapleaf_hash=None) -> Bytes
    pub fn sighash(args: Array, _: &ScopeRef) -> Result<Value> {
        use bitcoin::sighash::SighashCache;
        let (psbt, input_index, tapleaf_hash): (Psbt, _, _) = args.args_into()?;
        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

        let sighash_msg = psbt.sighash_msg(input_index, &mut sighash_cache, tapleaf_hash)?;
        Ok(sighash_msg.to_secp_msg()[..].to_vec().into())
    }

    /// psbt::fee(Psbt) -> Int
    pub fn fee(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args.arg_into::<Psbt>()?.fee()?.to_sat().try_into()?)
    }

    // psbt::sign(Psbt, SecKey<Xpriv>) -> [Psbt, Signed, Failed]
    // psbt::sign(Psbt, Array<SecKey<Xpriv>>) -> [Psbt, Signed, Failed]
    // psbt::sign(Psbt, Array<PubKey<Single>:SecKey<Single>>) -> [Psbt, Signed, Failed]
    //
    // where `Signed` is an `Array<Int:Array<PubKey>>` mapping input indexes to the PubKeys
    // used to sign them, and `Failed` is an `Array<Int:String>` mapping input indexes
    // to the error encountered while trying to sign them.
    pub fn sign(args: Array, _: &ScopeRef) -> Result<Value> {
        let (mut psbt, seckeys): (Psbt, Value) = args.args_into()?;
        let signing_result = match seckeys {
            Value::Array(seckeys) => {
                if let Some(Value::Array(_)) = seckeys.get(0) {
                    // Keys provided as tagged array of [ $single_pk1: $single_sk1, $single_pk2: $single_sk2, ... ]
                    psbt.sign(&BTreeMap::<PublicKey, PrivateKey>::try_from(seckeys)?, &EC)
                } else {
                    // Keys provided as [ $xpriv1, $xpriv2, ... ]
                    // FIXME: does not work because Xpriv does not implement Ord
                    //psbt.sign(&BTreeSet::<Xpriv>::try_from(seckeys), &EC)
                    bail!(Error::InvalidArguments);
                }
            }
            // Provided as a single Xpriv
            seckey => psbt.sign(&Xpriv::try_from(seckey)?, &EC),
        };
        let (signed, failed) = match signing_result {
            Ok(signed) => (signed, BTreeMap::new()),
            // Failures are returned without raising an error
            Err((signed, failed)) => (signed, failed),
        };
        let signed = signed
            .into_iter()
            .map(|(input_index, pks)| {
                let pks = pks.into_iter().map(Value::from).collect::<Vec<_>>();
                Value::array_of((input_index, pks))
            })
            .collect::<Vec<_>>();
        let failed = failed
            .into_iter()
            .map(|(input_index, error)| Value::array_of((input_index, error.to_string())))
            .collect::<Vec<_>>();

        Ok(Value::array_of((psbt, signed, failed)))
    }
}

fn psbt_from_tags(tags: Array) -> Result<Psbt> {
    let mut tags = tags.check_varlen(1, usize::MAX)?;

    // The first tag must be te tx to initialize the PSBT with
    let (first_tag, tx_val): (String, Value) = tags.0.remove(0).try_into()?; // safe to remove() because the length was checked
    ensure!(
        first_tag == "tx" || first_tag == "unsigned_tx",
        Error::PsbtFirstTagNotTx
    );

    let unsigned_tx = tx_val.try_into().box_err(Error::PsbtInvalidTx)?;
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

    // The rest are tagged instructions for update_psbt()
    update_psbt(&mut psbt, tags)?;

    Ok(psbt)
}

fn mut_input(psbt: &mut Psbt, vin: usize) -> Result<&mut psbt::Input> {
    psbt.inputs
        .get_mut(vin)
        .ok_or(Error::PsbtInputNotFound(vin))
}
fn mut_output(psbt: &mut Psbt, vout: usize) -> Result<&mut psbt::Output> {
    psbt.outputs
        .get_mut(vout)
        .ok_or(Error::PsbtOutputNotFound(vout))
}

fn update_psbt(psbt: &mut Psbt, tags: Array) -> Result<()> {
    tags.for_each_tag(|tag, val| {
        match tag {
            "version" => psbt.version = val.try_into()?,
            "xpub" => psbt.xpub = val.try_into()?,
            "proprietary" => psbt.proprietary = val.try_into()?,
            "unknown" => psbt.unknown = val.try_into()?,
            // Update PSBT fields for existing inputs
            "inputs" => {
                for (vin, in_tags) in mapped_or_all(val, psbt.inputs.len())? {
                    update_input(mut_input(psbt, vin)?, in_tags)?;
                }
            }
            // Update PSBT fields for existing outputs
            "outputs" => {
                for (vout, out_tags) in mapped_or_all(val, psbt.outputs.len())? {
                    update_output(mut_output(psbt, vout)?, out_tags)?;
                }
            }
            "combine" => psbt.combine(val.try_into()?)?,

            // Shortcut for adding a Transaction TxIn and Psbt Input in one go.
            // Must include the "input" field with the input (or just the input's prevout) to add to the transaction,
            // and can additionally contain any of the PSBT input fields.
            "add_inputs" => {
                for PsbtAddIn(input, psbt_input) in val.into_vec_of()? {
                    psbt.unsigned_tx.input.push(input);
                    psbt.inputs.push(psbt_input);
                }
            }

            // Shortcut for adding a Transaction TxOut and Psbt Output in one go.
            // Must include the "output" field with the output to add to the transaction,
            // and can additionally contain any of the PSBT output fields.
            "add_outputs" => {
                for PsbtAddOut(input, psbt_input) in val.into_vec_of()? {
                    psbt.unsigned_tx.output.push(input);
                    psbt.outputs.push(psbt_input);
                }
            }

            _ => bail!(Error::TagUnknown),
        }
        Ok(())
    })
}

fn update_input(psbt_input: &mut psbt::Input, tags: Array) -> Result<()> {
    let mut descriptor = None;
    let mut utxo_amount = None;
    tags.for_each_tag(|tag, val| {
        match tag {
            "non_witness_utxo" => psbt_input.non_witness_utxo = Some(val.try_into()?),
            "witness_utxo" | "utxo" => psbt_input.witness_utxo = Some(val.try_into()?),
            "partial_sigs" => psbt_input.partial_sigs = val.try_into()?,
            "sighash_type" => psbt_input.sighash_type = Some(val.try_into()?),
            "redeem_script" => psbt_input.redeem_script = Some(val.try_into()?),
            "witness_script" => psbt_input.witness_script = Some(val.try_into()?),
            "bip32_derivation" | "key_source" => {
                psbt_input.bip32_derivation = bip32_derivation(val)?
            }
            "final_script_sig" => psbt_input.final_script_sig = Some(val.try_into()?),
            "final_script_witness" => psbt_input.final_script_witness = Some(val.try_into()?),
            "ripemd160_preimages" => psbt_input.ripemd160_preimages = val.try_into()?,
            "sha256_preimages" => psbt_input.sha256_preimages = val.try_into()?,
            "hash160_preimages" => psbt_input.hash160_preimages = val.try_into()?,
            "hash256_preimages" => psbt_input.hash256_preimages = val.try_into()?,
            "tap_key_sig" => psbt_input.tap_key_sig = Some(val.try_into()?),
            "tap_script_sigs" => psbt_input.tap_script_sigs = val.try_into()?,
            "tap_scripts" => psbt_input.tap_scripts = val.try_into()?,
            "tap_key_origins" => psbt_input.tap_key_origins = val.try_into()?,
            "tap_internal_key" => psbt_input.tap_internal_key = Some(val.try_into()?),
            "tap_merkle_root" => psbt_input.tap_merkle_root = Some(val.try_into()?),
            "proprietary" => psbt_input.proprietary = val.try_into()?,
            "unknown" => psbt_input.unknown = val.try_into()?,
            "descriptor" => {
                let descriptor_ = val.try_into()?;
                psbt_input.update_with_descriptor_unchecked(&descriptor_)?;
                descriptor = Some(descriptor_);
            }
            // Keep the amount to later construct the utxo
            "amount" | "utxo_amount" => utxo_amount = Some(val.try_into()?),
            _ => bail!(Error::TagUnknown),
        }
        Ok(())
    })?;
    // Automatically fill in the `witness_utxo` if the `descriptor`` and `utxo_amount` are known
    if let (Some(descriptor), Some(utxo_amount), None) =
        (descriptor, utxo_amount, &psbt_input.witness_utxo)
    {
        psbt_input.witness_utxo = Some(TxOut {
            script_pubkey: descriptor.script_pubkey(),
            value: utxo_amount,
        });
    }
    Ok(())
}

fn update_output(psbt_output: &mut psbt::Output, tags: Array) -> Result<()> {
    tags.for_each_tag(|tag, val| {
        match tag {
            "redeem_script" => psbt_output.redeem_script = Some(val.try_into()?),
            "witness_script" => psbt_output.witness_script = Some(val.try_into()?),
            "bip32_derivation" | "key_source" => psbt_output.bip32_derivation = val.try_into()?,
            "tap_internal_key" => psbt_output.tap_internal_key = Some(val.try_into()?),
            // TOOD "tap_tree" => psbt_output.tap_internal_key = Some(val.try_into()?),
            "tap_key_origins" => psbt_output.tap_key_origins = val.try_into()?,
            "proprietary" => psbt_output.proprietary = val.try_into()?,
            "unknown" => psbt_output.unknown = val.try_into()?,
            "descriptor" => psbt_output
                .update_with_descriptor_unchecked(&val.try_into()?)
                .map(|_| ())?,
            _ => bail!(Error::TagUnknown),
        }
        Ok(())
    })
}

// Parse an Array that either contains a list of index:value tuples mapping from
// element indexes to values, or a full list of all element values with no indexes.
// Returned as a list of index:value tuples in both cases.
fn mapped_or_all<T: FromValue>(arr: Value, expected_all_length: usize) -> Result<Vec<(usize, T)>> {
    let arr = arr.into_array()?;
    if let Some(Value::Array(first_el)) = arr.get(0) {
        if let Some(Value::Number(_)) = first_el.get(0) {
            // Provided as [ 0: $val0, 1: $val1, ... ]
            return arr.try_into();
        }
    }
    // Provided as [ $val0, $val1, ... ]
    ensure!(
        arr.len() == expected_all_length,
        Error::InvalidLength(arr.len(), expected_all_length)
    );
    Ok(<Vec<T>>::try_from(arr)?.into_iter().enumerate().collect())
}

struct PsbtAddIn(TxIn, psbt::Input);
impl TryFrom<Value> for PsbtAddIn {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        // Extract the "input" tag to construct the tx input, collecting the other PSBT tags and forwarding them to update_input()
        let mut tx_input = None;
        let psbt_input_tags = value
            .into_tags()?
            .into_iter()
            .filter_map(|(tag, val)| {
                if tag == "input" {
                    tx_input = Some(val);
                    None
                } else {
                    Some(Value::array_of((tag, val)))
                }
            })
            .collect();
        let tx_input = tx_input
            .ok_or(Error::PsbtAddInMissingTxIn)?
            .try_into()
            .map_err(|e| Error::TagError("input".into(), Box::new(e)))?;

        let mut psbt_input = psbt::Input::default();
        update_input(&mut psbt_input, Array(psbt_input_tags))?;

        Ok(PsbtAddIn(tx_input, psbt_input))
    }
}

struct PsbtAddOut(TxOut, psbt::Output);
impl TryFrom<Value> for PsbtAddOut {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        // Extract the "output" tag to construct the tx output, collecting the other PSBT tags and forwarding them to update_output()
        let mut tx_output = None;
        let psbt_outputs_tags = value
            .into_tags()?
            .into_iter()
            .filter_map(|(tag, val)| {
                if tag == "output" {
                    tx_output = Some(val);
                    None
                } else {
                    Some(Value::array_of((tag, val)))
                }
            })
            .collect();
        let tx_output = tx_output
            .ok_or(Error::PsbtAddOutMissingTxOut)?
            .try_into()
            .map_err(|e| Error::TagError("output".into(), Box::new(e)))?;

        let mut psbt_output = psbt::Output::default();
        update_output(&mut psbt_output, Array(psbt_outputs_tags))?;

        Ok(PsbtAddOut(tx_output, psbt_output))
    }
}

// BIP32 key sources. May be provided as a single Xpub/Xpriv, as an array of Xpubs/Xprivs,
// or as map of single PubKey to KeySource. (examples in KeyWithSource below)
fn bip32_derivation(
    val: Value,
) -> Result<BTreeMap<secp256k1::PublicKey, (Fingerprint, DerivationPath)>> {
    let key_sources: Vec<KeyWithSource> = match val {
        Value::Array(array) => array.into_iter().collect_into()?,
        single => vec![single.try_into()?],
    };
    Ok(key_sources
        .into_iter()
        .map(|ks| (ks.0, (ks.1, ks.2)))
        .collect())
}
pub struct KeyWithSource(
    pub secp256k1::PublicKey,
    pub Fingerprint,
    pub DerivationPath,
);
impl TryFrom<Value> for KeyWithSource {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val {
            // May be provided as an array mapping from `pk` to the `source`,
            // where `source` is a tuple/tagged array of $fingerprint:$derivation_path.
            // For example: `$single_pk1: 0x1223344:[2,5]`
            // Or in long-form: `$single_pk1: [ "fingerprint": 0x11223344, "derivation_path": [2,5] ]`
            // Or even longer: `[ "pubkey": $single_pk1, "source": [ "fingerprint": 0x11223344, "derivation_path": [2,5] ] ]`
            Value::Array(_) => {
                let (pk, source): (_, Value) = val.tagged_or_tuple("pubkey", "source")?;
                let (fingerprint, derivation_path) =
                    source.tagged_or_tuple("fingerprint", "derivation_path")?;
                Self(pk, fingerprint, derivation_path)
            }
            // Or any value coercible into a PubKey/SecKey, using the origin/derivation associated with it
            // For example, `xpub123/1/10` would set the final key's origin to `[fingerprint(xpub123), [1, 10]]`
            _ => {
                let dpk = miniscript::DescriptorPublicKey::try_from(val)?;
                let fingerprint = dpk.master_fingerprint();
                let derivation_path = dpk.full_derivation_path().ok_or(Error::InvalidMultiXpub)?;
                let final_pk = dpk.at_derivation_index(0)?.derive_public_key(&EC)?.inner;
                Self(final_pk, fingerprint, derivation_path)
            }
        })
    }
}

impl TryFrom<Value> for psbt::PsbtSighashType {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val {
            Value::Number(Int(num)) => Self::from_u32(num.try_into()?),
            Value::String(str) => str.parse()?,
            other => bail!(Error::PsbtInvalidSighashType(Box::new(other))),
        })
    }
}
impl TryFrom<Value> for psbt::raw::Key {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        let (type_value, key): (u32, Vec<u8>) = val.try_into()?;
        Ok(Self {
            type_value: type_value.try_into()?,
            key,
        })
    }
}
impl TryFrom<Value> for psbt::raw::ProprietaryKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        let (prefix, subtype, key): (Vec<u8>, u32, Vec<u8>) = val.try_into()?;
        Ok(Self {
            prefix,
            subtype: subtype.try_into()?,
            key,
        })
    }
}
