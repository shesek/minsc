use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::{fmt, str::FromStr};

use bitcoin::bip32::{self, Xpriv};
use bitcoin::hex::DisplayHex;
use bitcoin::psbt::{self, raw, Psbt, SigningErrors, SigningKeys, SigningKeysMap};
use bitcoin::taproot::{self, LeafVersion, TapLeafHash};
use bitcoin::{hashes, secp256k1, PrivateKey, PublicKey, TxIn, TxOut, XOnlyPublicKey};
use miniscript::descriptor::{DescriptorPublicKey, DescriptorSecretKey};
use miniscript::psbt::{PsbtExt, PsbtInputExt, PsbtOutputExt};

use crate::display::{fmt_list, indentation_params, PrettyDisplay};
use crate::runtime::{Array, Error, FieldAccess, FromValue, Mutable, Result, ScopeRef, Value};
use crate::util::{DescriptorExt, DescriptorPubKeyExt, PsbtInExt, PsbtOutExt, TapInfoExt, EC};

use super::{btc::WshScript, keys::MasterXpriv};

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();
    scope.set_fn("psbt", fns::psbt).unwrap(); // create or update
    scope.set_fn("psbt::create", fns::create).unwrap();
    scope.set_fn("psbt::update", fns::update).unwrap();
    scope.set_fn("psbt::combine", fns::combine).unwrap();
    scope.set_fn("psbt::finalize", fns::finalize).unwrap();
    scope
        .set_fn("psbt::try_finalize", fns::try_finalize)
        .unwrap();
    scope.set_fn("psbt::sign", fns::sign).unwrap();
    scope.set_fn("psbt::try_sign", fns::try_sign).unwrap();
    scope.set_fn("psbt::extract", fns::extract).unwrap();
    scope.set_fn("psbt::extract_raw", fns::extract_raw).unwrap();

    scope.set_fn("psbt::fee", fns::fee).unwrap();
    scope.set_fn("psbt::sighash", fns::sighash).unwrap();
}

impl TryFrom<Value> for Psbt {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Psbt(psbt) => psbt,
            Value::Bytes(bytes) => Psbt::deserialize(&bytes)?,
            Value::String(base64) => Psbt::from_str(&base64)?,
            Value::Transaction(tx) => Psbt::from_unsigned_tx(tx)?,
            Value::Array(array) => psbt_from_tags(array)?,
            other => bail!(Error::NotPsbtLike(other.into())),
        })
    }
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;

    /// psbt(Transaction|Bytes|Array<Tagged>) -> Psbt
    /// psbt(Transaction|Bytes|Array<Tagged>, Array<Tagged>) -> Psbt
    pub fn psbt(args: Array, scope: &ScopeRef) -> Result<Value> {
        let args = args.check_varlen(1, 2)?;
        if args.len() == 1 {
            create(args, scope)
        } else {
            update(args, scope)
        }
    }

    /// psbt::create(Transaction|Bytes|Array<Tagged>) -> Psbt
    pub fn create(args: Array, _: &ScopeRef) -> Result<Value> {
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
    /// and an array of errors for the input that could not.
    pub fn try_finalize(args: Array, _: &ScopeRef) -> Result<Value> {
        let mut psbt: Psbt = args.arg_into()?;
        let errors = match psbt.finalize_mut(&EC) {
            Err(errors) => errors,
            Ok(()) => vec![],
        };
        Ok((psbt, errors).into())
    }

    // psbt::sign(Psbt, Xpriv|Array<Xpriv>|Array<SinglePk:SingleSk> sign_keys) -> Psbt
    //
    // Attempt to sign all transaction inputs for which we have keys, raising an error if any fail.
    pub fn sign(args: Array, _: &ScopeRef) -> Result<Value> {
        let (mut psbt, keys) = args.args_into()?;

        let (_signed, failed) = sign_psbt(&mut psbt, keys)?;
        ensure!(failed.is_empty(), Error::PsbtSigning(failed));
        // XXX check signed?

        Ok(psbt.into())
    }

    // psbt::try_sign(Psbt, Xpriv|Array<Xpriv>|Array<SinglePk:SingleSk> sign_keys) -> [Psbt, Signed, Failed]
    //
    // Attempt to sign all transaction inputs, returning a modified PSBT with the successfully signed inputs even if some fail.
    //
    // Returned with `Signed` as an `Array<Int:Array<PubKey>>` mapping input indexes to the PubKeys used to sign them
    // and `Failed` as an `Array<Int:String>` mapping input indexes to the error encountered while trying to sign them.
    pub fn try_sign(args: Array, _: &ScopeRef) -> Result<Value> {
        let (mut psbt, keys) = args.args_into()?;
        let (signed, failed) = sign_psbt(&mut psbt, keys)?;
        Ok((psbt, signed, failed).into())
    }

    /// psbt::extract(Psbt) -> Transaction
    ///
    /// Extract the PSBT finalized transaction (The PSBT must already be finalized).
    /// Will run the Miniscript interpreter sanity checks. Also possible using `tx(Psbt)`.
    pub fn extract(args: Array, _: &ScopeRef) -> Result<Value> {
        let psbt: Psbt = args.arg_into()?;
        // Uses rust-miniscript's PsbtExt::extract(), which only works with Miniscript-compatible Scripts
        Ok(psbt.extract(&EC)?.into())
    }

    /// psbt::extract_raw(Psbt) -> Transaction
    ///
    /// Extract the PSBT finalized transaction, without running the Miniscript interpreter checks.
    pub fn extract_raw(args: Array, _: &ScopeRef) -> Result<Value> {
        let psbt: Psbt = args.arg_into()?;
        // Uses rust-bitcoin's Psbt::extract_tx(). Unlike rust-miniscript's PsbtExt::extract(), this does not run the
        // interpreter checks and can be used with manual finalization of arbitrary (non-Miniscript-compatible) Script.
        // XXX enable absurd fee check?
        Ok(psbt.extract_tx_unchecked_fee_rate().into())
    }

    /// psbt::fee(Psbt) -> Int
    pub fn fee(args: Array, _: &ScopeRef) -> Result<Value> {
        let fee = args.arg_into::<Psbt>()?.fee()?;
        Ok(fee.to_signed().map_err(|_| Error::Overflow)?.into())
    }

    /// psbt::sighash(Psbt, Int input_index, Bytes tapleaf_hash=None) -> Bytes
    pub fn sighash(args: Array, _: &ScopeRef) -> Result<Value> {
        use bitcoin::sighash::SighashCache;
        let (psbt, input_index, tapleaf_hash): (Psbt, _, _) = args.args_into()?;
        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

        let sighash_msg = psbt.sighash_msg(input_index, &mut sighash_cache, tapleaf_hash)?;
        Ok(sighash_msg.into())
    }
}

fn psbt_from_tags(tags: Array) -> Result<Psbt> {
    let mut tags = tags.check_varlen(1, usize::MAX)?;

    // If the first tag is the 'unsigned_tx', initialize the PSBT with it then update it
    if tags[0].is_tagged_with("unsigned_tx") {
        let (_tag, unsigned_tx): (String, _) = tags.remove(0).try_into()?;
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;

        // Pass the rest of the tags to update_psbt()
        update_psbt(&mut psbt, tags)?;
        Ok(psbt)
    }
    // Otherwise, initialize a new transaction alongside its PSBT
    else {
        create_psbt_with_tx(tags)
    }
}

fn sign_psbt(psbt: &mut Psbt, keys_val: Value) -> Result<(SigningKeysMap, SigningErrors)> {
    let signing_result = match keys_val {
        Value::Array(keys) if !keys.is_empty() => {
            // Peek at the first array element to determine its format
            match keys.first().expect("not empty") {
                // Keys provided as a map of [ $single_pk1:$single_sk1, $single_pk2:$single_sk2, ... ]
                Value::Array(_) => {
                    psbt.sign(&BTreeMap::<PublicKey, PrivateKey>::try_from(keys)?, &EC)
                }

                // Keys provided as [ $xpriv1, $xpriv2, ... ]
                Value::SecKey(DescriptorSecretKey::XPrv(_) | DescriptorSecretKey::MultiXPrv(_)) => {
                    psbt.sign(&XprivSet::try_from(keys)?, &EC)
                }

                // Keys provided as [ $single_sk1, $single_sk2, ... ]
                Value::SecKey(DescriptorSecretKey::Single(_)) => {
                    psbt.sign(&single_seckeys_to_map(keys)?, &EC)
                }
                _ => bail!(Error::PsbtInvalidSignKeys),
            }
        }
        // Key provided as an Xpriv
        Value::SecKey(DescriptorSecretKey::XPrv(_) | DescriptorSecretKey::MultiXPrv(_)) => {
            psbt.sign(&MasterXpriv::try_from(keys_val)?.0, &EC)
        }

        // Key provided as a single key
        Value::SecKey(DescriptorSecretKey::Single(_)) => {
            psbt.sign(&single_seckey_to_map(PrivateKey::try_from(keys_val)?), &EC)
        }

        _ => bail!(Error::PsbtInvalidSignKeys),
    };
    // Returns input signing failures in the the Ok variant. An Err is only raised if the `seckeys` argument is invalid.
    Ok(match signing_result {
        Ok(signed) => (signed, BTreeMap::new()),
        Err((signed, failed)) => (signed, failed),
    })
}

fn update_psbt(psbt: &mut Psbt, tags: Array) -> Result<()> {
    tags.for_each_tag(|tag, val| {
        match tag {
            "version" => psbt.version = val.try_into()?,
            "xpub" => psbt.xpub.append(&mut xpub_map(val)?),
            "proprietary" => psbt.proprietary.append(&mut val.try_into()?),
            "unknown" => psbt.unknown.append(&mut val.try_into()?),
            "inputs" => {
                for (vin, in_tags) in val.into_array()?.mapped_or_all(psbt.inputs.len())? {
                    let psbt_input = psbt
                        .inputs
                        .get_mut(vin)
                        .ok_or(Error::PsbtInputNotFound(vin))?;
                    update_input(psbt_input, in_tags)?;
                }
            }
            "outputs" => {
                for (vout, out_tags) in val.into_array()?.mapped_or_all(psbt.outputs.len())? {
                    let psbt_output = psbt
                        .outputs
                        .get_mut(vout)
                        .ok_or(Error::PsbtOutputNotFound(vout))?;
                    update_output(psbt_output, out_tags)?;
                }
            }

            "combine" => psbt.combine(val.try_into()?)?,

            "utxos" => {
                let utxos = val.into_array()?;
                for (vin, utxo) in utxos.mapped_or_all::<Value>(psbt.inputs.len())? {
                    let psbt_input = psbt
                        .inputs
                        .get_mut(vin)
                        .ok_or(Error::PsbtInputNotFound(vin))?;
                    update_input(psbt_input, (("utxo", utxo),).into())?;
                }
            }

            // Expected to be provided as the first tag, which is handled and stripped by psbt_from_tags()
            "unsigned_tx" => bail!(Error::PsbtTxTagInvalidPosition),

            _ => bail!(Error::TagUnknown),
        }
        Ok(())
    })
}

fn update_input(input: &mut psbt::Input, tags: Array) -> Result<()> {
    let mut descriptor = None;
    let mut tapinfo = None;
    let mut wshscript: Option<WshScript> = None;
    let mut utxo_amount = None;
    tags.for_each_unique_tag(|tag, val| {
        match tag {
            "partial_sigs" => input.partial_sigs.append(&mut val.try_into()?),
            "sighash_type" => input.sighash_type = Some(val.try_into()?),
            "redeem_script" => input.redeem_script = Some(val.try_into()?),
            "witness_script" => input.witness_script = Some(val.try_into()?),
            "bip32_derivation" => input
                .bip32_derivation
                .append(&mut bip32_derivation_map(val)?),
            "final_script_sig" => input.final_script_sig = Some(val.try_into()?),
            "final_script_witness" => input.final_script_witness = Some(val.try_into()?),
            "ripemd160_preimages" => input.ripemd160_preimages.append(&mut hash_preimages(val)?),
            "sha256_preimages" => input.sha256_preimages.append(&mut hash_preimages(val)?),
            "hash160_preimages" => input.hash160_preimages.append(&mut hash_preimages(val)?),
            "hash256_preimages" => input.hash256_preimages.append(&mut hash_preimages(val)?),
            "tap_key_sig" => input.tap_key_sig = Some(val.try_into()?),
            "tap_script_sigs" => input.tap_script_sigs.append(&mut val.try_into()?),
            "tap_scripts" => input.tap_scripts.append(&mut tap_scripts_map(val)?),
            "tap_key_origins" => input.tap_key_origins.append(&mut tap_key_origins_map(val)?),
            "tap_internal_key" => input.tap_internal_key = Some(val.try_into()?),
            "tap_merkle_root" => input.tap_merkle_root = Some(val.try_into()?),
            "proprietary" => input.proprietary.append(&mut val.try_into()?),
            "unknown" => input.unknown.append(&mut val.try_into()?),
            "non_witness_utxo" => input.non_witness_utxo = Some(val.try_into()?),
            "witness_utxo" | "utxo" => {
                // If the UTXO was specified using a DescriptorTaprootSpendInfo/WshScript,
                // keep them to later also use them to populate the PSBT fields.
                if let Value::Array(arr) = &val {
                    match arr.first() {
                        Some(Value::Descriptor(desc)) if descriptor.is_none() => {
                            descriptor = Some(desc.definite()?)
                        }
                        Some(Value::TapInfo(tap)) if tapinfo.is_none() => {
                            tapinfo = Some(tap.clone())
                        }
                        Some(Value::WshScript(wsh)) if wshscript.is_none() => {
                            wshscript = Some(wsh.clone());
                        }
                        _ => {}
                    }
                }
                input.witness_utxo = Some(val.try_into()?);
            }

            // Keep the descriptor/tapinfo/wsh_script and amount fields to later construct the utxo and populate the PSBT fields
            "descriptor" => descriptor = Some(val.try_into()?),
            "tap_info" => tapinfo = Some(val.try_into()?),
            "wsh_script" => wshscript = Some(val.try_into()?),
            "amount" | "utxo_amount" => utxo_amount = Some(val.try_into()?),

            _ => bail!(Error::TagUnknown),
        }
        Ok(())
    })?;

    // Populate PSBT fields using the Descriptor/TaprootSpendInfo, if available
    let mut utxo_spk = None;
    if let Some(descriptor) = descriptor {
        input.update_with_descriptor_unchecked(&descriptor)?;
        utxo_spk = Some(descriptor.script_pubkey());
    } else if let Some(tapinfo) = tapinfo {
        input.update_with_taproot(&tapinfo)?;
        utxo_spk = Some(tapinfo.script_pubkey());
    } else if let Some(wsh) = wshscript {
        utxo_spk = Some(wsh.script_pubkey());
        input.witness_script = Some(wsh.0);
    }

    // Automatically fill in the witness_utxo if the utxo amount and scriptPubKey are known
    if let (None, Some(utxo_amount), Some(utxo_spk)) = (&input.witness_utxo, utxo_amount, utxo_spk)
    {
        input.witness_utxo = Some(TxOut {
            script_pubkey: utxo_spk,
            value: utxo_amount,
        });
    }

    Ok(())
}

fn update_output(out: &mut psbt::Output, tags: Array) -> Result<()> {
    tags.for_each_unique_tag(|tag, val| {
        match tag {
            "redeem_script" => out.redeem_script = Some(val.try_into()?),
            "witness_script" => out.witness_script = Some(val.try_into()?),
            "bip32_derivation" => out.bip32_derivation.append(&mut bip32_derivation_map(val)?),
            "tap_internal_key" => out.tap_internal_key = Some(val.try_into()?),
            "tap_tree" => out.tap_tree = Some(val.try_into()?),
            "tap_key_origins" => out.tap_key_origins.append(&mut tap_key_origins_map(val)?),
            "proprietary" => out.proprietary.append(&mut val.try_into()?),
            "unknown" => out.unknown.append(&mut val.try_into()?),
            "descriptor" => out
                .update_with_descriptor_unchecked(&val.try_into()?)
                .map(|_| ())?,
            "tap_info" => out.update_with_taproot(&val.try_into()?).map(|_| ())?,
            // note: PsbtTxOut calls update_with{descriptor,taproot}() itself and does not forward the "descriptor"
            // and "tap_info" tags here. This will need to be refactored if anything more complex is done here.
            _ => bail!(Error::TagUnknown),
        }
        Ok(())
    })
}

fn create_psbt_with_tx(tags: Array) -> Result<Psbt> {
    let mut psbt = Psbt::from_unsigned_tx(bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    // Handle tx construction tags, collecting and forwarding the rest to update_psbt()
    let mut psbt_tags = Array(vec![]);
    tags.for_each_tag(|tag, val| {
        match tag {
            "tx_version" | "version" => psbt.unsigned_tx.version = val.try_into()?,
            "locktime" => psbt.unsigned_tx.lock_time = val.try_into()?,
            "input" => {
                let PsbtTxIn(tx_input, psbt_input) = val.try_into()?;
                psbt.unsigned_tx.input.push(tx_input);
                psbt.inputs.push(psbt_input);
            }
            "output" => {
                let PsbtTxOut(tx_output, psbt_output) = val.try_into()?;
                psbt.unsigned_tx.output.push(tx_output);
                psbt.outputs.push(psbt_output);
            }
            "inputs" => {
                for PsbtTxIn(tx_input, psbt_input) in val.into_vec_of()? {
                    psbt.unsigned_tx.input.push(tx_input);
                    psbt.inputs.push(psbt_input);
                }
            }
            "outputs" => {
                for PsbtTxOut(tx_output, psbt_output) in val.into_vec_of()? {
                    psbt.unsigned_tx.output.push(tx_output);
                    psbt.outputs.push(psbt_output);
                }
            }

            // Collect other PSBT tags to forward to update_psbt()
            "psbt_version" => psbt_tags.push(("version", val).into()),
            other_tag => psbt_tags.push((other_tag, val).into()),
        }

        Ok(())
    })?;
    // XXX should ideally re-run Psbt::unsigned_tx_checks() but it is private

    update_psbt(&mut psbt, psbt_tags)?;
    Ok(psbt)
}

struct PsbtTxIn(TxIn, psbt::Input);
impl TryFrom<Value> for PsbtTxIn {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        let mut tx_input = bitcoin::transaction::TxIn::default();
        let mut psbt_input = psbt::Input::default();
        let mut psbt_input_tags = Array(vec![]);

        let mut prevout = None;

        let arr = value.into_array()?;
        if arr.len() == 2 && arr[1].is_int() {
            // Tx input provided as a tuple of the tx:vout prevout
            prevout = Some(Value::Array(arr));
        } else {
            // Tx input and PSBT metadata provided as a tagged list
            arr.for_each_unique_tag(|tag, val| {
                match tag {
                    "prevout" => prevout = Some(val),
                    "sequence" => tx_input.sequence = val.try_into()?,
                    // (script_sig and witness are not settable - the constructed tx should be unsigned)

                    // Collect other PSBT tags to forward to update_input()
                    other_tag => psbt_input_tags.push((other_tag, val).into()),
                }
                Ok(())
            })?;
            update_input(&mut psbt_input, psbt_input_tags)?;
        }
        let prevout = prevout.ok_or(Error::PsbtTxInMissingFields)?;

        // If the `prevout` was specified using a PSBT or Transaction, use the spent output info to populate the input PSBT fields
        if let Value::Array(prevout_arr) = &prevout {
            if prevout_arr.len() == 2 {
                match (&prevout_arr[0], &prevout_arr[1]) {
                    (Value::Psbt(prev_psbt), Value::Int(vout)) => {
                        psbt_input.update_with_prevout_psbt(prev_psbt, (*vout).try_into()?)?;
                    }
                    (Value::Transaction(prev_tx), Value::Int(vout)) => {
                        psbt_input.update_with_prevout_tx(prev_tx, (*vout).try_into()?)?;
                    }
                    _ => {}
                }
            }
        }
        tx_input.previous_output = prevout.try_into()?;

        Ok(PsbtTxIn(tx_input, psbt_input))
    }
}

struct PsbtTxOut(TxOut, psbt::Output);
impl TryFrom<Value> for PsbtTxOut {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        let mut tx_output = None;
        let mut psbt_output = psbt::Output::default();
        let mut psbt_output_tags = Array(vec![]);

        let arr = value.into_array()?;
        if arr.len() == 2 && arr.get(1).is_some_and(Value::is_int) {
            // Tx output provided as a $scriptPubKeyLike:$amount tuple
            let (spk_like, amount): (Value, _) = arr.try_into()?;

            // If the scriptPubKey was specified using a Descriptor/TaprootSpendInfo/WshScript, also use them to populate the PSBT fields
            match &spk_like {
                Value::Descriptor(descriptor) => {
                    psbt_output.update_with_descriptor_unchecked(&descriptor.definite()?)?;
                }
                Value::TapInfo(tapinfo) => {
                    psbt_output.update_with_taproot(tapinfo)?;
                }
                Value::WshScript(wsh) => {
                    psbt_output.witness_script = Some(wsh.explicit_script());
                }
                _ => {}
            }

            tx_output = Some(TxOut {
                script_pubkey: spk_like.into_spk()?,
                value: amount,
            });
        } else {
            // Tx output and PSBT metadata provided as a tagged list
            let mut spk = None;
            let mut amount = None;
            arr.for_each_unique_tag(|tag, val| {
                match tag {
                    "amount" => amount = Some(val.try_into()?),
                    "script_pubkey" => spk = Some(val.try_into()?),

                    // Use the Descriptor/TaprootSpendInfo/WshScript to populate the PSBT fields and to construct the scriptPubKey
                    "descriptor" => {
                        let descriptor = val.try_into()?;
                        psbt_output.update_with_descriptor_unchecked(&descriptor)?;
                        spk.get_or_insert_with(|| descriptor.script_pubkey());
                    }
                    "tap_info" => {
                        let tapinfo = val.try_into()?;
                        psbt_output.update_with_taproot(&tapinfo)?;
                        spk.get_or_insert_with(|| tapinfo.script_pubkey());
                    }
                    "wsh_script" => {
                        let wsh: WshScript = val.try_into()?;
                        psbt_output.witness_script = Some(wsh.explicit_script());
                        spk.get_or_insert_with(|| wsh.script_pubkey());
                    }

                    // Collect other PSBT tags to forward to update_output()
                    other_tag => psbt_output_tags.push((other_tag, val).into()),
                }
                Ok(())
            })?;
            update_output(&mut psbt_output, psbt_output_tags)?;

            // If not explicitly given, construct the tx output using the `amount` and `script_pubkey` (which may derived from the `descriptor`/`tap_info`)
            tx_output = tx_output.or_else(|| {
                spk.zip(amount).map(|(spk, amount)| TxOut {
                    script_pubkey: spk,
                    value: amount,
                })
            });
        }

        let tx_output = tx_output.ok_or(Error::PsbtTxOutMissingFields)?;
        Ok(PsbtTxOut(tx_output, psbt_output))
    }
}

// Support specifying just the preimage, automatically converted into the hash->preimage map
fn hash_preimages<H: hashes::Hash + FromValue>(val: Value) -> Result<BTreeMap<H, Vec<u8>>> {
    val.into_array()?
        .into_iter()
        .map(|el| match el {
            Value::Bytes(preimage) => {
                ensure!(preimage.len() == 32, Error::InvalidPreimageLen); // requirement by miniscript
                Ok((<H as hashes::Hash>::hash(&preimage), preimage))
            }
            other => other.try_into(),
        })
        .collect()
}

// BIP32 key sources. May be provided as as an array of Xpubs/Xprivs or as a map of single pubkeys to key sources
fn bip32_derivation_map(val: Value) -> Result<BTreeMap<secp256k1::PublicKey, bip32::KeySource>> {
    // TODO support MultiXpub/Prv as multiple KeyWithSource
    val.into_array()?
        .into_iter()
        .map(|el| {
            Ok(match el {
                // Provided as an explicit map from `pk` to the bip32 `source` (fingerprint+path)
                // For example: `$single_pk1: 0x1223344:[2,5]`, or in long-form: `$single_pk1: [ "fingerprint": 0x11223344, "derivation_path": [2,5] ]`
                // Or even longer: `[ "pubkey": $single_pk1, "source": [ "fingerprint": 0x11223344, "derivation_path": [2,5] ] ]`
                // The fingerprint may also be provided as a key to compute the fingerprint for, for example: `$single_pk1: xpub123:[2,5]`
                // Matches the underlying structure used by rust-bitcoin.
                explicit_map @ Value::Array(_) => {
                    let (pk, source): (_, Value) =
                        explicit_map.tagged_or_tuple("pubkey", "source")?;
                    let (fingerprint, derivation_path) =
                        source.tagged_or_tuple("fingerprint", "derivation_path")?;
                    (pk, (fingerprint, derivation_path))
                }
                // Alternatively, can be provided as a DescriptorPubKey with an internally associated key source.
                // For example, `xpub123/1/10` would set the final key's origin to `[fingerprint(xpub123), [1, 10]]`
                pk_with_source => {
                    let dpk = DescriptorPublicKey::try_from(pk_with_source)?;
                    let fingerprint = dpk.master_fingerprint();
                    let derivation_path =
                        dpk.full_derivation_path().ok_or(Error::InvalidMultiXpub)?;
                    let final_pk = dpk.derive_definite()?.inner;
                    (final_pk, (fingerprint, derivation_path))
                }
            })
        })
        .collect()
}

// Similar to bip32_derivation_map(), but for Xpubs. Used for the global PSBT `xpub` field.
fn xpub_map(val: Value) -> Result<BTreeMap<bip32::Xpub, bip32::KeySource>> {
    val.into_array()?
        .into_iter()
        .map(|el| {
            Ok(match el {
                // Provided as an explicit map from xpubs to the key source (fingerprint+path)
                // Matches the underlying structure used by rust-bitcoin.
                explicit_map @ Value::Array(_) => {
                    let (xpub, source): (_, Value) =
                        explicit_map.tagged_or_tuple("xpub", "source")?;
                    let (fingerprint, derivation_path) =
                        source.tagged_or_tuple("fingerprint", "derivation_path")?;
                    (xpub, (fingerprint, derivation_path))
                }
                // Alternatively, provided as a DescriptorPubKey xpub with an internally associated key source
                xpub_with_source => match xpub_with_source.try_into()? {
                    ref dpk @ DescriptorPublicKey::XPub(ref dxpub) => {
                        let fingerprint = dpk.master_fingerprint();
                        let derivation_path =
                            dpk.full_derivation_path().ok_or(Error::InvalidMultiXpub)?;
                        let final_xpub = dxpub.xkey.derive_pub(&EC, &dxpub.derivation_path)?;
                        (final_xpub, (fingerprint, derivation_path))
                    }
                    other => bail!(Error::NotSingleXpub(other.into())),
                },
            })
        })
        .collect()
}

// Taproot key source map, with support for some additional ways to specify the BIP32 sources and leaf hashes
fn tap_key_origins_map(
    val: Value,
) -> Result<BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)>> {
    val.into_array()?
        .into_iter()
        .map(|el| {
            Ok(if el.is_array() {
                let (pk, pk_val): (DescriptorPublicKey, _) = el.try_into()?;
                match pk_val {
                    // Provided as an explicit map from pubkeys to a tuple of (leaf_hashes,(bip32_fingerprint, path))
                    // Matches the underlying structure used by rust-bitcoin.
                    // For example: "tap_key_origins": [ SINGLE_PUBKEY: [ [ LEAF_HASH1, LEAF_HASH2 ], 0xFINGERPRINT:[0,100]] ] ]
                    Value::Array(arr) if !arr.is_empty() && arr[0].is_array() => {
                        (pk.derive_definite()?.into(), arr.try_into()?)
                    }

                    // Provided as a map from xpubs (with associated key source) to the leaf_hashes
                    // For example: "tap_key_origins": [ xpubAAA/0/100: [ LEAF_HASH1, LEAF_HASH2 ] ]
                    //
                    // Scripts may be provided in place of the LEAF_HASH to compute the hash automatically (via TryFrom<Value> for TapLeafHash)
                    // For example: "tap_key_origins": [ xpubAAA/0/100: [ `xpubAAA/0/100 OP_CHECKSIG` ] ]
                    Value::Array(leaves) => {
                        let leaf_hashes = leaves.try_into()?;
                        let path = pk.full_derivation_path().ok_or(Error::InvalidMultiXpub)?;
                        let source = (pk.master_fingerprint(), path);
                        (pk.derive_definite()?.into(), (leaf_hashes, source))
                    }

                    // Provided as a map from xpubs (with associated key source) to a single leaf as a script/hash
                    // For example: "tap_key_origins": [ xpubAAA/0/100: `xpubAAA/0/100 OP_CHECKSIG` ]
                    single_leaf @ (Value::Bytes(_) | Value::Script(_)) => {
                        let leaf_hash = single_leaf.try_into()?;
                        let path = pk.full_derivation_path().ok_or(Error::InvalidMultiXpub)?;
                        let source = (pk.master_fingerprint(), path);
                        (pk.derive_definite()?.into(), (vec![leaf_hash], source))
                    }

                    other => bail!(Error::InvalidValue(other.into())),
                }
            } else {
                // Provided as just the internal key (with associated source), with no leaf hashes
                // For example: "tap_key_origins": [ xpubAAA/0/100 ], which is equivalent to [ xpubAAA/0/100: [] ]
                let pk: DescriptorPublicKey = el.try_into()?;
                let fingerprint = pk.master_fingerprint();
                let path = pk.full_derivation_path().ok_or(Error::InvalidMultiXpub)?;
                (pk.derive_definite()?.into(), (vec![], (fingerprint, path)))
            })
        })
        .collect()
}

// Accept the `tap_scripts` PSBT input field without an explicit leaf version (defaults to TapScript)
fn tap_scripts_map(
    val: Value,
) -> Result<BTreeMap<taproot::ControlBlock, (bitcoin::ScriptBuf, LeafVersion)>> {
    static DEFAULT_VERSION: LeafVersion = LeafVersion::TapScript;

    val.into_array()?
        .into_iter()
        .map(|el| {
            let (ctrl, script_val): (_, Value) = el.try_into()?;
            Ok(if script_val.is_array() {
                (ctrl, script_val.try_into()?)
            } else {
                (ctrl, (script_val.try_into()?, DEFAULT_VERSION))
            })
        })
        .collect()
}

impl TryFrom<Value> for psbt::PsbtSighashType {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val {
            Value::Int(num) => Self::from_u32(num.try_into()?),
            Value::Bytes(bytes) if bytes.len() == 1 => Self::from_u32(bytes[0] as u32),
            Value::String(str) => str.parse()?,
            other => bail!(Error::PsbtInvalidSighashType(Box::new(other))),
        })
    }
}
impl TryFrom<Value> for raw::Key {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        let (type_value, key): (u32, Vec<u8>) = val.try_into()?;
        Ok(Self {
            type_value: type_value.try_into()?,
            key,
        })
    }
}
impl TryFrom<Value> for raw::ProprietaryKey {
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

// GetKey wrapper around Vec<Xpriv>
struct XprivSet(Vec<Xpriv>);

// Convert an Array into a set of Xprivs used for PSBT signing.
// Unlike the the standard TryInto<Xpriv> conversion which derives the final child Xpriv after applying all derivation
// steps, this instead uses the top-most known Xpriv without deriving. The PSBT bip32_derivation/tap_key_origins fields
// are expected to point to the fingerprint of the top-most key, and not to that of the child.
// XXX could collect both the derived Xpriv and MasterXpriv
impl TryFrom<Array> for XprivSet {
    type Error = Error;
    fn try_from(arr: Array) -> Result<Self> {
        Ok(Self(
            arr.into_iter_of()
                .map(|xprv: Result<MasterXpriv>| Ok(xprv?.0))
                .collect::<Result<Vec<Xpriv>>>()?,
        ))
    }
}

// Needed as a workaround for https://github.com/rust-bitcoin/rust-bitcoin/pull/2850
// Could otherwise use Psbt::sign() with the inner Vec<Xpriv>.
impl psbt::GetKey for XprivSet {
    type Error = <Xpriv as psbt::GetKey>::Error;

    fn get_key<C: secp256k1::Signing>(
        &self,
        key_request: psbt::KeyRequest,
        secp: &secp256k1::Secp256k1<C>,
    ) -> std::result::Result<Option<PrivateKey>, Self::Error> {
        self.0
            .iter()
            .find_map(|xpriv| xpriv.get_key(key_request.clone(), secp).transpose())
            .transpose()
    }
}

fn single_seckey_to_map(sk: PrivateKey) -> BTreeMap<PublicKey, PrivateKey> {
    let mut map = BTreeMap::new();
    map.insert(sk.public_key(&EC), sk);
    map
}
fn single_seckeys_to_map(keys: Array) -> Result<BTreeMap<PublicKey, PrivateKey>> {
    keys.into_iter_of()
        .map(|sk| {
            let sk: PrivateKey = sk?;
            Ok((sk.public_key(&EC), sk))
        })
        .collect()
}
// TODO support BTreeMap<XOnlyPublicKey, PrivateKey>

// PSBT fields accessors
impl FieldAccess for Psbt {
    fn get_field(self, field: &Value) -> Option<Value> {
        Some(match field.as_str()? {
            "unsigned_tx" => self.unsigned_tx.into(),
            "version" => self.version.into(),
            "input" | "inputs" => self.inputs.into(),
            "output" | "outputs" => self.outputs.into(),
            "xpub" => self.xpub.into(),
            "unknown" => self.unknown.into(),
            "proprietary" => self.proprietary.into(),

            "txid" => self.unsigned_tx.compute_txid().into(),
            "utxos" => self
                .iter_funding_utxos()
                .map(|rtxo| Ok(rtxo?.clone()))
                .collect::<Result<Vec<_>>>()
                .ok()?
                .into(),
            "fee" => {
                // Returns -1 if the fee cannot be calculated or if it overflows i64 (~92 billion BTC, ~4400x more than can exists)
                // Use psbt::fee() if you prefer an exception to be raised instead.
                let fee = self.fee().ok();
                let fee = fee.and_then(|f| f.to_sat().try_into().ok());
                fee.unwrap_or(-1i64).into()
            }
            _ => {
                return None;
            }
        })
    }
}

impl From<psbt::Input> for Value {
    #[rustfmt::skip]
    fn from(input: psbt::Input) -> Self {
        let mut tags = Vec::with_capacity(21);
        add_opt_tags!(input, tags, witness_utxo, non_witness_utxo, sighash_type, redeem_script, witness_script, tap_key_sig, tap_internal_key, tap_merkle_root, final_script_sig, final_script_witness);
        add_tags!(input, tags, partial_sigs, tap_scripts, tap_script_sigs, tap_key_origins, ripemd160_preimages, sha256_preimages, hash160_preimages, hash256_preimages, bip32_derivation, unknown, proprietary);
        Value::array(tags)
    }
}
impl From<psbt::Output> for Value {
    #[rustfmt::skip]
    fn from(output: psbt::Output) -> Self {
        let mut tags = Vec::with_capacity(8);
        add_opt_tags!(output, tags, redeem_script, witness_script, tap_internal_key, tap_tree);
        add_tags!(output, tags, bip32_derivation, tap_key_origins, unknown, proprietary);
        Value::array(tags)
    }
}

impl_simple_to_value!(psbt::PsbtSighashType, ty, ty.to_u32());
impl_simple_to_value!(raw::Key, k, (k.type_value as i64, k.key));
impl_simple_to_value!(raw::ProprietaryKey, k, (k.prefix, k.subtype as i64, k.key));
impl_simple_to_value!(psbt::SignError, e, e.to_string());
impl_simple_to_value!(miniscript::psbt::PsbtSighashMsg, msg, msg.to_secp_msg());
impl_simple_to_value!(
    SigningKeys,
    pks,
    match pks {
        SigningKeys::Ecdsa(pks) => Value::from(pks),
        SigningKeys::Schnorr(pks) => Value::from(pks),
    }
);
#[rustfmt::skip]
impl_simple_to_value!(miniscript::psbt::Error, e, match e {
    miniscript::psbt::Error::InputError(err, inv) => (inv as i64, err.to_string()),
    non_input_err => (-1, non_input_err.to_string()),
});

impl PrettyDisplay for Psbt {
    const AUTOFMT_ENABLED: bool = false;

    #[rustfmt::skip]
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        let (newline_or_space, inner_indent, indent_w, inner_indent_w) =
            indentation_params(indent);
        let sep = format!("{newline_or_space}{:inner_indent_w$}", "");
        let mut is_first = true;

        write!(f, "psbt[")?;
        fmt_field!(self, unsigned_tx, f, sep, is_first, "{}", self.unsigned_tx.pretty(inner_indent));
        fmt_field!(self, version, f, sep, is_first);
        fmt_map_field!(self, xpub, f, sep, is_first, inner_indent,
            |f, (pk, src), _| write!(f, "[{}]{}", src.pretty(None), pk));
        fmt_map_field!(self, proprietary, f, sep, is_first, inner_indent);
        fmt_map_field!(self, unknown, f, sep, is_first, inner_indent);

        write!(f, ",{sep}\"inputs\": ")?;
        fmt_list(f, &mut self.inputs.iter(), inner_indent,
            |f, input, in_indent| write!(f, "{}", input.pretty(in_indent)))?;

        write!(f, ",{sep}\"outputs\": ")?;
        fmt_list(f, &mut self.outputs.iter(), inner_indent,
            |f, output, out_indent| write!(f, "{}", output.pretty(out_indent)))?;

        write!(f, "{newline_or_space}{:indent_w$}]", "")
    }
}

impl PrettyDisplay for psbt::Input {
    const AUTOFMT_ENABLED: bool = true;

    #[rustfmt::skip]
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        let (newline_or_space, inner_indent, indent_w, inner_indent_w) =
            indentation_params(indent);
        let sep = format!("{newline_or_space}{:inner_indent_w$}", "");
        let mut is_first = true;

        write!(f, "[")?;
        fmt_opt_field!(self, non_witness_utxo, f, sep, is_first, "{}", non_witness_utxo.pretty(None));
        fmt_opt_field!(self, witness_utxo, f, sep, is_first, "{}", witness_utxo.pretty(None));

        fmt_map_field!(self, partial_sigs, f, sep, is_first, inner_indent,
            |f, (pk, sig), _| write!(f, "{}: 0x{}", pk, sig));
        fmt_opt_field!(self, sighash_type, f, sep, is_first);
        fmt_opt_field!(self, redeem_script, f, sep, is_first, "{}", redeem_script.pretty(inner_indent));
        fmt_opt_field!(self, witness_script, f, sep, is_first, "{}", witness_script.pretty(inner_indent));
        fmt_map_field!(self, bip32_derivation, f, sep, is_first, inner_indent,
            |f, (pk, src), _| write!(f, "[{}]{}", src.pretty(None), pk));

        fmt_opt_field!(self, final_script_sig, f, sep, is_first, "{}", final_script_sig.pretty(None));
        fmt_opt_field!(self, final_script_witness, f, sep, is_first, "{}", final_script_witness.pretty(None));

        fmt_map_field!(self, ripemd160_preimages, f, sep, is_first, inner_indent,
            |f, (h, p), _| write!(f, "0x{}: 0x{}", h, p.as_hex()));
        fmt_map_field!(self, sha256_preimages, f, sep, is_first, inner_indent,
            |f, (h, p), _| write!(f, "0x{}: 0x{}", h, p.as_hex()));
        fmt_map_field!(self, hash160_preimages, f, sep, is_first, inner_indent,
            |f, (h, p), _| write!(f, "0x{}: 0x{}", h, p.as_hex()));
        fmt_map_field!(self, hash256_preimages, f, sep, is_first, inner_indent,
            |f, (h, p), _| write!(f, "0x{}: 0x{}", h, p.as_hex()));

        fmt_opt_field!(self, tap_key_sig, f, sep, is_first, "0x{}", tap_key_sig.to_vec().as_hex());
        fmt_map_field!(self, tap_script_sigs, f, sep, is_first, inner_indent,
            |f, ((pk, leaf_hash), sig), _| write!(f, "[{}, {}]: 0x{}", pk, leaf_hash, sig.to_vec().as_hex()));
        fmt_map_field!(self, tap_scripts, f, sep, is_first, inner_indent, // TODO leaf version not encoded
            |f, (ctrl, (script, _ver)), _| write!(f, "0x{}: {}", ctrl.serialize().as_hex(), script.pretty(None)));
        fmt_map_field!(self, tap_key_origins, f, sep, is_first, inner_indent, fmt_tap_key_origin);
        fmt_opt_field!(self, tap_internal_key, f, sep, is_first);
        fmt_opt_field!(self, tap_merkle_root, f, sep, is_first);

        fmt_map_field!(self, proprietary, f, sep, is_first, inner_indent);
        fmt_map_field!(self, unknown, f, sep, is_first, inner_indent);

        write!(f, "{newline_or_space}{:indent_w$}]", "")
    }
}

impl PrettyDisplay for psbt::Output {
    const AUTOFMT_ENABLED: bool = true;

    #[rustfmt::skip]
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        let (newline_or_space, inner_indent, indent_w, inner_indent_w) =
            indentation_params(indent);
        let sep = format!("{newline_or_space}{:inner_indent_w$}", "");
        let mut is_first = true;

        write!(f, "[")?;
        fmt_opt_field!(self, redeem_script, f, sep, is_first, "{}", redeem_script.pretty(inner_indent));
        fmt_opt_field!(self, witness_script, f, sep, is_first, "{}", witness_script.pretty(inner_indent));
        fmt_map_field!(self, bip32_derivation, f, sep, is_first, inner_indent,
            |f, (pk, src), _| write!(f, "[{}]{}", src.pretty(None), pk));
        fmt_opt_field!(self, tap_internal_key, f, sep, is_first);
        fmt_opt_field!(self, tap_tree, f, sep, is_first, "{}", tap_tree.pretty(inner_indent));
        fmt_map_field!(self, tap_key_origins, f, sep, is_first, inner_indent, fmt_tap_key_origin);
        fmt_map_field!(self, proprietary, f, sep, is_first, inner_indent);
        fmt_map_field!(self, unknown, f, sep, is_first, inner_indent);
        write!(f, "{newline_or_space}{:indent_w$}]", "")
    }
}

#[rustfmt::skip]
fn fmt_tap_key_origin<W: fmt::Write>(
    f: &mut W,
    (pk, (leaf_hashes, src)): (&XOnlyPublicKey, &(Vec<TapLeafHash>, bip32::KeySource)),
    _indent: Option<usize>,
) -> fmt::Result {
    match leaf_hashes.len() {
        0 => write!(f, "[{}]{}", src.pretty(None), pk),
        1 => write!(f, "[{}]{}: {}", src.pretty(None), pk, leaf_hashes[0].pretty(None)),
        _ => write!(f, "[{}]{}: {}", src.pretty(None), pk, leaf_hashes.pretty(None)),
    }
}
impl_simple_pretty!(raw::Key, k, "[{}, 0x{}]", k.type_value, k.key.as_hex());
impl_simple_pretty!(
    raw::ProprietaryKey,
    k,
    "[0x{}, {}, 0x{}]",
    k.prefix.as_hex(),
    k.subtype,
    k.key.as_hex()
);
impl_simple_pretty!(
    &bip32::KeySource,
    (fp, path),
    "{}{}{}",
    fp,
    if path.is_empty() { "" } else { "/" },
    path
);
