use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::{fmt, str::FromStr};

use bitcoin::bip32::{self, Xpriv};
use bitcoin::hex::DisplayHex;
use bitcoin::psbt::{self, raw, Psbt, SigningErrors, SigningKeys, SigningKeysMap};
use bitcoin::taproot::{self, LeafVersion, TapLeafHash};
use bitcoin::{hashes, secp256k1, PrivateKey, PublicKey, TxIn, TxOut};
use miniscript::psbt::{PsbtExt, PsbtInputExt, PsbtOutputExt};
use miniscript::DescriptorPublicKey;

use crate::runtime::{Array, Error, FromValue, Mutable, Number::Int, Result, ScopeRef, Value};
use crate::util::{
    self, DescriptorExt, DescriptorPubKeyExt, PrettyDisplay, PsbtTaprootExt, TapInfoExt, EC,
};

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();
    scope.set_fn("psbt", fns::create).unwrap(); // alias
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
    scope
        .set_fn("psbt::extract_non_ms", fns::extract_non_ms)
        .unwrap();

    scope.set_fn("psbt::unsigned_tx", fns::unsigned_tx).unwrap();
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

    /// psbt::create(Transaction|Bytes|Array<Tagged>) -> Psbt
    /// Aliased as psbt()
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
            Ok(()) => vec![],
            Err(errors) => errors.iter().map(|e| Value::from(e.to_string())).collect(),
        };
        Ok(Value::array_of((psbt, errors)))
    }

    // psbt::sign(Psbt, Xpriv|Array<Xpriv>|Array<SinglePk:SingleSk> sign_keys, Bool finalize=false) -> Psbt
    //
    // Attempt to sign all transaction inputs, raising an error if any fail.
    pub fn sign(args: Array, _: &ScopeRef) -> Result<Value> {
        let (mut psbt, keys, finalize): (_, _, Option<bool>) = args.args_into()?;

        let (_signed, failed) = sign_psbt(&mut psbt, keys)?;
        ensure!(failed.is_empty(), Error::PsbtSigning(failed));
        // XXX check signed?

        if finalize.unwrap_or(false) {
            psbt.finalize_mut(&EC).map_err(Error::PsbtFinalize)?;
        }

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

        let signed = signed
            .into_iter()
            .map(|(input_index, pks)| {
                let pks: Vec<Value> = match pks {
                    SigningKeys::Ecdsa(pks) => pks.into_iter().map(Into::into).collect(),
                    SigningKeys::Schnorr(pks) => pks.into_iter().map(Into::into).collect(),
                };
                Value::array_of((input_index, pks))
            })
            .collect::<Vec<_>>();
        let failed = failed
            .into_iter()
            .map(|(input_index, error)| Value::array_of((input_index, error.to_string())))
            .collect::<Vec<_>>();

        Ok(Value::array_of((psbt, signed, failed)))
    }

    /// psbt::extract(Psbt, Bool finalize=false) -> Transaction
    ///
    /// Extract the PSBT finalized transaction. Will run the Miniscript interpreter sanity checks.  
    /// Also possible using `tx(Psbt)` (without the `finalize` option, for pre-finalized PSBT only)
    pub fn extract(args: Array, _: &ScopeRef) -> Result<Value> {
        let (mut psbt, finalize): (Psbt, Option<bool>) = args.args_into()?;
        if finalize.unwrap_or(false) {
            psbt.finalize_mut(&EC).map_err(Error::PsbtFinalize)?;
        }
        // Uses rust-miniscript's PsbtExt::extract(), which only works with Miniscript-compatible Scripts
        Ok(psbt.extract(&EC)?.into())
    }

    /// psbt::extract_non_ms(Psbt) -> Transaction
    ///
    /// Extract the PSBT finalized transaction, without running the Miniscript interpreter checks.
    pub fn extract_non_ms(args: Array, _: &ScopeRef) -> Result<Value> {
        let psbt: Psbt = args.arg_into()?;
        // Uses rust-bitcoin's Psbt::extract_tx(). Unlike rust-miniscript's PsbtExt::extract(), this does not run the
        // interpreter checks and can be used with manual finalization of arbitrary (non-Miniscript-compatible) Script.
        // Also unlike it, this includes a check for absurdly high fees (over 25k sat/vb) -- TODO make fee check configurable, support in both variants
        Ok(psbt.extract_tx()?.into())
    }

    /// psbt::unsigned_tx(Psbt) -> Transaction
    ///
    /// Get the PSBT's unsigned transaction (PSBT_GLOBAL_UNSIGNED_TX)
    pub fn unsigned_tx(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(args.arg_into::<Psbt>()?.unsigned_tx.into())
    }

    /// psbt::fee(Psbt) -> Int
    pub fn fee(args: Array, _: &ScopeRef) -> Result<Value> {
        args.arg_into::<Psbt>()?.fee()?.to_sat().try_into()
    }

    /// psbt::sighash(Psbt, Int input_index, Bytes tapleaf_hash=None) -> Bytes
    pub fn sighash(args: Array, _: &ScopeRef) -> Result<Value> {
        use bitcoin::sighash::SighashCache;
        let (psbt, input_index, tapleaf_hash): (Psbt, _, _) = args.args_into()?;
        let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

        let sighash_msg = psbt.sighash_msg(input_index, &mut sighash_cache, tapleaf_hash)?;
        Ok(sighash_msg.to_secp_msg()[..].to_vec().into())
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
                // Keys provided as tagged array of [ $single_pk1:$single_sk1, $single_pk2:$single_sk2, ... ]
                Value::Array(_) => {
                    psbt.sign(&BTreeMap::<PublicKey, PrivateKey>::try_from(keys)?, &EC)
                }
                // Keys provided as [ $xpriv1, $xpriv2, ... ]
                Value::SecKey(_) => psbt.sign(&XprivSet(keys.try_into()?), &EC),
                _ => bail!(Error::PsbtInvalidSignKeys),
            }
        }
        // Key provided as a single Xpriv
        Value::SecKey(_) => psbt.sign(&Xpriv::try_from(keys_val)?, &EC),
        // TODO support signing with MultiXpriv
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
            "xpub" => psbt.xpub = xpub_map(val)?,
            "proprietary" => psbt.proprietary = val.try_into()?,
            "unknown" => psbt.unknown = val.try_into()?,
            "inputs" => {
                for (vin, in_tags) in mapped_or_all(val, psbt.inputs.len())? {
                    let psbt_input = psbt
                        .inputs
                        .get_mut(vin)
                        .ok_or(Error::PsbtInputNotFound(vin))?;
                    update_input(psbt_input, in_tags)?;
                }
            }
            "outputs" => {
                for (vout, out_tags) in mapped_or_all(val, psbt.outputs.len())? {
                    let psbt_output = psbt
                        .outputs
                        .get_mut(vout)
                        .ok_or(Error::PsbtOutputNotFound(vout))?;
                    update_output(psbt_output, out_tags)?;
                }
            }
            "combine" => psbt.combine(val.try_into()?)?,

            // Expected to be provided as the first tag, which is handled and stripped by psbt_from_tags()
            "unsigned_tx" => bail!(Error::PsbtTxTagInvalidPosition),

            _ => bail!(Error::TagUnknown),
        }
        Ok(())
    })
}

fn update_input(psbt_input: &mut psbt::Input, tags: Array) -> Result<()> {
    let mut descriptor = None;
    let mut tapinfo = None;
    let mut utxo_amount = None;
    tags.for_each_unique_tag(|tag, val| {
        match tag {
            "partial_sigs" => psbt_input.partial_sigs = val.try_into()?,
            "sighash_type" => psbt_input.sighash_type = Some(val.try_into()?),
            "redeem_script" => psbt_input.redeem_script = Some(val.try_into()?),
            "witness_script" => psbt_input.witness_script = Some(val.try_into()?),
            "bip32_derivation" => psbt_input.bip32_derivation = bip32_derivation_map(val)?,
            "final_script_sig" => psbt_input.final_script_sig = Some(val.try_into()?),
            "final_script_witness" => psbt_input.final_script_witness = Some(val.try_into()?),
            "ripemd160_preimages" => psbt_input.ripemd160_preimages = hash_preimages(val)?,
            "sha256_preimages" => psbt_input.sha256_preimages = hash_preimages(val)?,
            "hash160_preimages" => psbt_input.hash160_preimages = hash_preimages(val)?,
            "hash256_preimages" => psbt_input.hash256_preimages = hash_preimages(val)?,
            "tap_key_sig" => psbt_input.tap_key_sig = Some(val.try_into()?),
            "tap_script_sigs" => psbt_input.tap_script_sigs = val.try_into()?,
            "tap_scripts" => psbt_input.tap_scripts = tap_scripts_map(val)?,
            "tap_key_origins" => psbt_input.tap_key_origins = tap_key_origins_map(val)?,
            "tap_internal_key" => psbt_input.tap_internal_key = Some(val.try_into()?),
            "tap_merkle_root" => psbt_input.tap_merkle_root = Some(val.try_into()?),
            "proprietary" => psbt_input.proprietary = val.try_into()?,
            "unknown" => psbt_input.unknown = val.try_into()?,
            "non_witness_utxo" => psbt_input.non_witness_utxo = Some(val.try_into()?),
            "witness_utxo" | "utxo" => {
                // If the UTXO was specified using a Descriptor or a TaprootSpendInfo, keep
                // a copy of them around prior to converting them to a TxOut scriptPubKey
                if let Value::Array(arr) = &val {
                    match arr.first() {
                        Some(Value::Descriptor(desc)) if descriptor.is_none() => {
                            descriptor = Some(desc.definite()?)
                        }
                        Some(Value::TapInfo(tap)) if tapinfo.is_none() => {
                            tapinfo = Some(tap.clone())
                        }
                        _ => {}
                    }
                }
                psbt_input.witness_utxo = Some(val.try_into()?);
            }

            // Keep the descriptor, tapinfo and amount to later construct the utxo and populate the PSBT fields
            "descriptor" => descriptor = Some(val.try_into()?),
            "tap_info" => tapinfo = Some(val.try_into()?),
            "amount" | "utxo_amount" => utxo_amount = Some(val.try_into()?),

            _ => bail!(Error::TagUnknown),
        }
        Ok(())
    })?;

    // Populate PSBT fields using the Descriptor/TaprootSpendInfo, if available
    let mut utxo_spk = None;
    if let Some(descriptor) = &descriptor {
        psbt_input.update_with_descriptor_unchecked(descriptor)?;
        utxo_spk = Some(descriptor.script_pubkey());
    } else if let Some(tapinfo) = &tapinfo {
        psbt_input.update_with_taproot(tapinfo)?;
        utxo_spk = Some(tapinfo.script_pubkey());
    }

    // Automatically fill in the witness_utxo if utxo amount and scriptPubKey are known
    if let (None, Some(utxo_amount), Some(utxo_spk)) =
        (&psbt_input.witness_utxo, utxo_amount, utxo_spk)
    {
        psbt_input.witness_utxo = Some(TxOut {
            script_pubkey: utxo_spk,
            value: utxo_amount,
        });
    }

    Ok(())
}

fn update_output(psbt_output: &mut psbt::Output, tags: Array) -> Result<()> {
    tags.for_each_unique_tag(|tag, val| {
        match tag {
            "redeem_script" => psbt_output.redeem_script = Some(val.try_into()?),
            "witness_script" => psbt_output.witness_script = Some(val.try_into()?),
            "bip32_derivation" => psbt_output.bip32_derivation = bip32_derivation_map(val)?,
            "tap_internal_key" => psbt_output.tap_internal_key = Some(val.try_into()?),
            "tap_tree" => psbt_output.tap_tree = Some(val.try_into()?),
            "tap_key_origins" => psbt_output.tap_key_origins = tap_key_origins_map(val)?,
            "proprietary" => psbt_output.proprietary = val.try_into()?,
            "unknown" => psbt_output.unknown = val.try_into()?,
            "descriptor" => psbt_output
                .update_with_descriptor_unchecked(&val.try_into()?)
                .map(|_| ())?,
            "tap_info" => psbt_output
                .update_with_taproot(&val.try_into()?)
                .map(|_| ())?,
            // note: PsbtTxOut calls update_with{descriptor,taproot}() itself and does not forward the "descriptor"
            // and "tap_info" tags here. This will need to be refactored if anything more complex is done here.
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
    if let Some(Value::Array(first_el)) = arr.first() {
        if let Some(Value::Number(_)) = first_el.first() {
            // Provided as [ 0: $val0, 1: $val1, ... ]
            return arr.try_into();
        }
    }
    // Provided as [ $val0, $val1, ... ]
    ensure!(
        arr.len() == expected_all_length,
        Error::InvalidLength(arr.len(), expected_all_length)
    );
    Ok(Vec::<T>::try_from(arr)?.into_iter().enumerate().collect())
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
            "psbt_version" => psbt_tags.push(Value::array_of(("version", val))),
            other_tag => psbt_tags.push(Value::array_of((other_tag, val))),
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

        let arr = value.into_array()?;
        if arr.len() == 2 && arr.get(1).is_some_and(Value::is_number) {
            // Tx input provided as a simple $txid:$vout tuple with just the prevout
            tx_input.previous_output = Value::Array(arr).try_into()?;
        } else {
            // Tx input and PSBT metadata provided as a tagged list
            arr.for_each_unique_tag(|tag, val| {
                match tag {
                    // The entire input may be provided under the "input" tag, or alternatively as individual fields
                    // (script_sig and witness are not settable - the constructed tx should be unsigned)
                    "input" => tx_input = val.try_into()?,
                    "prevout" => tx_input.previous_output = val.try_into()?,
                    "sequence" => tx_input.sequence = val.try_into()?,

                    // Collect other PSBT tags to forward to update_input()
                    other_tag => psbt_input_tags.push(Value::array_of((other_tag, val))),
                }
                Ok(())
            })?;

            ensure!(
                tx_input.previous_output != Default::default(),
                Error::PsbtTxInMissingFields
            );

            update_input(&mut psbt_input, psbt_input_tags)?;
        }

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
        if arr.len() == 2 && arr.get(1).is_some_and(Value::is_number) {
            // Tx output provided as a $scriptPubKeyLike:$amount tuple
            let (spk_like, amount): (Value, _) = arr.try_into()?;

            // If the scriptPubKey was specified using a Descriptor or a TaprootSpendInfo, also use them to populate the PSBT fields
            match &spk_like {
                Value::Descriptor(descriptor) => {
                    psbt_output.update_with_descriptor_unchecked(&descriptor.definite()?)?;
                }
                Value::TapInfo(tapinfo) => {
                    psbt_output.update_with_taproot(&tapinfo)?;
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
                    // The entire output may be provided under the "output" tag, or alternatively as individual fields
                    "output" => tx_output = Some(val.try_into()?),
                    "amount" => amount = Some(val.try_into()?),
                    "script_pubkey" => spk = Some(val.try_into()?),

                    // Use the Descriptor to populate the PSBT fields and to construct the scriptPubKey
                    "descriptor" => {
                        let descriptor = val.try_into()?;
                        psbt_output.update_with_descriptor_unchecked(&descriptor)?;
                        spk.get_or_insert_with(|| descriptor.script_pubkey());
                    }

                    // Use the TaprootSpendInfo to populate the PSBT fields and to construct the scriptPubKey
                    "tap_info" => {
                        let tapinfo = val.try_into()?;
                        psbt_output.update_with_taproot(&tapinfo)?;
                        spk.get_or_insert_with(|| tapinfo.script_pubkey());
                    }

                    // Collect other PSBT tags to forward to update_output()
                    other_tag => psbt_output_tags.push(Value::array_of((other_tag, val))),
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
) -> Result<BTreeMap<bitcoin::XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)>> {
    val.into_array()?
        .into_iter()
        .map(|el| {
            let (pk, pk_val): (DescriptorPublicKey, _) = el.try_into()?;
            let (leaf_hashes, key_source) = match pk_val {
                // Provided as an explicit map from pubkeys to a tuple of (leaf_hashes,(bip32_fingerprint, path))
                // Matches the underlying structure used by rust-bitcoin.
                // For example: "tap_key_origins": [ SINGLE_PUBKEY: [ [ LEAF_HASH1, LEAF_HASH2 ], 0xFINGERPRINT:[0,100]] ] ]
                Value::Array(arr) if !arr.is_empty() && arr[0].is_array() => arr.try_into()?,

                // Provided as a map from xpubs (with associated key source) to the leaf_hashes
                // For example: "tap_key_origins": [ xpubAAA/0/100: [ LEAF_HASH1, LEAF_HASH2 ] ]
                Value::Array(arr) => {
                    let leaf_hashes = arr.try_into()?;
                    let fingerprint = pk.master_fingerprint();
                    let path = pk.full_derivation_path().ok_or(Error::InvalidMultiXpub)?;
                    (leaf_hashes, (fingerprint, path))
                }

                // Provided as a map from xpubs (with associated key source) to a single script to compute the leaf hash for
                // For example: "tap_key_origins": [ xpubAAA/0/100: `xpubAAA/0/100 OP_CHECKSIG` ]
                Value::Script(script) => {
                    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
                    let fingerprint = pk.master_fingerprint();
                    let path = pk.full_derivation_path().ok_or(Error::InvalidMultiXpub)?;
                    (vec![leaf_hash], (fingerprint, path))
                }

                other => bail!(Error::InvalidValue(other.into())),
            };
            let final_pk = pk.derive_definite()?;
            Ok((final_pk.into(), (leaf_hashes, key_source)))
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
            Value::Number(Int(num)) => Self::from_u32(num.try_into()?),
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

// GetKey wrapper around Vec<Xpriv>, needed as a workaround for https://github.com/rust-bitcoin/rust-bitcoin/pull/2850
// Could otherwise directly use `psbt.sign(&Vec::<Xpriv>::try_from(seckeys)?, &EC)`
struct XprivSet(Vec<Xpriv>);
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

impl PrettyDisplay for Psbt {
    const AUTOFMT_ENABLED: bool = false;

    #[rustfmt::skip]
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        let (newline_or_space, inner_indent, indent_w, inner_indent_w) =
            util::indentation_params(indent);
        let sep = format!("{newline_or_space}{:inner_indent_w$}", "");
        let mut is_first = true;

        write!(f, "psbt [")?;
        fmt_field!(self, unsigned_tx, f, sep, is_first, "{}", self.unsigned_tx.pretty(inner_indent));
        fmt_field!(self, version, f, sep, is_first);
        fmt_map_field!(self, xpub, f, sep, is_first, inner_indent,
            |f, (pk, src), _| write!(f, "[{}/{}]{}", src.0, src.1, pk));
        fmt_map_field!(self, proprietary, f, sep, is_first, inner_indent);
        fmt_map_field!(self, unknown, f, sep, is_first, inner_indent);

        write!(f, ",{sep}\"inputs\": ")?;
        util::fmt_list(f, &mut self.inputs.iter(), inner_indent,
            |f, input, in_indent| write!(f, "{}", input.pretty(in_indent)))?;

        write!(f, ",{sep}\"outputs\": ")?;
        util::fmt_list(f, &mut self.outputs.iter(), inner_indent,
            |f, output, out_indent| write!(f, "{}", output.pretty(out_indent)))?;

        write!(f, "{newline_or_space}{:indent_w$}]", "")
    }
}

impl PrettyDisplay for psbt::Input {
    const AUTOFMT_ENABLED: bool = true;

    #[rustfmt::skip]
    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        let (newline_or_space, inner_indent, indent_w, inner_indent_w) =
            util::indentation_params(indent);
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
            |f, (pk, src), _| write!(f, "[{}/{}]{}", src.0, src.1, pk));

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
        fmt_map_field!(self, tap_key_origins, f, sep, is_first, inner_indent,
            |f, (pk, (hashes, src)), _| write!(f, "[{}/{}]{}: {}", src.0, src.1, pk, hashes.pretty(None)));
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
            util::indentation_params(indent);
        let sep = format!("{newline_or_space}{:inner_indent_w$}", "");
        let mut is_first = true;

        write!(f, "[")?;
        fmt_opt_field!(self, redeem_script, f, sep, is_first, "{}", redeem_script.pretty(inner_indent));
        fmt_opt_field!(self, witness_script, f, sep, is_first, "{}", witness_script.pretty(inner_indent));
        fmt_map_field!(self, bip32_derivation, f, sep, is_first, inner_indent,
            |f, (pk, src), _| write!(f, "[{}/{}]{}", src.0, src.1, pk));
        fmt_opt_field!(self, tap_internal_key, f, sep, is_first);
        fmt_opt_field!(self, tap_tree, f, sep, is_first, "{}", tap_tree.pretty(inner_indent));
        fmt_map_field!(self, tap_key_origins, f, sep, is_first, inner_indent,
            |f, (pk, (hashes, src)), _| write!(f, "[{}/{}]{}: {}", src.0, src.1, pk, hashes.pretty(None)));
        fmt_map_field!(self, proprietary, f, sep, is_first, inner_indent);
        fmt_map_field!(self, unknown, f, sep, is_first, inner_indent);
        write!(f, "{newline_or_space}{:indent_w$}]", "")
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
