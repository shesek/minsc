use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv};
use bitcoin::psbt::{self, Psbt};
use bitcoin::{secp256k1, PrivateKey, PublicKey, TxIn, TxOut};
use miniscript::psbt::PsbtExt;

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
            "inputs" => {
                for (vin, in_tags) in mapped_or_all(val, psbt.inputs.len())? {
                    update_input(mut_input(psbt, vin)?, in_tags)?;
                }
            }
            "outputs" => {
                for (vout, out_tags) in mapped_or_all(val, psbt.outputs.len())? {
                    update_output(mut_output(psbt, vout)?, out_tags)?;
                }
            }
            "combine" => psbt.combine(val.try_into()?)?,

            // Shortcut for setting just the `witness_utxo` of multiple inputs
            // (non-segwit inputs may be set manually through `inputs`)
            "utxos" | "witness_utxos" => {
                for (vin, spent_utxo) in mapped_or_all(val, psbt.inputs.len())? {
                    mut_input(psbt, vin)?.witness_utxo = Some(spent_utxo);
                }
            }

            // Shortcut for adding a Coin as a Transaction input and as a Psbt Input with the `witness_utxo` field.
            // (non-segwit inputs may be set manually through `inputs`)
            //
            // Coin consists of a tx input (or just its outpoint) alongside the spent txout.
            // All of the following are valid Coin definitions:
            // [ "input": [ "prevout": $txid:0, "sequence": 0, ... ], "utxo": [ "scriptPubKey": wpkh($alice), "amount": 0.01 BTC ] ]
            // [ "input": $txid:0, "utxo": wpkh($alice):1000000 ]
            // [ $txid:0, wpkh($alice):0.1 BTC]
            // ($txid:0):(wpkh($alice):0.1 BTC)
            // $outpoint:$utxo
            "coins" => {
                for PsbtCoin(input, spent_utxo) in val.into_vec_of()? {
                    psbt.unsigned_tx.input.push(input);
                    let mut psbt_input = psbt::Input::default();
                    psbt_input.witness_utxo = Some(spent_utxo);
                    psbt.inputs.push(psbt_input);
                }
            }

            _ => bail!(Error::TagUnknown),
        }
        Ok(())
    })
}

fn update_input(psbt_input: &mut psbt::Input, tags: Array) -> Result<()> {
    tags.for_each_tag(|tag, val| {
        match tag {
            "non_witness_utxo" => psbt_input.non_witness_utxo = Some(val.try_into()?),
            "witness_utxo" | "utxo" => psbt_input.witness_utxo = Some(val.try_into()?),
            "partial_sigs" => psbt_input.partial_sigs = val.try_into()?,
            "sighash_type" => psbt_input.sighash_type = Some(val.try_into()?),
            "redeem_script" => psbt_input.redeem_script = Some(val.try_into()?),
            "witness_script" => psbt_input.witness_script = Some(val.try_into()?),
            "bip32_derivation" | "sources" => psbt_input.bip32_derivation = bip32_derivation(val)?,
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
            _ => bail!(Error::TagUnknown),
        }
        Ok(())
    })
}

fn update_output(psbt_output: &mut psbt::Output, tags: Array) -> Result<()> {
    tags.for_each_tag(|tag, val| {
        match tag {
            "redeem_script" => psbt_output.redeem_script = Some(val.try_into()?),
            "witness_script" => psbt_output.witness_script = Some(val.try_into()?),
            "bip32_derivation" => psbt_output.bip32_derivation = val.try_into()?,
            "tap_internal_key" => psbt_output.tap_internal_key = Some(val.try_into()?),
            // TOOD "tap_tree" => psbt_output.tap_internal_key = Some(val.try_into()?),
            "tap_key_origins" => psbt_output.tap_key_origins = val.try_into()?,
            "proprietary" => psbt_output.proprietary = val.try_into()?,
            "unknown" => psbt_output.unknown = val.try_into()?,
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

struct PsbtCoin(TxIn, TxOut);
impl TryFrom<Value> for PsbtCoin {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        let (input, spent_utxo) = value.tagged_or_tuple("input", "utxo")?;
        Ok(Self(input, spent_utxo))
    }
}

fn bip32_derivation(
    val: Value,
) -> Result<BTreeMap<secp256k1::PublicKey, (Fingerprint, DerivationPath)>> {
    // Intermediate decoding into btc::KeySource for specialized decoding logic,
    // then into the psbt::Inputs's bip32_derivation field type.
    Ok(Vec::try_from(val)?
        .into_iter()
        .map(|KeyWithSource(pk, fingerprint, path)| (pk, (fingerprint, path)))
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
            // May be provided as a tuple/tagged array mapping from `pk` to the `source`,
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
