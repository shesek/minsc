use std::convert::{TryFrom, TryInto};

use miniscript::bitcoin::{
    absolute::LockTime, address, taproot::TaprootSpendInfo, transaction::Version, Address, Amount,
    Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WitnessProgram,
    WitnessVersion,
};

use crate::util::DescriptorExt;

use crate::runtime::{Array, Error, Result, Scope, Value};
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
    scope.set_fn("script", fns::script).unwrap();
    scope.set_fn("scriptPubKey", fns::scriptPubKey).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;
    /// Generate an address
    /// address(Script|Descriptor|PubKey|TapInfo|String|Address) -> Address
    pub fn address(args: Array, _: &Scope) -> Result<Value> {
        let (spk, network): (Value, Option<Network>) = args.args_into()?;
        let spk = spk.into_spk()?;
        let network = network.unwrap_or(Network::Signet);

        Ok(Address::from_script(&spk, network)
            .map_err(|_| Error::NotAddressable(spk))?
            .into())
    }

    /// script(Script|Bytes) -> Script
    pub fn script(args: Array, _: &Scope) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::Script(script) => script.into(),
            Value::Bytes(bytes) => ScriptBuf::from(bytes).into(),
            other => bail!(Error::InvalidScriptConstructor(other)),
        })
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
}

impl Value {
    /// Get the scriptPubKey representation of this Value
    pub fn into_spk(self) -> Result<ScriptBuf> {
        Ok(match self {
            // Raw scripts are returned as-is
            Value::Script(script) => script,
            // Descriptors (or values coercible into them) are converted into their scriptPubKey
            v @ Value::Descriptor(_) | v @ Value::PubKey(_) => v.into_desc()?.to_script_pubkey()?,
            // TapInfo returns the output V1 witness program of the output key
            Value::TapInfo(tapinfo) => ScriptBuf::new_witness_program(&WitnessProgram::new(
                WitnessVersion::V1,
                &tapinfo.output_key().serialize(),
            )?),
            // Addresses can be provided as an Address or String
            v @ Value::Address(_) | v @ Value::String(_) => v.into_address()?.script_pubkey(),
            v => bail!(Error::NoSpkRepr(v)),
        })
    }
    pub fn into_address(self) -> Result<Address> {
        self.try_into()
    }
    pub fn into_tapinfo(self) -> Result<TaprootSpendInfo> {
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
                _ => bail!(Error::NotTapInfoLike(Value::Descriptor(desc))),
            },
            v => bail!(Error::NotTapInfoLike(v)),
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
            v => bail!(Error::NotAddress(v)),
        })
    }
}

// From tagged [ "version": $version, "locktime": $locktime, "inputs": [ .. ], "outputs": [ .. ] ]
impl TryFrom<Value> for Transaction {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        let mut tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        value.for_each_unique_tag(|tag, val| {
            match tag {
                "version" => tx.version = Version::try_from(val)?,
                "locktime" => tx.lock_time = LockTime::try_from(val)?,
                "inputs" => tx.input = val.into_vec_of()?,
                "outputs" => tx.output = val.into_vec_of()?,
                _ => bail!(Error::TagUnknown),
            }
            Ok(())
        })?;

        Ok(tx)
    }
}

// From tagged [ "prevout": $txid:$vout, "sequence": $sequence ] or just the $txid:vout
impl TryFrom<Value> for TxIn {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        let (previous_output, sequence) = if value.is_tagged_or_empty() {
            value.tagged_into2_default("prevout", "sequence")?
        } else {
            (OutPoint::try_from(value)?, Sequence::default())
        };

        Ok(TxIn {
            previous_output,
            sequence,
            ..Default::default()
        })
    }
}

// From tagged [ "scriptPubKey": $address, "amount": $amount ] or $address:$amount
impl TryFrom<Value> for TxOut {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        let (spk, amount): (Value, Amount) = val.tagged_or_tuple("scriptPubKey", "amount")?;
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
        Ok(Txid::from_raw_hash(val.try_into()?))
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
        Ok(Sequence(val.into_u32()?))
    }
}
