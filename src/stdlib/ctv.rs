use std::convert::TryInto;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Transaction, TxIn};
use miniscript::bitcoin;

use crate::parser::Library;
use crate::runtime::scope::{Mutable, ScopeRef};
use crate::runtime::{Error, Execute, Result, Value};

lazy_static! {
    static ref MINSC_CTV_LIB: Library = r#"
        OP_CHECKTEMPLATEVERIFY = OP_NOP4;
        OP_CTV = OP_CHECKTEMPLATEVERIFY;

        fn ctv($tx) = `ctv::hash($tx) OP_CHECKTEMPLATEVERIFY OP_DROP`;
        fn ctv::verify($tx) = `ctv::hash($tx) OP_CHECKTEMPLATEVERIFY`;
    "#
    .parse()
    .unwrap();
}

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    {
        let mut scope = scope.borrow_mut();
        scope.set_fn("ctv::hash", fns::hash).unwrap();
    }
    MINSC_CTV_LIB.exec(scope).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;
    use crate::runtime::Array;

    /// ctv::hash(Transaction, Int input_index=0) -> Bytes
    ///
    /// Example: ctv::hash([ "outputs": [ wpkh($bob_pk): 10000 sats, wpkh($alice_pk): 25000 sats ] ])
    pub fn hash(args: Array, _: &ScopeRef) -> Result<Value> {
        let (tx, input_index): (_, Option<u32>) = args.args_into()?;
        let mut tx = match tx {
            Value::Psbt(psbt) => psbt.unsigned_tx,
            Value::Transaction(tx) => tx,
            other => other.try_into()?,
        };

        ensure!(!tx.output.is_empty(), Error::InvalidArguments);

        // Add a default input if none exists. The only input field that matters for
        // the CTV hash is the nSequence.
        if tx.input.is_empty() {
            tx.input.push(TxIn::default());
        }

        Ok(get_ctv_hash(&tx, input_index.unwrap_or(0)).into())
    }
}

// Based on https://github.com/sapio-lang/sapio/blob/master/sapio-base/src/util.rs,
// with support for scriptSigs
fn get_ctv_hash(tx: &Transaction, input_index: u32) -> sha256::Hash {
    use bitcoin::consensus::encode::Encodable;

    let mut ctv_hash = sha256::Hash::engine();
    tx.version.consensus_encode(&mut ctv_hash).unwrap();
    tx.lock_time.consensus_encode(&mut ctv_hash).unwrap();
    // If any of the inputs scriptSigs are non-empty, all of them are hashed - including empty ones
    // If no scriptSigs are set, this hash is skipped entirely
    if tx.input.iter().any(|i| !i.script_sig.is_empty()) {
        let mut enc = sha256::Hash::engine();
        for i in &tx.input {
            i.script_sig.consensus_encode(&mut enc).unwrap();
        }
        sha256::Hash::from_engine(enc)
            .to_byte_array()
            .consensus_encode(&mut ctv_hash)
            .unwrap();
    }
    (tx.input.len() as u32)
        .consensus_encode(&mut ctv_hash)
        .unwrap();
    {
        let mut enc = sha256::Hash::engine();
        for seq in tx.input.iter().map(|i| i.sequence) {
            seq.consensus_encode(&mut enc).unwrap();
        }
        sha256::Hash::from_engine(enc)
            .to_byte_array()
            .consensus_encode(&mut ctv_hash)
            .unwrap();
    }

    (tx.output.len() as u32)
        .consensus_encode(&mut ctv_hash)
        .unwrap();

    {
        let mut enc = sha256::Hash::engine();
        for out in tx.output.iter() {
            out.consensus_encode(&mut enc).unwrap();
        }
        sha256::Hash::from_engine(enc)
            .to_byte_array()
            .consensus_encode(&mut ctv_hash)
            .unwrap();
    }
    input_index.consensus_encode(&mut ctv_hash).unwrap();
    sha256::Hash::from_engine(ctv_hash)
}
