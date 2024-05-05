use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Transaction, TxIn};
use miniscript::bitcoin;

use crate::parser;
use crate::runtime::{Error, Execute, Result, Scope, Value};

lazy_static! {
    static ref MINSC_CTV_LIB: parser::Library = r#"
        OP_CHECKTEMPLATEVERIFY = script(0xb3);
        OP_CTV = OP_CHECKTEMPLATEVERIFY;

        fn ctv($tx) = `ctvHash($tx) OP_CHECKTEMPLATEVERIFY OP_DROP`;
    "#
    .parse()
    .unwrap();
}

pub fn attach_stdlib(scope: &mut Scope) {
    scope.set_fn("ctvHash", fns::ctvHash).unwrap();

    MINSC_CTV_LIB.exec(scope).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;
    use crate::runtime::Array;

    /// ctvHash(Array tx, Number input_index=0) -> Hash
    ///
    /// Example: ctvHash([ "version": 1, "outputs": [ $bob_pk: 10000 sats, $alice_pk: 25000 sats ] ])
    pub fn ctvHash(args: Array, _: &Scope) -> Result<Value> {
        let (mut tx, input_index): (Transaction, Option<u32>) = args.args_into()?;

        // Add a default input if none exists. The only input field that matters for
        // the CTV hash is the nSequence.
        if tx.input.is_empty() {
            tx.input.push(TxIn::default());
        }
        ensure!(tx.output.len() > 0, Error::InvalidArguments);

        let hash = get_ctv_hash(&tx, input_index.unwrap_or(0));
        Ok(hash.into())
    }
}

// Copied from https://github.com/sapio-lang/sapio/blob/master/sapio-base/src/util.rs
fn get_ctv_hash(tx: &Transaction, input_index: u32) -> sha256::Hash {
    use bitcoin::consensus::encode::Encodable;

    let mut ctv_hash = sha256::Hash::engine();
    tx.version.consensus_encode(&mut ctv_hash).unwrap();
    tx.lock_time.consensus_encode(&mut ctv_hash).unwrap();
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
