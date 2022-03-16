use std::convert::TryInto;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Transaction, TxIn, TxOut};
use miniscript::bitcoin;

use crate::runtime::Execute;
use crate::{ast, parse_lib, Error, Policy, Result, Scope, Value};

lazy_static! {
    static ref MINSC_CTV_LIB: ast::Library = parse_lib(
        r#"
        OP_CHECKTEMPLATEVERIFY = rawscript(0xb3);
        OP_CTV = OP_CHECKTEMPLATEVERIFY;

        fn ctv($tx) = `ctvHash($tx) OP_CHECKTEMPLATEVERIFY OP_DROP`;

        // Utility functions for tagged arrays with a more DSL-y syntax
        fn txVersion($version) = [ "version", $version ];
        fn txLocktime($locktime) = [ "locktime", $locktime ];
        fn txInSeq($seq) = [ "input", $seq ];
        fn txIn() = [ "input" ];
        fn txOut($spk, $amount) = [ "output", $spk, $amount ];
        "#
    )
    .unwrap();
}

pub fn attach_stdlib(scope: &mut Scope) {
    scope.set_fn("ctvHash", fns::ctvHash).unwrap();
    scope.set_fn("txtmpl", fns::txtmpl).unwrap();

    MINSC_CTV_LIB.exec(scope).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;

    /// ctvHash(Array tx_instructions, Number index=0) -> Hash
    ///
    /// Example: ctvHash([ txVersion(1), txOut($bob_pk, 10000), txOut($alice_pk, 25000) ])
    pub fn ctvHash(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(matches!(args.len(), 1 | 2), Error::InvalidArguments);
        let tx_instructions = args.remove(0).into_array()?;
        let input_index = args.pop().map_or(Ok(0), |v| v.into_u32())?;

        let tx = build_tx(tx_instructions)?;
        let hash = get_ctv_hash(&tx, input_index);

        Ok(hash.into())
    }

    /// txtmpl(Hash) -> Policy
    pub fn txtmpl(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let hash = args.remove(0).try_into()?;
        Ok(Policy::TxTemplate(hash).into())
    }
}

// Parse tagged array instructions to build a Transaction
fn build_tx(mut instructions: Vec<Value>) -> Result<Transaction> {
    let mut tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };

    // Support short form with just a single output instruction (i.e. ctvHash(txOut($bob_pk)))
    if let Some(Value::Bytes(_)) = instructions.get(0) {
        instructions = vec![Value::Array(instructions)];
    }

    for inst in instructions {
        let mut inst = inst.into_array()?;
        ensure!(inst.len() > 0, Error::InvalidArguments);
        let inst_name = inst.remove(0).into_string()?;

        match (inst_name.as_str(), inst.len()) {
            ("version", 1) => tx.version = inst.remove(0).into_i32()?,
            ("locktime", 1) => tx.lock_time = inst.remove(0).into_u32()?,
            ("input", 0 | 1) => tx.input.push(TxIn {
                previous_output: Default::default(),
                script_sig: Default::default(),
                witness: Default::default(),
                sequence: inst.pop().map_or(Ok(u32::MAX), |v| v.into_u32())?,
            }),
            ("output", 2) => tx.output.push(TxOut {
                script_pubkey: inst.remove(0).into_spk()?,
                value: inst.remove(0).into_u64()?,
            }),
            _ => bail!(Error::InvalidArguments),
        }
    }

    ensure!(tx.output.len() > 0, Error::InvalidArguments);

    // Add the default input last, to give the user a chance to add it with a different sequence number
    if tx.input.len() == 0 {
        tx.input.push(TxIn {
            previous_output: Default::default(),
            script_sig: Default::default(),
            witness: Default::default(),
            sequence: u32::MAX,
        })
    }

    Ok(tx)
}

// Copied from https://github.com/sapio-lang/sapio/blob/master/sapio-base/src/util.rs

use bitcoin::consensus::encode::Encodable;

fn get_ctv_hash(tx: &Transaction, input_index: u32) -> sha256::Hash {
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
            .into_inner()
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
            .into_inner()
            .consensus_encode(&mut ctv_hash)
            .unwrap();
    }
    input_index.consensus_encode(&mut ctv_hash).unwrap();
    sha256::Hash::from_engine(ctv_hash)
}
