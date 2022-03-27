use std::convert::TryInto;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::util::key::XOnlyPublicKey;
use bitcoin::util::taproot::{LeafVersion, TapBranchHash, TapLeafHash, TaprootSpendInfo};
use miniscript::bitcoin;

use crate::util::EC;
use crate::{Error, Result, Scope, Value};

pub fn attach_stdlib(scope: &mut Scope) {
    // Tweak an internal key with the script tree/root
    scope.set_fn("tapTweak", fns::tapTweak).unwrap();

    // Functions for extracting information out of TapInfo
    scope.set_fn("tapInternalKey", fns::tapInternalKey).unwrap();
    scope.set_fn("tapOutputKey", fns::tapOutputKey).unwrap();
    scope.set_fn("tapMerkleRoot", fns::tapMerkleRoot).unwrap();
    scope.set_fn("tapScripts", fns::tapScripts).unwrap();

    // Low-level leaf/branch hash calculation. Shouldn't be used directly typically.
    scope.set_fn("tapLeaf", fns::tapLeaf).unwrap();
    scope.set_fn("tapBranch", fns::tapBranch).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;

    /// tapLeaf(Script, version=0xc0) -> Hash
    ///
    /// Compute the leaf hash of the given script
    pub fn tapLeaf(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(matches!(args.len(), 1 | 2), Error::InvalidArguments);
        let script = args.remove(0).into_tapscript()?;
        let leaf_ver = args
            .pop()
            .map_or(Ok(LeafVersion::TapScript), |v| -> Result<_> {
                let leaf_ver = match v {
                    Value::Number(num) => num.try_into()?,
                    Value::Bytes(bytes) if bytes.len() == 1 => bytes[0],
                    _ => bail!(Error::InvalidArguments),
                };
                Ok(LeafVersion::from_consensus(leaf_ver)?)
            })?;
        let leaf_hash = TapLeafHash::from_script(&script, leaf_ver);
        Ok(Value::Bytes(leaf_hash.into_inner().to_vec()))
    }

    /// tapBranch(Hash node_a, Hash node_b) -> Hash
    ///
    /// Combine two nodes to create a new TapBranch parent
    pub fn tapBranch(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidArguments);

        let a = args.remove(0).try_into()?;
        let b = args.remove(0).try_into()?;

        let branch = branch_hash(&a, &b);

        Ok(Value::Bytes(branch.into_inner().to_vec()))
    }

    /// tapTweak(PubKey internal_key, Bytes|Script|Array tree) -> TapInfo
    ///
    /// Tweak the internal key with the given script tree and return the TapInfo (TaprootSpendInfo)
    pub fn tapTweak(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidArguments);

        let internal_key = args.remove(0);
        let script_tree = args.remove(0);
        let tapinfo = tap_tweak(internal_key, script_tree)?;

        Ok(Value::TapInfo(tapinfo))
    }

    /// tapInternal(TapInfo) -> PubKey
    ///
    /// Get the internal x-only key of the given TapInfo
    pub fn tapInternalKey(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let tapinfo = args.remove(0).into_tapinfo()?;

        Ok(tapinfo.internal_key().into())
    }

    /// tapOutput(TapInfo) -> (PubKey, Number parity)
    ///
    /// Get the output key and parity of the given TapInfo as a tuple of [ key, parity ]
    pub fn tapOutputKey(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let tapinfo = args.remove(0).into_tapinfo()?;

        let key = tapinfo.output_key();
        let parity = tapinfo.output_key_parity().to_u8() as i64;

        Ok(Value::Array(vec![key.into(), parity.into()]))
    }

    /// tapMerkleRoot(TapInfo) -> Hash
    ///
    /// Get the merkle root hash of the given TapInfo
    pub fn tapMerkleRoot(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let tapinfo = args.remove(0).into_tapinfo()?;

        Ok(Value::Bytes(match tapinfo.merkle_root() {
            None => vec![], // empty byte vector signifies an empty script tree
            Some(root) => root.into_inner().to_vec(),
        }))
    }

    /// tapScripts(TapInfo) -> Array<(Script, Bytes version, Bytes control_block)>
    ///
    /// Get the scripts in this TapInfo with their control blocks
    pub fn tapScripts(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let tapinfo = args.remove(0).into_tapinfo()?;

        let scripts_ctrls = tapinfo
            .as_script_map()
            .keys()
            .map(|script_ver| {
                let script = script_ver.0.clone();
                let version = vec![script_ver.1.into_consensus()];
                let ctrl = tapinfo.control_block(script_ver).unwrap().serialize();
                Value::Array(vec![script.into(), version.into(), ctrl.into()])
            })
            .collect();

        Ok(Value::Array(scripts_ctrls))
    }
}

pub fn tap_tweak(internal_key: Value, script_tree: Value) -> Result<TaprootSpendInfo> {
    // Get the pubkey out of the DescriptorPublicKey and transform it into an x-only pubkey
    let internal_key = internal_key.into_key()?.derive_public_key(&EC)?;
    let internal_key: XOnlyPublicKey = internal_key.inner.into();

    // Construct a key-path-only TapInfo
    let key_only_tr = || TaprootSpendInfo::new_key_spend(&EC, internal_key, None);

    Ok(match script_tree {
        // Empty bytes or arrays are treated as an empty script tree (key-path only)
        Value::Bytes(bytes) if bytes.len() == 0 => key_only_tr(),
        Value::Array(array) if array.len() == 0 => key_only_tr(),

        // Bytes of length 32 are used as the merkle root hash
        // The script tree contents will be unknown.
        Value::Bytes(bytes) if bytes.len() == 32 => {
            let merkle_root = TapBranchHash::from_slice(&bytes)?;
            TaprootSpendInfo::new_key_spend(&EC, internal_key, Some(merkle_root))
        }
        Value::Bytes(bytes) => bail!(Error::InvalidMerkleLen(bytes.len())),

        // Construct an huffman tree for the given set of scripts
        Value::Array(nodes) => huffman_tree(internal_key, nodes)?,

        // Single script tree
        node => huffman_tree(internal_key, vec![node])?,
    })
}

fn huffman_tree(internal_key: XOnlyPublicKey, scripts: Vec<Value>) -> Result<TaprootSpendInfo> {
    let script_weights = scripts
        .into_iter()
        .map(|v| {
            Ok(match v {
                Value::WithProb(prob, value) => (prob as u32, value.into_tapscript()?),
                other => (1, other.into_tapscript()?),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(TaprootSpendInfo::with_huffman_tree(
        &EC,
        internal_key,
        script_weights,
    )?)
}

fn branch_hash(a: &sha256::Hash, b: &sha256::Hash) -> sha256::Hash {
    let mut eng = TapBranchHash::engine();
    if a < b {
        eng.input(a);
        eng.input(b);
    } else {
        eng.input(b);
        eng.input(a);
    };
    sha256::Hash::from_engine(eng)
}
