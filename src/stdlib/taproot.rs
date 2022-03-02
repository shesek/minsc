use std::convert::TryInto;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::schnorr::{TapTweak, UntweakedPublicKey, XOnlyPublicKey};
use bitcoin::util::address::WitnessVersion;
use bitcoin::util::taproot::{LeafVersion, TapBranchHash, TapLeafHash, TaprootSpendInfo};
use bitcoin::Script;
use miniscript::bitcoin;

use crate::util::EC;
use crate::{Error, Result, Scope, Value};

pub fn attach_stdlib(scope: &mut Scope) {
    scope.set_fn("tapLeaf", fns::tapLeaf).unwrap();
    scope.set_fn("tapBranch", fns::tapBranch).unwrap();
    scope.set_fn("tapTweak", fns::tapTweak).unwrap();
    scope.set_fn("tapTreeRoot", fns::tapTreeRoot).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;

    /// tapLeaf(Script, version=0xc0) -> Hash
    ///
    /// Compute the leaf hash of the given script
    pub fn tapLeaf(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(matches!(args.len(), 1 | 2), Error::InvalidArguments);
        let script = args.remove(0).into_script()?;
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

        let a: sha256::Hash = args.remove(0).try_into()?;
        let b: sha256::Hash = args.remove(0).try_into()?;

        let branch = branch_hash(&a, &b);

        Ok(Value::Bytes(branch.into_inner().to_vec()))
    }

    /// tapTweak(PubKey internal_key, Mixed) -> Script
    ///
    /// Tweak the internal key with the given script tree and return the v1 output SPK
    /// The second argument can be a 32 bytes hash or anything accepted by tree_root()
    pub fn tapTweak(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(matches!(args.len(), 1 | 2), Error::InvalidArguments);

        let internal_key = args.remove(0);
        let script_tree = args.pop();
        let output_spk = tap_tweak(internal_key, script_tree)?;

        Ok(output_spk.into())
    }

    /// tapTreeRoot(Script|Array) -> Hash merkle_root
    ///
    /// Compute the merkle root hash for the given script tree
    pub fn tapTreeRoot(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);

        let merkle_root = tree_root(args.remove(0))?;

        Ok(Value::Bytes(
            // Return empty tree as an empty Bytes vector (Minsc doesn't yet have Null/None)
            merkle_root.map_or_else(Vec::new, |r| r.into_inner().to_vec()),
        ))
    }
}

fn tap_tweak(internal_key: Value, script_tree: Option<Value>) -> Result<Script> {
    // Get the pubkey out of the DescriptorPublicKey and transform it into an x-only pubkey
    let internal_key = internal_key.into_key()?.derive_public_key(&EC)?;
    let internal_key: XOnlyPublicKey = internal_key.key.into();

    // When there's no script tree, the second argument can be omitted entirely or provided as en empty byte vector (`0x`)
    // The second argument can be anything accepted
    let merkle_root = script_tree.map_or(Ok(None), tree_root)?;

    let (output_key, _) = internal_key.tap_tweak(&EC, merkle_root);

    Ok(Script::new_witness_program(
        WitnessVersion::V1,
        &output_key.serialize(),
    ))
}

fn tree_root(root: Value) -> Result<Option<TapBranchHash>> {
    Ok(match root {
        // Empty arrays and empty bytes are treated as an empty script tree (key-path only)
        Value::Array(nodes) if nodes.len() == 0 => None,
        Value::Bytes(bytes) if bytes.len() == 0 => None,

        // Bytes of length 32 are considered to be the merkle root hash and returned as-is
        Value::Bytes(bytes) if bytes.len() == 32 => Some(bytes.try_into().unwrap()),
        Value::Bytes(bytes) => bail!(Error::InvalidMerkleLen(bytes.len())),

        // An array with 1 element is a tree with a single script, where the leaf is also the root
        // This can be useful if the single script is passed as a Bytes value.
        Value::Array(mut nodes) if nodes.len() == 1 => {
            Some(make_leaf(nodes.remove(0))?.into_inner())
        }

        // An array with 2 elements is constructed as a nested tree of arrays (i.e. [ [S1,S2], [S3,S4] ]  )
        Value::Array(mut nodes) if nodes.len() == 2 => {
            Some(combine_nodes(nodes.remove(0), nodes.remove(0))?.into_inner())
        }

        // An array with 3 or more scripts is constructed as an huffman tree
        Value::Array(nodes) if nodes.len() > 2 => Some(huffman_tree(nodes)?.into_inner()),

        // Other values are expected to be script-like and are constructed as a single script tree
        node => Some(make_leaf(node)?.into_inner()),
    }
    .map(TapBranchHash::from_inner))
}

fn make_leaf(node: Value) -> Result<sha256::Hash> {
    let script = node.into_script()?;
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    Ok(sha256::Hash::from_inner(leaf_hash.into_inner()))
}

fn combine_nodes(a: Value, b: Value) -> Result<sha256::Hash> {
    Ok(branch_hash(&process_node(a)?, &process_node(b)?))
}

fn process_node(node: Value) -> Result<sha256::Hash> {
    if node.is_script_like() {
        make_leaf(node)
    } else if let Value::Array(mut nodes) = node {
        if nodes.len() == 2 {
            combine_nodes(nodes.remove(0), nodes.remove(0))
        } else {
            Err(Error::TaprootInvalidNestedTree)
        }
    } else {
        Err(Error::TaprootInvalidNestedTree)
    }
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

fn huffman_tree(scripts: Vec<Value>) -> Result<sha256::Hash> {
    lazy_static! {
        // Use a fixed dummy internal key, we only care about the merkle tree root and throw away the generated output key.
        static ref INTERNAL_KEY: UntweakedPublicKey =
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
                .parse()
                .unwrap();
    }

    ensure!(scripts.len() > 2, Error::InvalidArguments);

    let script_weights = scripts
        .into_iter()
        .map(|v| {
            Ok(match v {
                Value::WithProb(prob, value) => (prob as u32, value.into_script()?),
                other => (1, other.into_script()?),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let tree_info = TaprootSpendInfo::with_huffman_tree(&EC, *INTERNAL_KEY, script_weights)?;

    let merkle_root = tree_info.merkle_root().expect("at least 1 script");

    Ok(sha256::Hash::from_inner(merkle_root.into_inner()))
}
