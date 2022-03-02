use crate::Scope;

pub fn attach_stdlib(scope: &mut Scope) {
    scope.set_fn("tapLeaf", fns::tapLeaf).unwrap();
    scope.set_fn("tapBranch", fns::tapBranch).unwrap();
    scope.set_fn("tapTweak", fns::tapTweak).unwrap();
    scope.set_fn("tapHuffmanTree", fns::tapHuffmanTree).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;
    use std::convert::TryInto;

    use bitcoin::hashes::{sha256, Hash, HashEngine};
    use bitcoin::schnorr::{TapTweak, UntweakedPublicKey, XOnlyPublicKey};
    use bitcoin::util::address::WitnessVersion;
    use bitcoin::util::taproot::{LeafVersion, TapBranchHash, TapLeafHash, TaprootSpendInfo};
    use bitcoin::Script;
    use miniscript::bitcoin;

    use crate::util::EC;
    use crate::{Error, Result, Value};

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

        let mut eng = TapBranchHash::engine();
        if a < b {
            eng.input(&a);
            eng.input(&b);
        } else {
            eng.input(&b);
            eng.input(&a);
        };
        let branch = sha256::Hash::from_engine(eng);

        Ok(Value::Bytes(branch.into_inner().to_vec()))
    }

    /// tapTweak(PubKey internal_key, Hash merkle_root) -> Script
    ///
    /// Tweak the internal key with the given script tree merkle root and return the v1 output SPK
    pub fn tapTweak(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(matches!(args.len(), 1 | 2), Error::InvalidArguments);

        // Get the pubkey out of the DescriptorPublicKey and transform it into an x-only pubkey
        let internal_key = args.remove(0).into_key()?.derive_public_key(&EC)?;
        let internal_key: XOnlyPublicKey = internal_key.key.into();

        // When there's no script tree, the second argument can be omitted entirely or provided as en empty byte vector (`0x`)
        let merkle_root = match args.pop() {
            Some(Value::Bytes(bytes)) => match bytes.len() {
                32 => Some(TapBranchHash::from_inner(bytes.try_into().unwrap())),
                0 => None,
                _ => bail!(Error::InvalidMerkleLen(bytes.len())),
            },
            None => None,
            Some(_) => bail!(Error::InvalidArguments),
        };

        let (output_key, _) = internal_key.tap_tweak(&EC, merkle_root);

        Ok(Script::new_witness_program(WitnessVersion::V1, &output_key.serialize()).into())
    }

    /// tapHuffmanTree(Array<Script>) -> Hash merkle_root
    ///
    /// Compute the merkle root hash of the given array of scripts using the Huffman tree algorithm.
    /// Each element can be an array with `[ weight, script ]`.
    ///
    /// This cannot be used with custom leaf versions, as the underlying TaprootSpendInfo::with_huffman_tree() does not support it
    pub fn tapHuffmanTree(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        lazy_static! {
            // Use a fixed dummy internal key, we only care about the merkle tree root and throw away the generated output key.
            static ref INTERNAL_KEY: UntweakedPublicKey =
                "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
                    .parse()
                    .unwrap();
        }

        ensure!(args.len() == 1, Error::InvalidArguments);
        let scripts = args.remove(0).into_array()?;

        if scripts.len() == 0 {
            // Return an empty Bytes vector to signify no merkle root (Minsc doesn't have Null/None)
            return Ok(Value::Bytes(vec![]));
        }

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

        Ok(Value::Bytes(merkle_root.into_inner().to_vec()))
    }
}
