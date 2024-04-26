use std::convert::TryInto;
use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::{LeafVersion, NodeInfo, TapLeafHash, TapNodeHash, TaprootSpendInfo};
use miniscript::{bitcoin, descriptor::TapTree, DescriptorPublicKey};

use crate::error::{Error, Result};
use crate::util::EC;
use crate::{DescriptorDpk as Descriptor, PolicyDpk as Policy, Scope, Value};

// XXX mention in header that some miniscript stuff is over here
pub fn attach_stdlib(scope: &mut Scope) {
    // Miniscript descriptor function
    scope.set_fn("tr", fns::tr).unwrap();
    //scope.set_fn("rawtr", fns::rawtr).unwrap();

    // Tweak an internal key with the script tree/root, returning a TapInfo
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

    pub fn tr(mut args: Vec<Value>, scope: &Scope) -> Result<Value> {
        ensure!(args.len() == 1 || args.len() == 2, Error::InvalidArguments);
        let unspendable = tr_unspendable(scope)?;

        Ok(match (args.remove(0), args.pop()) {
            // tr(Policy)
            // Extracts the internal key from the policy, or uses the UNSPENDABLE key
            (Value::Policy(policy), None) => descriptor_from_policy(None, unspendable, policy)?,

            // tr(PubKey)
            // Key-path spend only
            (Value::PubKey(pk), None) => Descriptor::new_tr(pk, None)?,

            // tr(PubKey, Policy)
            // Use an explicit internal key with the give policy
            (Value::PubKey(pk), Some(Value::Policy(policy))) => {
                descriptor_from_policy(Some(pk), None, policy)?
            }

            // tr(PubKey, [ A, [ B, C ] ])
            // Nested array tuples to manually construct the taproot script tree
            // tr(PubKey, [ A, B, C ])
            // Or an array of >2 elements to create a policy with an OR between all the sub-policies
            (Value::PubKey(pk), Some(Value::Array(nodes))) => {
                descriptor_from_array(Some(pk), unspendable, nodes)?
            }

            // tr([ A, B, .. ])
            (Value::Array(nodes), None) => descriptor_from_array(None, unspendable, nodes)?,

            _ => bail!(Error::InvalidTrUse),
        }
        .into())
    }

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
        Ok(Value::Bytes(leaf_hash.to_byte_array().to_vec()))
    }

    /// tapBranch(Hash node_a, Hash node_b) -> Hash
    ///
    /// Combine two nodes to create a new TapBranch parent
    pub fn tapBranch(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidArguments);

        let a = args.remove(0).try_into()?;
        let b = args.remove(0).try_into()?;

        let branch = branch_hash(&a, &b);

        Ok(Value::Bytes(branch.to_byte_array().to_vec()))
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

    /// tapInternalKey(TapInfo) -> PubKey
    ///
    /// Get the internal x-only key of the given TapInfo
    pub fn tapInternalKey(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let tapinfo = args.remove(0).into_tapinfo()?;

        Ok(tapinfo.internal_key().into())
    }

    /// tapOutputKey(TapInfo) -> (PubKey, Number parity)
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
            Some(root) => root.to_byte_array().to_vec(),
        }))
    }

    /// tapScripts(TapInfo) -> Array<(Script, Bytes version, Bytes control_block)>
    ///
    /// Get the scripts in this TapInfo with their control blocks
    pub fn tapScripts(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let tapinfo = args.remove(0).into_tapinfo()?;

        let scripts_ctrls = tapinfo
            .script_map()
            .keys()
            .map(|script_ver| {
                let script = script_ver.0.clone();
                let version = vec![script_ver.1.to_consensus()];
                let ctrl = tapinfo.control_block(script_ver).unwrap().serialize();
                Value::Array(vec![script.into(), version.into(), ctrl.into()])
            })
            .collect();

        Ok(Value::Array(scripts_ctrls))
    }
}

pub fn tap_tweak(internal_key: Value, script_tree: Value) -> Result<TaprootSpendInfo> {
    // Get the pubkey out of the DescriptorPublicKey and transform it into an x-only pubkey
    // XXX ensure no wildcards?
    let internal_key = internal_key
        .into_key()?
        .at_derivation_index(0)?
        .derive_public_key(&EC)?;
    let internal_key: XOnlyPublicKey = internal_key.inner.into();

    // Construct a key-path-only TapInfo
    let key_only_tr = || TaprootSpendInfo::new_key_spend(&EC, internal_key, None);

    // Construct a script tree with the given top-level node
    let script_tree_tr = |node| TaprootSpendInfo::from_node_info(&EC, internal_key, node);

    Ok(match script_tree {
        // Empty bytes or arrays are treated as an empty script tree (key-path only)
        Value::Bytes(bytes) if bytes.len() == 0 => key_only_tr(),
        Value::Array(array) if array.len() == 0 => key_only_tr(),

        // Bytes of length 32 are used as the merkle root hash
        // The script tree contents will be unknown.
        Value::Bytes(bytes) if bytes.len() == 32 => {
            let merkle_root = TapNodeHash::from_slice(&bytes)?;
            TaprootSpendInfo::new_key_spend(&EC, internal_key, Some(merkle_root))
        }
        Value::Bytes(bytes) => bail!(Error::InvalidMerkleLen(bytes.len())),

        // Arrays of length != 2 are constructed as a huffman tree
        Value::Array(nodes) if nodes.len() != 2 => huffman_tree(internal_key, nodes)?,

        // Arrays of length 2 are processed as a nested tree structure (i.e. [ [ S1, S2 ], [ [ S3, S4 ], S5 ] ] )
        array @ Value::Array(_) => script_tree_tr(process_node(array)?),

        // Single script tree
        node => script_tree_tr(process_node(node)?),
    })
}

fn process_node(node: Value) -> Result<NodeInfo> {
    if node.is_script_coercible(true) {
        let script = node.into_tapscript()?;
        return Ok(NodeInfo::new_leaf_with_ver(script, LeafVersion::TapScript));
    }
    if let Value::Array(mut nodes) = node {
        if nodes.len() == 2 {
            let a = process_node(nodes.remove(0))?;
            let b = process_node(nodes.remove(0))?;
            return Ok(NodeInfo::combine(a, b)?);
        }
    }
    Err(Error::TaprootInvalidNestedTree)
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
    let mut eng = TapNodeHash::engine();
    if a < b {
        eng.input(a.as_byte_array());
        eng.input(b.as_byte_array());
    } else {
        eng.input(b.as_byte_array());
        eng.input(a.as_byte_array());
    };
    sha256::Hash::from_engine(eng)
}

// Functions for miniscript descriptor taproot construction

fn descriptor_from_policy(
    pk: Option<DescriptorPublicKey>,
    unspendable: Option<DescriptorPublicKey>,
    policy: Policy,
) -> Result<Descriptor> {
    let policy = match pk {
        // Create an OR policy between the provided PubKey and Policy, then compile that
        Some(pk) => Policy::Or(vec![
            // 10000x likelihood given to the key spend. should (hopefully?) be picked up as the internal key by the compiler.
            (10000, Arc::new(Policy::Key(pk))),
            (1, Arc::new(policy)),
        ]),
        // If no key was provided, use the policy as-is
        None => policy,
    };
    Ok(policy.compile_tr(unspendable)?)
}

fn descriptor_from_array(
    pk: Option<DescriptorPublicKey>,
    unspendable: Option<DescriptorPublicKey>,
    policies: Vec<Value>,
) -> Result<Descriptor> {
    if policies.len() == 2 {
        let internal_key = pk.or(unspendable).ok_or(Error::TaprootNoViableKey)?;
        descriptor_from_tree(internal_key, Value::Array(policies))
    } else {
        let policies = policies
            .into_iter()
            .map(|v| Ok(Arc::new(v.into_policy()?)))
            .collect::<Result<_>>()?;
        let policy = Policy::Threshold(1, policies);
        descriptor_from_policy(pk, unspendable, policy)
    }
}

fn descriptor_from_tree(pk: DescriptorPublicKey, node: Value) -> Result<Descriptor> {
    fn tree_node(node: Value) -> Result<TapTree<DescriptorPublicKey>> {
        Ok(match node {
            Value::Policy(policy) => TapTree::Leaf(Arc::new(policy.compile()?)),
            Value::Array(mut nodes) if nodes.len() == 2 => {
                let a = tree_node(nodes.remove(0))?;
                let b = tree_node(nodes.remove(0))?;
                TapTree::combine(a, b)
            }
            _ => bail!(Error::TaprootInvalidNestedTree),
        })
    }
    let tree = tree_node(node)?;
    Ok(Descriptor::new_tr(pk, Some(tree))?)
}

fn tr_unspendable(scope: &Scope) -> Result<Option<DescriptorPublicKey>> {
    // Must exists in scope because its set in the stdlib
    Ok(match scope.get(&"TR_UNSPENDABLE".into()).unwrap().clone() {
        Value::Bool(val) if val == false => None,
        Value::PubKey(val) => Some(val),
        other => bail!(Error::InvalidTrUnspendable(other)),
    })
}
