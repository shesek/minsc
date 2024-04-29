use std::convert::TryInto;
use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::{LeafVersion, NodeInfo, TapLeafHash, TapNodeHash, TaprootSpendInfo};
use miniscript::{bitcoin, descriptor::TapTree, DescriptorPublicKey};

use super::miniscript::into_policies;
use crate::error::{Error, Result};
use crate::util::EC;
use crate::{DescriptorDpk as Descriptor, Int, PolicyDpk as Policy, Scope, Value};

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

    /// tr(PubKey[, Policy|Array<Policy>]) -> Descriptor
    /// tr(Policy|Array<Policy>) -> Descriptor
    ///
    /// Construct a tr() descriptor from the given internal_key and/or policy
    pub fn tr(mut args: Vec<Value>, scope: &Scope) -> Result<Value> {
        ensure!(args.len() == 1 || args.len() == 2, Error::InvalidArguments);

        Ok(match (args.remove(0), args.pop()) {
            // tr(Policy)
            // Extracts the internal key from the policy, or uses the UNSPENDABLE key
            (Value::Policy(policy), None) => {
                descriptor_from_policy(None, tr_unspendable(scope)?, policy)?
            }

            // tr(PubKey)
            // Key-path spend only
            (Value::PubKey(pk), None) => Descriptor::new_tr(pk, None)?,

            // tr(PubKey, Policy)
            // Use an explicit internal key with the give policy
            (Value::PubKey(pk), Some(Value::Policy(policy))) => {
                descriptor_from_policy(Some(pk), None, policy)?
            }

            // tr(PubKey, [ A, [ B, C ] ])
            // Nested binary array to manually construct the taproot script tree
            // tr(PubKey, [ A, B, C ])
            // Or an array of >2 elements to create a policy with an OR between all the sub-policies
            (Value::PubKey(pk), Some(Value::Array(nodes))) => {
                descriptor_from_array(Some(pk), None, nodes)?
            }

            // tr([ A, B, .. ])
            (Value::Array(nodes), None) => {
                descriptor_from_array(None, tr_unspendable(scope)?, nodes)?
            }

            _ => bail!(Error::InvalidTrUse),
        }
        .into())
    }

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
                    Value::Number(Int(num)) => num.try_into()?,
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

    /// tapTweak(PubKey internal_key, Policy|Script|Array|Bytes tree) -> TapInfo|Descriptor
    ///
    /// Tweak the internal key with the given script tree
    pub fn tapTweak(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 2, Error::InvalidArguments);

        let internal_key = args.remove(0);
        let script_tree = args.remove(0);

        tap_tweak(internal_key, script_tree)
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

    /// tapInfo(Descriptor|TapInfo) -> TapInfo
    ///
    /// Convert the Tr Descriptor into a TapInfo (or return TapInfo as-is)
    pub fn tapInfo(mut args: Vec<Value>, _: &Scope) -> Result<Value> {
        ensure!(args.len() == 1, Error::InvalidArguments);
        let tapinfo = args.remove(0).into_tapinfo()?;
        Ok(tapinfo.into())
    }
}

/// Tweak the internal_key with the script_tree, which can be one of:
/// - a Policy or an array of Policies (returns a tr() Descriptor)
/// - a Script or an array of Scripts (returns TaprootSpendInfo)
/// - empty Array for keypath-spend only (returns a tr() Descriptor)
/// - Bytes of length 32 to be used as the raw merkle root hash (returns a TaprootSpendInfo)
pub fn tap_tweak(internal_key: Value, script_tree: Value) -> Result<Value> {
    let internal_key = internal_key.into_key()?;

    // TODO ensure no wildcards for TaprootInfo construction

    Ok(match script_tree {
        // Single policy, compiled into a tree
        Value::Policy(policy) => descriptor_from_policy(Some(internal_key), None, policy)?.into(),

        // Single script, used as the tree root
        Value::Script(script) => {
            tapinfo_from_tree(definite_xonly(internal_key)?, Value::Script(script))?.into()
        }

        // Arrays can be of Policies or Scripts, but cannot be mixed
        // They can be provided as a nested binary tree structure (e.g. [ [ A, B ], [ [ C, D ], E ] ]),
        // as a flat array to automatically build a tree, or empty to construct a keypath-only descriptor.
        // Scripts may include weights.
        Value::Array(nodes) => tr_from_array(internal_key, nodes)?,

        // Bytes of length 32 are used as the merkle root hash
        // The script tree contents will be unknown.
        Value::Bytes(bytes) if bytes.len() == 32 => {
            let merkle_root = TapNodeHash::from_slice(&bytes)?;
            // TODO should ideally return a Descriptor, but rawtr() is not yet supported in rust-miniscript
            TaprootSpendInfo::new_key_spend(&EC, definite_xonly(internal_key)?, Some(merkle_root))
                .into()
        }
        Value::Bytes(bytes) => bail!(Error::InvalidMerkleLen(bytes.len())),

        _ => bail!(Error::TaprootInvalidScript),
    })
}

fn tr_from_array(internal_key: DescriptorPublicKey, nodes: Vec<Value>) -> Result<Value> {
    // Determine the type of node based on the first Script/Policy. The other nodes are
    // expected to be of the same type.
    fn peek_node_type(node: &Value) -> Result<NodeType> {
        Ok(match node {
            Value::Policy(_) => NodeType::Policy,
            Value::Script(_) => NodeType::Script,
            Value::WithProb(_, inner) if inner.is_script() => NodeType::Script,
            Value::Array(array) if array.len() > 0 => peek_node_type(&array[0])?,
            _ => bail!(Error::TaprootInvalidScript),
        })
    }
    enum NodeType {
        Script,
        Policy,
    }

    Ok(if nodes.len() == 0 {
        // Key-path only
        Descriptor::new_tr(internal_key, None)?.into()
    } else {
        match peek_node_type(&nodes[0])? {
            NodeType::Policy => descriptor_from_array(Some(internal_key), None, nodes)?.into(),
            NodeType::Script => tapinfo_from_array(definite_xonly(internal_key)?, nodes)?.into(),
        }
    })
}

// Functions for TaprootSpendInfo construction

fn tapinfo_from_array(dpk: XOnlyPublicKey, array: Vec<Value>) -> Result<TaprootSpendInfo> {
    if array.len() == 2 {
        // Arrays of length 2 are treated as a nested binary tree of scripts (e.g. [ A, [ [ B, C ], D ] ])
        tapinfo_from_tree(dpk, Value::Array(array))
    } else {
        // Arrays of length >2 are expected to be flat and are built into a huffman tree
        // Scripts may include weights (e.g. [ 10@`$pk OP_CHECSIG`, 1@`OP_ADD 2 OP_EQUAL` ] )
        tapinfo_huffman(dpk, array)
    }
}

fn tapinfo_from_tree(dpk: XOnlyPublicKey, node: Value) -> Result<TaprootSpendInfo> {
    fn process_node(node: Value) -> Result<NodeInfo> {
        Ok(match node {
            Value::Script(script) => NodeInfo::new_leaf_with_ver(script, LeafVersion::TapScript),
            Value::Array(mut nodes) if nodes.len() == 2 => {
                let a = process_node(nodes.remove(0))?;
                let b = process_node(nodes.remove(0))?;
                NodeInfo::combine(a, b)?
            }
            _ => bail!(Error::TaprootInvalidScriptBinaryTree),
        })
    }
    Ok(TaprootSpendInfo::from_node_info(
        &EC,
        dpk,
        process_node(node)?,
    ))
}

fn tapinfo_huffman(internal_key: XOnlyPublicKey, scripts: Vec<Value>) -> Result<TaprootSpendInfo> {
    let script_weights = scripts
        .into_iter()
        .map(|v| {
            Ok(match v {
                Value::WithProb(prob, value) => (prob as u32, value.into_script()?),
                other => (1, other.into_script()?),
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

// Functions for Taproot tr() descriptor construction

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
    array: Vec<Value>,
) -> Result<Descriptor> {
    if array.len() == 2 {
        // Arrays of length 2 are treated as a nested binary tree of policies (e.g. [ A, [ [ B, C ], D ] ])
        let internal_key = pk.or(unspendable).ok_or(Error::TaprootNoViableKey)?;
        descriptor_from_tree(internal_key, Value::Array(array))
    } else {
        // Arrays of length >2 are expected to be flat and are compiled into a thresh(1, POLICIES) policy
        let policy = Policy::Threshold(1, into_policies(array)?);
        descriptor_from_policy(pk, unspendable, policy)
    }
}

fn descriptor_from_tree(pk: DescriptorPublicKey, node: Value) -> Result<Descriptor> {
    fn process_node(node: Value) -> Result<TapTree<DescriptorPublicKey>> {
        Ok(match node {
            Value::Policy(policy) => TapTree::Leaf(Arc::new(policy.compile()?)),
            Value::Array(mut nodes) if nodes.len() == 2 => {
                let a = process_node(nodes.remove(0))?;
                let b = process_node(nodes.remove(0))?;
                TapTree::combine(a, b)
            }
            _ => bail!(Error::TaprootInvalidScriptBinaryTree),
        })
    }
    let tree = process_node(node)?;
    Ok(Descriptor::new_tr(pk, Some(tree))?)
}

// Get the TR_UNSPENDABLE key from scope. It may be set to false to disable it.
fn tr_unspendable(scope: &Scope) -> Result<Option<DescriptorPublicKey>> {
    // Must exists in scope because its set in the stdlib
    Ok(match scope.builtin("TR_UNSPENDABLE").clone() {
        Value::Bool(val) if val == false => None,
        Value::PubKey(val) => Some(val),
        other => bail!(Error::InvalidTrUnspendable(other)),
    })
}

// Derive the DescriptorPublicKey into a definite key and transform to an x-only
fn definite_xonly(pk: DescriptorPublicKey) -> Result<XOnlyPublicKey> {
    Ok(XOnlyPublicKey::from(
        pk.at_derivation_index(0)?.derive_public_key(&EC)?.inner,
    ))
}
