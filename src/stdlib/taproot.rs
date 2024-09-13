use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::taproot::{LeafVersion, NodeInfo, TapLeafHash, TapNodeHash, TaprootSpendInfo};
use miniscript::{bitcoin, descriptor::TapTree, DescriptorPublicKey};

use super::miniscript::{multi_andor, AndOr};
use crate::runtime::scope::{Mutable, Scope, ScopeRef};
use crate::runtime::{Error, Result, Value};
use crate::util::{fmt_list, PrettyDisplay, EC};
use crate::{DescriptorDpk as Descriptor, PolicyDpk as Policy};

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();

    // Taproot Descriptor/TaprootSpendInfo construction
    scope.set_fn("tr", fns::tr).unwrap();

    // Functions for extracting information out of Descriptors/TaprootSpendInfo
    scope.set_fn("tr::internalKey", fns::internalKey).unwrap();
    scope.set_fn("tr::outputKey", fns::outputKey).unwrap();
    scope.set_fn("tr::merkleRoot", fns::merkleRoot).unwrap();
    scope.set_fn("tr::scripts", fns::scripts).unwrap();

    // Convert a tr() descriptor into a TaprootSpendInfo
    scope.set_fn("tr::tapInfo", fns::tapInfo).unwrap();

    // Low-level leaf/branch hash calculation. Shouldn't be used directly typically.
    scope.set_fn("tr::tapLeaf", fns::tapLeaf).unwrap();
    scope.set_fn("tr::tapBranch", fns::tapBranch).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;
    use crate::runtime::{Array, Int};
    use bitcoin::ScriptBuf;

    /// Construct a tr() descriptor:
    /// tr(PubKey) -> Descriptor
    /// tr(Policy|Array<Policy>) -> Descriptor
    /// tr(PubKey, Policy|Array<Policy>) -> Descriptor
    ///
    /// Construct a non-descriptor TaprootSpendInfo:
    /// tr(PubKey, Script|Array<Script>) -> TaprootSpendInfo
    /// tr(Script|Array<Script>) -> TaprootSpendInfo
    /// tr(PubKey, Hash) -> TaprootSpendInfo
    pub fn tr(args: Array, scope: &ScopeRef) -> Result<Value> {
        let (a, b): (Value, Option<Value>) = args.args_into()?;
        super::tr(a, b, &scope.borrow())
    }

    /// tr::internalKey(TapInfo) -> PubKey
    ///
    /// Get the internal x-only key of the given TapInfo
    pub fn internalKey(args: Array, _: &ScopeRef) -> Result<Value> {
        let tapinfo: TaprootSpendInfo = args.arg_into()?;

        Ok(tapinfo.internal_key().into())
    }

    /// tr::outputKey(TapInfo) -> PubKey | (PubKey, Number)
    ///
    /// Get the output key of the given TapInfo, optionally with the parity as a tuple of (key, parity)
    pub fn outputKey(args: Array, _: &ScopeRef) -> Result<Value> {
        let (tapinfo, with_parity): (TaprootSpendInfo, Option<bool>) = args.args_into()?;
        let key = tapinfo.output_key();

        if with_parity.unwrap_or(false) {
            let parity = tapinfo.output_key_parity().to_u8() as i64;
            Ok(Value::array(vec![key.into(), parity.into()]))
        } else {
            Ok(key.into())
        }
    }

    /// tr::merkleRoot(TapInfo) -> Hash
    ///
    /// Get the merkle root hash of the given TapInfo
    pub fn merkleRoot(args: Array, _: &ScopeRef) -> Result<Value> {
        let tapinfo: TaprootSpendInfo = args.arg_into()?;

        Ok(Value::Bytes(match tapinfo.merkle_root() {
            None => vec![], // empty byte vector signifies an empty script tree
            Some(root) => root.to_byte_array().to_vec(),
        }))
    }

    /// tr::scripts(TapInfo) -> Array<(Script, Bytes version, Bytes control_block)>
    ///
    /// Get the scripts in this TapInfo with their control blocks
    pub fn scripts(args: Array, _: &ScopeRef) -> Result<Value> {
        let tapinfo: TaprootSpendInfo = args.arg_into()?;

        let scripts_ctrls = tapinfo
            .script_map()
            .keys()
            .map(|script_ver| {
                let script = script_ver.0.clone();
                let version = vec![script_ver.1.to_consensus()];
                let ctrl = tapinfo.control_block(script_ver).unwrap().serialize();
                Value::array(vec![script.into(), version.into(), ctrl.into()])
            })
            .collect();

        Ok(Value::array(scripts_ctrls))
    }

    /// tr::tapInfo(Descriptor|TapInfo) -> TapInfo
    ///
    /// Convert the Tr Descriptor into a TapInfo (or return TapInfo as-is)
    pub fn tapInfo(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::TapInfo(args.arg_into()?))
    }

    /// tr::tapLeaf(Script, version=0xc0) -> Hash
    ///
    /// Compute the leaf hash of the given script
    pub fn tapLeaf(args: Array, _: &ScopeRef) -> Result<Value> {
        let (script, leaf_var): (ScriptBuf, Option<Value>) = args.args_into()?;
        let leaf_ver = leaf_var.map_or(Ok(LeafVersion::TapScript), |ver| -> Result<_> {
            Ok(LeafVersion::from_consensus(match ver {
                Value::Number(Int(num)) => num.try_into()?,
                Value::Bytes(bytes) if bytes.len() == 1 => bytes[0],
                _ => bail!(Error::InvalidArguments),
            })?)
        })?;
        let leaf_hash = TapLeafHash::from_script(&script, leaf_ver);
        Ok(Value::Bytes(leaf_hash.to_byte_array().to_vec()))
    }

    /// tr::tapBranch(Hash node_a, Hash node_b) -> Hash
    ///
    /// Combine two nodes to create a new TapBranch parent
    pub fn tapBranch(args: Array, _: &ScopeRef) -> Result<Value> {
        let (a_hash, b_hash) = args.args_into()?;
        let branch = branch_hash(&a_hash, &b_hash);

        Ok(Value::Bytes(branch.to_byte_array().to_vec()))
    }
}

pub fn tr(a: Value, b: Option<Value>, scope: &Scope) -> Result<Value> {
    let a = match a {
        // Convert internal keys provided as Bytes into PubKeys, for compatibility with the Miniscirpt Policy tr() syntax
        Value::Bytes(_) => Value::PubKey(a.try_into()?),
        // Accept SecKeys, converted into a PubKey
        Value::SecKey(_) => Value::PubKey(a.try_into()?),
        other => other,
    };

    Ok(match (a, b) {
        // tr(Policy) -> Descriptor
        // Single policy, compiled into a script tree
        // Extracts the internal key from the policy, or uses the TR_UNSPENDABLE key
        (Value::Policy(policy), None) => {
            descriptor_from_policy(None, tr_unspendable(scope)?, policy)?.into()
        }

        // tr(PubKey) -> Descriptor
        // Key-path spend only using the given internal key
        (Value::PubKey(pk), None) => Descriptor::new_tr(pk, None)?.into(),

        // tr(PubKey, Policy) -> Descriptor
        // Use an explicit internal key with the given Policy (or PubKey, coerced into a pk() Policy)
        (Value::PubKey(pk), Some(b @ Value::Policy(_) | b @ Value::PubKey(_))) => {
            descriptor_from_policy(Some(pk), None, b.into_policy()?)?.into()
        }

        // tr(PubKey, Script) -> TaprootSpendInfo
        // Single Script used as the tree root, with an explicit internal key
        (Value::PubKey(pk), Some(Value::Script(script))) => {
            tapinfo_from_tree(definite_xonly(pk)?, Value::Script(script))?.into()
        }

        // tr(Script) -> TaprootSpendInfo
        // Single Script used as the tree root, with an unspendable internal key
        (Value::Script(script), None) => {
            let unspendable = tr_unspendable(scope)?.ok_or(Error::TaprootNoViableKey)?;
            tapinfo_from_tree(definite_xonly(unspendable)?, Value::Script(script))?.into()
        }

        // tr(PubKey, Hash) -> TaprootSpendInfo
        // Explicit internal key and merkle root hash. The script tree contents will be unknown.
        (Value::PubKey(pk), Some(Value::Bytes(bytes))) => {
            let merkle_root = TapNodeHash::from_slice(&bytes).map_err(Error::InvalidMerkleRoot)?;
            // TODO should ideally return a Descriptor, but rawtr() is not yet supported in rust-miniscript
            TaprootSpendInfo::new_key_spend(&EC, definite_xonly(pk)?, Some(merkle_root)).into()
        }

        // tr(PubKey, Array<Policy>) -> Descriptor
        // tr(PubKey, Array<Script>) -> TaprootSpendInfo
        // Create a Taproot structure for the given Policies/Scripts and internal key. Policies and Scripts cannot be mixed.
        //
        // Can be provided as an explicit binary tree array structure ([ A, [ [ B, C ], [ D, E ] ] ]), or as a flat array
        // of Scripts/Policies to automatically construct a tree. Policies are merged together with OR and compiled into a
        // tree using rust-miniscript. Scripts can have probability weights associated with them to construct a huffman tree.
        (Value::PubKey(pk), Some(Value::Array(nodes))) => {
            tr_from_array(Some(pk), None, nodes.0)?.into()
        }

        // tr(Array<Policy>) -> Descriptor
        // Create a Taproot descriptor for the given Policies, extracting the internal key or using TR_UNSPENDABLE
        // tr(Array<Script>) -> TaprootSpendInfo
        // Create a TaprootSpendInfo for the given Scripts, using TR_UNSPEDABLE as the internal key
        (Value::Array(nodes), None) => tr_from_array(None, tr_unspendable(scope)?, nodes.0)?.into(),

        _ => bail!(Error::TaprootInvalidTrUse),
    })
}

fn tr_from_array(
    internal_key: Option<DescriptorPublicKey>,
    unspendable: Option<DescriptorPublicKey>,
    nodes: Vec<Value>,
) -> Result<Value> {
    // Determine the type of node based on the first Script/Policy. The other nodes are
    // expected to be of the same type.
    fn peek_node_type(node: &Value) -> Result<NodeType> {
        Ok(match node {
            Value::Script(_) => NodeType::Script,
            // PubKeys/SecKeys are coercible into Policy
            _ if node.is_policy_coercible() => NodeType::Policy,
            Value::WithProb(_, inner) if inner.is_script() => NodeType::Script,
            Value::WithProb(_, inner) if inner.is_policy_coercible() => NodeType::Policy,
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
        Descriptor::new_tr(internal_key.ok_or(Error::TaprootNoViableKey)?, None)?.into()
    } else {
        match peek_node_type(&nodes[0])? {
            NodeType::Policy => descriptor_from_array(internal_key, unspendable, nodes)?.into(),
            NodeType::Script => tapinfo_from_array(internal_key, unspendable, nodes)?.into(),
        }
    })
}

// Functions for TaprootSpendInfo construction

fn tapinfo_from_array(
    pk: Option<DescriptorPublicKey>,
    unspendable: Option<DescriptorPublicKey>,
    scripts: Vec<Value>,
) -> Result<TaprootSpendInfo> {
    let dpk = definite_xonly(pk.or(unspendable).ok_or(Error::TaprootNoViableKey)?)?;

    if scripts.len() == 2 && (scripts[0].is_array() || scripts[1].is_array()) {
        // Nested arrays of length 2 are treated as a binary tree of scripts (e.g. [ A, [ [ B, C ], D ] ])
        tapinfo_from_tree(dpk, Value::array(scripts))
    } else {
        // Other arrays are expected to be flat and are built into a huffman tree
        // Scripts may include weights (e.g. [ 10@`$pk OP_CHECSIG`, 1@`OP_ADD 2 OP_EQUAL` ] )
        tapinfo_huffman(dpk, scripts)
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
            Value::WithProb(_, _) => bail!(Error::InvalidScriptProb),
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
    policies: Vec<Value>,
) -> Result<Descriptor> {
    if policies.len() == 2 && (policies[0].is_array() || policies[1].is_array()) {
        // Nested arrays of length 2 are treated as a binary tree of policies (e.g. [ A, [ [ B, C ], D ] ])
        let internal_key = pk.or(unspendable).ok_or(Error::TaprootNoViableKey)?;
        descriptor_from_tree(internal_key, Value::array(policies))
    } else {
        // Other arrays are expected to be flat and are compiled into an OR or thresh(1, POLICIES) policy
        let policy = multi_andor(AndOr::Or, policies)?;
        descriptor_from_policy(pk, unspendable, policy)
    }
}

fn descriptor_from_tree(pk: DescriptorPublicKey, node: Value) -> Result<Descriptor> {
    fn process_node(node: Value) -> Result<TapTree<DescriptorPublicKey>> {
        Ok(match node {
            Value::Policy(_) | Value::PubKey(_) | Value::SecKey(_) => {
                TapTree::Leaf(Arc::new(node.into_policy()?.compile()?))
            }
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
    Ok(match scope.builtin("TR_UNSPENDABLE") {
        Value::Bool(val) if val == false => None,
        Value::PubKey(val) => Some(val),
        other => bail!(Error::InvalidTrUnspendable(other.into())),
    })
}

// Derive the DescriptorPublicKey into a definite key and transform to an x-only
fn definite_xonly(pk: DescriptorPublicKey) -> Result<XOnlyPublicKey> {
    Ok(XOnlyPublicKey::from(
        pk.at_derivation_index(0)?.derive_public_key(&EC)?.inner,
    ))
}
impl TryFrom<Value> for bitcoin::XOnlyPublicKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        definite_xonly(val.try_into()?)
    }
}
impl TryFrom<Value> for bitcoin::secp256k1::schnorr::Signature {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Self::from_slice(&val.into_bytes()?)?)
    }
}

impl PrettyDisplay for TaprootSpendInfo {
    const AUTOFMT_ENABLED: bool = true;
    const MAX_ONELINER_LENGTH: usize = 300;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        write!(f, "tr(0x{}", self.internal_key())?;
        let scripts = self.script_map();
        if !scripts.is_empty() {
            write!(f, ", ",)?;
            if scripts.len() > 1 {
                fmt_list(f, scripts.keys(), indent, |f, (script, _), indent_inner| {
                    //write!(f, "{:?}:", leaf_ver)?;
                    write!(f, "{}", script.pretty(indent_inner))
                })?;
                if scripts.len() > 2 {
                    // The Taproot script tree is displayed as a flat array, which loses the the Taproot tree structure information when there
                    // are more than two scripts. "(not tree)" is added to inform users, and to make the serialized string invalid as a
                    // Minsc expression to prevent it from being used to reconstruct a TaprootSpendInfo with the wrong tree structure.
                    // FIXME deduce the original TapTree structure from the TaprootSpendInfo merkle paths (not available in rust-bitcoin)
                    write!(f, "(not tree)")?;
                }
            } else {
                let ((script, _), _) = scripts.first_key_value().expect("checked non-empty");
                write!(f, "{}", script.pretty(indent))?;
            }
        }
        write!(f, ")")
    }

    fn prefer_multiline_anyway(&self) -> bool {
        self.script_map().len() > 2
    }
}
