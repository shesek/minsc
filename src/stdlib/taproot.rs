use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::taproot::{LeafVersion, NodeInfo, TapLeafHash, TapNodeHash, TaprootSpendInfo};
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use miniscript::descriptor::{self, DescriptorPublicKey};

use super::miniscript::{multi_andor, AndOr};
use crate::runtime::scope::{Mutable, Scope, ScopeRef};
use crate::runtime::{Array, Error, Result, Value};
use crate::util::{self, fmt_list, DescriptorExt, DescriptorPubKeyExt, PrettyDisplay, EC};
use crate::{DescriptorDpk as Descriptor, ExprRepr, PolicyDpk as Policy};

pub fn attach_stdlib(scope: &ScopeRef<Mutable>) {
    let mut scope = scope.borrow_mut();

    // Taproot Descriptor/TaprootSpendInfo construction
    scope.set_fn("tr", fns::tr).unwrap();

    // Functions for extracting information out of Descriptors/TaprootSpendInfo
    scope.set_fn("tr::internalKey", fns::internalKey).unwrap();
    scope.set_fn("tr::outputKey", fns::outputKey).unwrap();
    scope.set_fn("tr::merkleRoot", fns::merkleRoot).unwrap();
    scope.set_fn("tr::scripts", fns::scripts).unwrap();
    scope.set_fn("tr::ctrl", fns::ctrl).unwrap();

    // Convert a tr() descriptor into a TaprootSpendInfo
    scope.set_fn("tr::tapInfo", fns::tapInfo).unwrap();

    // Low-level leaf/branch hash calculation. Shouldn't be used directly typically.
    scope.set_fn("tr::tapLeaf", fns::tapLeaf).unwrap();
    scope.set_fn("tr::tapBranch", fns::tapBranch).unwrap();
}

#[allow(non_snake_case)]
pub mod fns {
    use super::*;
    use crate::util::MiniscriptExt;

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

    /// tr::internalKey(TapInfo|Descriptor) -> PubKey
    ///
    /// Get the internal x-only key of the given TapInfo/Descriptor
    pub fn internalKey(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(match args.arg_into()? {
            Value::TapInfo(tapinfo) => tapinfo.internal_key().into(),
            Value::Descriptor(Descriptor::Tr(tr)) => tr.internal_key().clone().into(),
            _ => bail!(Error::InvalidArguments),
        })
    }

    /// tr::outputKey(TapInfo) -> PubKey | (PubKey, Number)
    ///
    /// Get the output key of the given TapInfo, optionally with the parity as a tuple of (key, parity)
    pub fn outputKey(args: Array, _: &ScopeRef) -> Result<Value> {
        let (tapinfo, with_parity): (TaprootSpendInfo, Option<bool>) = args.args_into()?;
        let key = tapinfo.output_key();

        if with_parity.unwrap_or(false) {
            let parity = tapinfo.output_key_parity().to_u8() as i64;
            Ok(Value::array_of((key, parity)))
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

    /// tr::scripts(TapInfo|Descriptor) -> Array<Script>
    ///
    /// Get an array of all scripts in the tree
    pub fn scripts(args: Array, _: &ScopeRef) -> Result<Value> {
        let tapinfo: TaprootSpendInfo = args.arg_into()?;
        let scripts = tapinfo.script_map().keys();
        Ok(Value::array(
            scripts.map(|(script, _)| script.clone().into()).collect(),
        ))
    }

    /// tr::ctrl(TapInfo|Descriptor, Script|Policy, Byte version=TapScript) -> Array<Script>
    ///
    /// Get the control block for the given script/policy
    pub fn ctrl(args: Array, _: &ScopeRef) -> Result<Value> {
        let (tapinfo, script_or_policy, leaf_ver): (TaprootSpendInfo, Value, Option<LeafVersion>) =
            args.args_into()?;
        let script = match script_or_policy {
            Value::Script(script) => script,
            Value::Policy(policy) => policy.compile::<miniscript::Tap>()?.derive_keys()?.encode(),
            other => bail!(Error::InvalidValue(other.into())),
        };
        let leaf_ver = leaf_ver.unwrap_or(LeafVersion::TapScript);
        let ctrl = tapinfo
            .control_block(&(script, leaf_ver))
            .ok_or(Error::TaprootScriptNotFound)?;
        Ok(ctrl.serialize().into())
    }

    /// tr::tapInfo(Descriptor|TapInfo) -> TapInfo
    ///
    /// Convert the Tr Descriptor into a TapInfo (or return TapInfo as-is)
    pub fn tapInfo(args: Array, _: &ScopeRef) -> Result<Value> {
        Ok(Value::TapInfo(args.arg_into()?))
    }

    /// tr::tapLeaf(Script, Byte version=TapScript) -> Hash
    ///
    /// Compute the leaf hash of the given script
    pub fn tapLeaf(args: Array, _: &ScopeRef) -> Result<Value> {
        let (script, leaf_var): (ScriptBuf, Option<_>) = args.args_into()?;
        let leaf_ver = leaf_var.unwrap_or(LeafVersion::TapScript);
        let leaf_hash = TapLeafHash::from_script(&script, leaf_ver);
        Ok(leaf_hash.to_byte_array().to_vec().into())
    }

    /// tr::tapBranch(Hash node_a, Hash node_b) -> Hash
    ///
    /// Combine two nodes to create a new TapBranch parent
    pub fn tapBranch(args: Array, _: &ScopeRef) -> Result<Value> {
        let (a_hash, b_hash) = args.args_into()?;
        let branch_hash = TapNodeHash::from_node_hashes(a_hash, b_hash);
        Ok(branch_hash.to_byte_array().to_vec().into())
    }
}

impl TryFrom<Value> for TaprootSpendInfo {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::TapInfo(tapinfo) => tapinfo,
            Value::Descriptor(desc) => match desc.definite()? {
                miniscript::Descriptor::Tr(tr_desc) => (*tr_desc.spend_info()).clone(),
                _ => bail!(Error::NotTapInfoLike(Value::Descriptor(desc).into())),
            },
            v => bail!(Error::NotTapInfoLike(v.into())),
        })
    }
}

pub fn tr(a: Value, b: Option<Value>, scope: &Scope) -> Result<Value> {
    let a = match a {
        // Convert internal keys provided as Bytes into PubKeys, for compatibility with the Miniscript Policy tr() syntax
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
            tapinfo_from_tree_node(pk.derive_xonly()?, Value::Script(script))?.into()
        }

        // tr(Script) -> TaprootSpendInfo
        // Single Script used as the tree root, with an unspendable internal key
        (Value::Script(script), None) => {
            let unspendable = tr_unspendable(scope)?.ok_or(Error::TaprootNoViableKey)?;
            tapinfo_from_tree_node(unspendable.derive_xonly()?, Value::Script(script))?.into()
        }

        // tr(PubKey, Hash) -> TaprootSpendInfo
        // Explicit internal key and merkle root hash. The script tree contents will be unknown.
        (Value::PubKey(pk), Some(Value::Bytes(bytes))) => {
            let merkle_root = TapNodeHash::from_slice(&bytes).map_err(Error::InvalidMerkleRoot)?;
            // TODO should ideally return a Descriptor, but rawtr() is not yet supported in rust-miniscript
            TaprootSpendInfo::new_key_spend(&EC, pk.derive_xonly()?, Some(merkle_root)).into()
        }

        // tr(PubKey, Array<Policy>) -> Descriptor
        // tr(PubKey, Array<Script>) -> TaprootSpendInfo
        // Create a Taproot structure for the given Policies/Scripts and internal key. Policies and Scripts cannot be mixed.
        //
        // Can be provided as an explicit binary tree array structure ([ A, [ [ B, C ], [ D, E ] ] ]), or as a flat array
        // of Scripts/Policies to automatically construct a tree. Policies are merged together with OR and compiled into a
        // tree using rust-miniscript. Scripts can have probability weights associated with them to construct a huffman tree.
        (Value::PubKey(pk), Some(Value::Array(nodes))) => tr_from_array(Some(pk), None, nodes.0)?,

        // tr(Array<Policy>) -> Descriptor
        // Create a Taproot descriptor for the given Policies, extracting the internal key or using TR_UNSPENDABLE
        // tr(Array<Script>) -> TaprootSpendInfo
        // Create a TaprootSpendInfo for the given Scripts, using TR_UNSPEDABLE as the internal key
        (Value::Array(nodes), None) => tr_from_array(None, tr_unspendable(scope)?, nodes.0)?,

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

    Ok(if nodes.is_empty() {
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
    let dpk = pk
        .or(unspendable)
        .ok_or(Error::TaprootNoViableKey)?
        .derive_xonly()?;

    if scripts.len() == 2 && (scripts[0].is_array() || scripts[1].is_array()) {
        // Nested arrays of length 2 are treated as a binary tree of scripts (e.g. [ A, [ [ B, C ], D ] ])
        tapinfo_from_tree_node(dpk, Value::array(scripts))
    } else {
        // Other arrays are expected to be flat and are built into a huffman tree
        // Scripts may include weights (e.g. [ 10@`$pk OP_CHECSIG`, 1@`OP_ADD 2 OP_EQUAL` ] )
        tapinfo_huffman(dpk, scripts)
    }
}

fn tapinfo_from_tree_node(internal_key: XOnlyPublicKey, node: Value) -> Result<TaprootSpendInfo> {
    let tree = NodeInfo::try_from(node)?;
    Ok(TaprootSpendInfo::from_node_info(&EC, internal_key, tree))
}

impl TryFrom<Value> for NodeInfo {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Script(script) => NodeInfo::new_leaf_with_ver(script, LeafVersion::TapScript),
            Value::Array(mut nodes) if nodes.len() == 2 => {
                let a = nodes.remove(0).try_into()?;
                let b = nodes.remove(0).try_into()?;
                NodeInfo::combine(a, b)?
            }
            Value::WithProb(_, _) => bail!(Error::InvalidScriptProb),
            _ => bail!(Error::TaprootInvalidScriptBinaryTree),
        })
    }
}
impl TryFrom<Value> for bitcoin::taproot::TapTree {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(NodeInfo::try_from(value)?.try_into()?)
    }
}

impl TryFrom<Value> for TapLeafHash {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Bytes(bytes) if bytes.len() == 32 => Self::from_slice(&bytes)?,
            Value::Script(script) => TapLeafHash::from_script(&script, LeafVersion::TapScript),
            v => bail!(Error::TaprootInvalidLeaf(v.into())),
        })
    }
}
impl From<TapLeafHash> for Value {
    fn from(hash: TapLeafHash) -> Self {
        hash.to_byte_array().to_vec().into()
    }
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
        let tree = descriptor::TapTree::try_from(Value::array(policies))?;
        Ok(Descriptor::new_tr(internal_key, Some(tree))?)
    } else {
        // Other arrays are expected to be flat and are compiled into an OR or thresh(1, POLICIES) policy
        let policy = multi_andor(AndOr::Or, policies)?;
        descriptor_from_policy(pk, unspendable, policy)
    }
}

impl TryFrom<Value> for descriptor::TapTree<DescriptorPublicKey> {
    type Error = Error;
    fn try_from(value: Value) -> Result<Self> {
        Ok(match value {
            Value::Policy(_) | Value::PubKey(_) | Value::SecKey(_) => {
                Self::Leaf(Arc::new(value.into_policy()?.compile()?))
            }
            Value::Array(mut nodes) if nodes.len() == 2 => {
                let a = nodes.remove(0).try_into()?;
                let b = nodes.remove(0).try_into()?;
                Self::combine(a, b)
            }
            _ => bail!(Error::TaprootInvalidScriptBinaryTree),
        })
    }
}

// Get the TR_UNSPENDABLE key from scope. It may be set to false to disable it.
fn tr_unspendable(scope: &Scope) -> Result<Option<DescriptorPublicKey>> {
    // Must exists in scope because its set in the stdlib
    Ok(match scope.builtin("TR_UNSPENDABLE") {
        Value::Bool(false) => None,
        Value::PubKey(val) => Some(val),
        other => bail!(Error::InvalidTrUnspendable(other.into())),
    })
}

impl TryFrom<Value> for XOnlyPublicKey {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(bitcoin::PublicKey::try_from(val)?.into())
    }
}
impl TryFrom<Value> for bitcoin::secp256k1::schnorr::Signature {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Self::from_slice(&val.into_bytes()?)?)
    }
}
impl TryFrom<Value> for bitcoin::taproot::Signature {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Self::from_slice(&val.into_bytes()?)?)
    }
}
impl TryFrom<Value> for bitcoin::taproot::LeafVersion {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(match val {
            Value::Number(num) => Self::from_consensus(num.into_i64()?.try_into()?)?,
            Value::Bytes(bytes) if bytes.len() == 1 => Self::from_consensus(bytes[0])?,
            other => bail!(Error::InvalidValue(other.into())),
        })
    }
}
impl TryFrom<Value> for bitcoin::taproot::ControlBlock {
    type Error = Error;
    fn try_from(val: Value) -> Result<Self> {
        Ok(Self::decode(&val.into_bytes()?)?)
    }
}

impl PrettyDisplay for TaprootSpendInfo {
    const AUTOFMT_ENABLED: bool = true;
    const MAX_ONELINER_LENGTH: usize = 300;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        write!(f, "tr({}", self.internal_key())?;
        let scripts = self.script_map();
        if !scripts.is_empty() {
            write!(f, ", ",)?;
            let max_depth = scripts.values().map(|bs| bs.len()).max().unwrap_or(0);

            // If the tree's depth is below 2 (meaning only 1 or 2 leaves), its easy -  we can treat it as a flat list, with no tree
            // structure information that needs to be preserved (siblings are ordered, making trees of 2 is deterministic).
            if max_depth == 0 && scripts.len() == 1 {
                let (script, _) = scripts.first_key_value().expect("checked non-empty").0;
                write!(f, "{}", script.pretty(indent))?;
            } else if max_depth == 1 && scripts.len() == 2 {
                fmt_list(f, scripts.keys(), indent, |f, (script, _), indent_inner| {
                    write!(f, "{}", script.pretty(indent_inner))
                })?;
            }
            // If there are >2 leaf nodes, the tree structure must be reconstructed in order to encode it as a nested binary array that can be
            // round-tripped back into the same structure. The reconstruction involves hashing and may be computationally heavy for large trees.
            else {
                let tree = reconstruct_tree(self).expect("invalid TaprootSpendInfo"); // can only fail if the TaprootSpendInfo has invalid proofs
                write!(f, "{}", tree.pretty(indent))?;
            }
        } else if let Some(root_hash) = self.merkle_root() {
            // Merkle root hash of an unknown script tree
            write!(f, ", {}", root_hash)?; // TODO should use rawleaf() (https://github.com/bitcoin/bitcoin/pull/30243)
        }
        write!(f, ")")
    }

    fn prefer_multiline_anyway(&self) -> bool {
        self.script_map().len() > 2
    }
}

impl ExprRepr for TaprootSpendInfo {
    fn repr_fmt<W: fmt::Write>(&self, f: &mut W) -> fmt::Result {
        write!(f, "tr({}", self.internal_key())?;
        if !self.script_map().is_empty() {
            write!(f, ",")?;
            // Always reconstruct the tree, without the optimization for simple cases used in PrettyDisplay,
            // to be 100% certain that it is fully round-trip-able.
            let tree = reconstruct_tree(self).expect("invalid TaprootSpendInfo"); // can only fail if the TaprootSpendInfo has invalid proofs
            tree.repr_fmt(f)?;
        } else if let Some(root_hash) = self.merkle_root() {
            write!(f, ",{}", root_hash)?;
        }
        write!(f, ")")
    }
}

#[derive(Debug)]
enum NodeTree<'a> {
    Leaf(&'a (ScriptBuf, LeafVersion)),
    Branch(Box<NodeTree<'a>>, Box<NodeTree<'a>>),
    Hidden(TapNodeHash),
}

// Reconstruct the Taproot tree structure from a TaprootSpendInfo using the merkle proofs associated with its scripts.
// Returns None if there are no script paths, or if any of the merkle proofs are invalid (don't connect to the root).
fn reconstruct_tree(tapinfo: &TaprootSpendInfo) -> Option<NodeTree<'_>> {
    let root_hash = tapinfo.merkle_root()?;

    // First, build a map of all known nodes indexed by their hash using an intermediate Node structure
    enum Node<'a> {
        Leaf(&'a (ScriptBuf, LeafVersion)),
        Branch(TapNodeHash, TapNodeHash), // children referenced by hash, not an actual tree (yet)
    }
    let mut node_map = HashMap::new();

    for (script_leaf, merkle_branches) in tapinfo.script_map() {
        let leaf_hash = TapNodeHash::from_script(&script_leaf.0, script_leaf.1);
        node_map.insert(leaf_hash, Node::Leaf(script_leaf));

        // Process each merkle branch leading to this leaf script (there may multiple for duplicated scripts)
        for merkle_branch in merkle_branches {
            let mut current_hash = leaf_hash;
            for sibling_hash in merkle_branch.iter() {
                let branch_hash = TapNodeHash::from_node_hashes(current_hash, *sibling_hash); // XXX could cache
                node_map
                    .entry(branch_hash)
                    .or_insert_with(|| Node::Branch(current_hash, *sibling_hash));
                current_hash = branch_hash;
            }
            // All branches should converge to the root hash
            if current_hash != root_hash {
                return None;
            }
        }
    }

    // Now, going from the root node, convert the Node structure into a nested tree structure of NodeTree
    fn tree<'a>(hash: &TapNodeHash, map: &HashMap<TapNodeHash, Node<'a>>) -> NodeTree<'a> {
        match map.get(hash) {
            Some(Node::Branch(a, b)) => NodeTree::Branch(tree(a, map).into(), tree(b, map).into()),
            Some(Node::Leaf(leaf)) => NodeTree::Leaf(leaf),
            None => NodeTree::Hidden(*hash),
        }
    }
    Some(tree(&root_hash, &node_map))
}

impl<'a> ExprRepr for NodeTree<'a> {
    fn repr_fmt<W: fmt::Write>(&self, f: &mut W) -> fmt::Result {
        match self {
            NodeTree::Leaf((script, _)) => {
                // TODO leaf version not encoded
                write!(f, "script(0x{})", script.as_bytes().as_hex())
            }
            NodeTree::Branch(first, second) => {
                write!(f, "[")?;
                first.repr_fmt(f)?;
                write!(f, ",")?;
                second.repr_fmt(f)?;
                write!(f, "]")
            }
            NodeTree::Hidden(hash) => write!(f, "rawleaf(0x{})", hash),
            // TODO rawleaf() not yet implemented (https://github.com/bitcoin/bitcoin/pull/30243)
        }
    }
}
impl<'a> PrettyDisplay for NodeTree<'a> {
    const AUTOFMT_ENABLED: bool = true;

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        let (newline_or_space, inner_indent, indent_w, inner_indent_w) =
            util::indentation_params(indent);
        match self {
            NodeTree::Leaf((script, _)) => {
                // TODO leaf version not encoded
                write!(f, "{}", script.pretty(inner_indent))
            }
            NodeTree::Branch(first, second) => {
                let sep = format!("{newline_or_space}{:inner_indent_w$}", "");
                write!(f, "[{sep}{}", first.pretty(inner_indent))?;
                write!(f, ",{sep}{}", second.pretty(inner_indent))?;
                write!(f, "{newline_or_space}{:indent_w$}]", "")
            }
            NodeTree::Hidden(hash) => write!(f, "rawleaf(0x{})", hash),
        }
    }
}

impl PrettyDisplay for bitcoin::taproot::TapTree {
    const AUTOFMT_ENABLED: bool = false; // Enabled for the rendered NodeTree

    fn pretty_fmt<W: fmt::Write>(&self, f: &mut W, indent: Option<usize>) -> fmt::Result {
        // Construct a TaprootSpendInfo with a dummy key so that it may be used for reconstruct_tree()
        // TODO reconstructing the tree without going through TaprootSpendInfo is possible and more efficient.
        lazy_static! {
            static ref DUMMY_KEY: XOnlyPublicKey =
                "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
                    .parse()
                    .unwrap();
        }
        let tapinfo = TaprootSpendInfo::from_node_info(&EC, *DUMMY_KEY, self.node_info().clone());
        let tree = reconstruct_tree(&tapinfo).expect("invalid TapTree");
        write!(f, "{}", tree.pretty(indent))
    }
}

impl_simple_pretty!(TapLeafHash, h, "{}", h);
