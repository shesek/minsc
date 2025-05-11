use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::{TryFrom, TryInto};
use std::iter;
use std::marker::PhantomData;
use std::result::Result as StdResult;
use std::sync::Arc;

use bitcoin::bip32::{self, DerivationPath, IntoDerivationPath};
use bitcoin::hashes::Hash;
use bitcoin::taproot::{self, ControlBlock, LeafVersion, NodeInfo, TapNodeHash, TaprootSpendInfo};
use bitcoin::{key::TapTweak, psbt, secp256k1, PublicKey, ScriptBuf, Transaction};
use miniscript::descriptor::{
    self, DerivPaths, DescriptorMultiXKey, DescriptorPublicKey, DescriptorSecretKey, SinglePubKey,
    Wildcard,
};
use miniscript::{
    DefiniteDescriptorKey, Descriptor, ForEachKey, MiniscriptKey, TranslatePk, Translator,
};

use crate::runtime::{Array, Error, Result, Value};

lazy_static! {
    pub static ref EC: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

//
// Taproot
//

pub trait TapInfoExt {
    fn witness_program(&self) -> bitcoin::WitnessProgram;

    fn script_pubkey(&self) -> ScriptBuf {
        bitcoin::ScriptBuf::new_witness_program(&self.witness_program())
    }

    /// Construct a `TapNode` tree structure representation for this `TaprootSpendInfo`.
    /// Returns `None` if there are no script paths, panics if the `TaprootSpendInfo` has
    /// invalid merkle proofs (should be impossible to construct).
    fn script_tree(&self) -> Option<TapNode<'_>>;

    /// Reconstruct the `NodeInfo` for this `TaprootSpendInfo`.
    /// Returns `None` if there are no script paths, panics for invalid `TaprootSpendInfo`.
    fn node_info(&self) -> Option<NodeInfo> {
        let tree = self.script_tree()?;
        Some(tree.try_into().expect("should have valid tree depth"))
        // XXX it would be more efficient to construct the NodeInfo directly from the TaprootSpendInfo merkle proofs, without
        // going through TapNode. However, the rust-bitcoin API does not allow constructing NodeInfo with explicit merkle proofs.
        // Instead, this first expands into the TapNode tree structure, then flattens back using NodeInfo::combine().
    }
}

impl TapInfoExt for TaprootSpendInfo {
    fn witness_program(&self) -> bitcoin::WitnessProgram {
        bitcoin::WitnessProgram::p2tr_tweaked(self.output_key())
    }

    fn script_tree(&self) -> Option<TapNode<'_>> {
        let merkle_root = self.merkle_root()?;
        let tree = TapNode::from_script_map(self.script_map(), merkle_root)
            .expect("TaprootSpendInfo merkle proofs expected to be valid");
        Some(tree)
    }
}

/// A tree structure representation for Taproot scripts.
/// Unlike rust-bitcoin's TapTree/NodeInfo, which are flat.
#[derive(Debug)]
pub enum TapNode<'a> {
    Leaf(&'a (ScriptBuf, LeafVersion)),
    Branch(Box<TapNode<'a>>, Box<TapNode<'a>>),
    Hidden(TapNodeHash),
}

// The TaprootSpendInfo script_map structure
type ScriptMerkleProofMap =
    BTreeMap<(ScriptBuf, LeafVersion), BTreeSet<taproot::TaprootMerkleBranch>>;

impl TapNode<'_> {
    /// Construct the `TapNode` tree structure from the Taproot scripts, their merkle proofs and the merkle root.
    /// Returns `None` if any of the merkle proofs are invalid (don't connect to the root).
    pub fn from_script_map(
        script_map: &ScriptMerkleProofMap,
        merkle_root: TapNodeHash,
    ) -> Option<TapNode<'_>> {
        // First, build a map of all known nodes indexed by their hash, using an intermediate Node structure
        enum Node<'a> {
            Leaf(&'a (ScriptBuf, LeafVersion)),
            Branch(TapNodeHash, TapNodeHash), // children referenced by hash, not an actual tree (yet)
        }
        let mut node_map = HashMap::new();

        for (script_leaf, merkle_branches) in script_map {
            // Insert leaf nodes to map
            let leaf_hash = TapNodeHash::from_script(&script_leaf.0, script_leaf.1);
            node_map.insert(leaf_hash, Node::Leaf(script_leaf));

            // Process each merkle branch leading to this leaf script (there may multiple for duplicated scripts)
            for merkle_branch in merkle_branches {
                let mut current_hash = leaf_hash;
                for sibling_hash in merkle_branch.iter() {
                    // Insert branch nodes to map
                    let branch_hash = TapNodeHash::from_node_hashes(current_hash, *sibling_hash); // XXX could cache
                    node_map
                        .entry(branch_hash)
                        .or_insert_with(|| Node::Branch(current_hash, *sibling_hash));
                    current_hash = branch_hash;
                }
                // All branches should converge to the root hash
                if current_hash != merkle_root {
                    return None;
                }
            }
        }

        // Now, going from the root node, convert the intermediate Node structure into a nested TapNode tree structure
        fn tree<'a>(hash: &TapNodeHash, map: &HashMap<TapNodeHash, Node<'a>>) -> TapNode<'a> {
            match map.get(hash) {
                Some(Node::Branch(a, b)) => {
                    TapNode::Branch(tree(a, map).into(), tree(b, map).into())
                }
                Some(Node::Leaf(leaf)) => TapNode::Leaf(leaf),
                None => TapNode::Hidden(*hash),
            }
        }
        Some(tree(&merkle_root, &node_map))
    }
}

impl TryFrom<TapNode<'_>> for NodeInfo {
    // Can fail with InvalidMerkleTreeDepth if the TapNode depth exceeds the limit
    type Error = taproot::TaprootBuilderError;

    fn try_from(node: TapNode<'_>) -> StdResult<Self, Self::Error> {
        Ok(match node {
            TapNode::Branch(a, b) => NodeInfo::combine((*a).try_into()?, (*b).try_into()?)?,
            TapNode::Leaf((script, ver)) => NodeInfo::new_leaf_with_ver(script.clone(), *ver),
            TapNode::Hidden(hash) => NodeInfo::new_hidden_node(hash),
        })
    }
}

pub trait TapTreeExt {
    /// Construct a `ScriptMerkleProofMap` representation of this `TapTree` (same as used
    /// by `TaprootSpendInfo`), which can then be used to construct a `TapNode`/`NodeInfo`.
    fn script_map(&self) -> ScriptMerkleProofMap;
}
impl TapTreeExt for taproot::TapTree {
    fn script_map(&self) -> ScriptMerkleProofMap {
        let mut script_map = BTreeMap::new();
        for leaf in self.script_leaves() {
            script_map
                .entry((leaf.script().into(), leaf.version()))
                .or_insert_with(BTreeSet::new)
                .insert(leaf.merkle_branch().clone());
        }
        script_map
        // XXX could implement a TapNode::from_script_map() variant that accepts
        // the TapTree structure directly, so that its data doesn't have to be copied.
    }
}

//
// PSBT
//

pub trait PsbtInExt {
    /// Populate PSBT fields using the TaprootSpendInfo of the spent output
    fn update_with_taproot(&mut self, tapinfo: &TaprootSpendInfo) -> Result<()>;

    /// Populate PSBT fields using the PSBT of the spent transaction
    fn update_with_prevout_psbt(&mut self, prev_psbt: &psbt::Psbt, vout: usize) -> Result<()>;

    /// Populate PSBT fields using the spent transaction
    fn update_with_prevout_tx(&mut self, prev_tx: &Transaction, vout: usize) -> Result<()>;
}

impl PsbtInExt for psbt::Input {
    fn update_with_taproot(&mut self, tapinfo: &TaprootSpendInfo) -> Result<()> {
        self.tap_merkle_root = tapinfo.merkle_root();
        self.tap_internal_key = Some(tapinfo.internal_key());
        self.tap_scripts
            .extend(tapinfo.script_map().iter().map(|(script_ver, _)| {
                let ctrl = tapinfo.control_block(script_ver).expect("must exists");
                (ctrl, script_ver.clone())
            }));
        // `tap_key_origins` needs to be filled in manually
        Ok(())
    }

    fn update_with_prevout_psbt(&mut self, prev_psbt: &psbt::Psbt, vout: usize) -> Result<()> {
        self.update_with_prevout_tx(&prev_psbt.unsigned_tx, vout)?;

        let prevout = prev_psbt
            .outputs
            .get(vout)
            .ok_or_else(|| Error::PsbtOutputNotFound(vout))?;

        self.bip32_derivation
            .extend(prevout.bip32_derivation.clone());
        self.tap_key_origins.extend(prevout.tap_key_origins.clone());
        self.proprietary.extend(prevout.proprietary.clone());
        self.unknown.extend(prevout.unknown.clone());

        if let Some(witness_script) = &prevout.witness_script {
            self.witness_script = Some(witness_script.clone());
        }
        if let Some(redeem_script) = &prevout.redeem_script {
            self.redeem_script = Some(redeem_script.clone());
        }
        if let Some(internal_key) = prevout.tap_internal_key {
            self.tap_internal_key = Some(internal_key);
        }
        if let Some(tap_tree) = &prevout.tap_tree {
            let merkle_root = tap_tree.root_hash();
            self.tap_merkle_root = Some(merkle_root);

            // Convert the output's tap_tree into the input's tap_scripts (requires the internal key to be known)
            if let Some(internal_key) = self.tap_internal_key {
                let (_, output_key_parity) = internal_key.tap_tweak(&EC, Some(merkle_root));
                self.tap_scripts
                    .extend(tap_tree.script_leaves().map(|leaf| {
                        let ctrl = ControlBlock {
                            leaf_version: leaf.version(),
                            merkle_branch: leaf.merkle_branch().clone(),
                            internal_key,
                            output_key_parity,
                        };
                        (ctrl, (leaf.script().into(), leaf.version()))
                    }));
            }
        }

        Ok(())
    }

    fn update_with_prevout_tx(&mut self, prev_tx: &Transaction, vout: usize) -> Result<()> {
        self.witness_utxo = Some(
            prev_tx
                .output
                .get(vout)
                .ok_or_else(|| Error::PsbtOutputNotFound(vout))?
                .clone(),
        );
        Ok(())
    }
}

pub trait PsbtOutExt {
    /// Update PSBT fields using the TaprootSpendInfo
    fn update_with_taproot(&mut self, tapinfo: &TaprootSpendInfo) -> Result<()>;
}
impl PsbtOutExt for psbt::Output {
    fn update_with_taproot(&mut self, tapinfo: &TaprootSpendInfo) -> Result<()> {
        self.tap_internal_key = Some(tapinfo.internal_key());

        if let Some(node_info) = tapinfo.node_info() {
            // Can fail if the TaprootSpendInfo has hidden nodes
            if let Ok(tap_tree) = node_info.try_into() {
                self.tap_tree = Some(tap_tree);
            }
        }

        // `tap_key_origins` needs to be filled in manually
        Ok(())
    }
}

//
// Public/Secret Keys
//

pub trait DescriptorPubKeyExt: Sized {
    /// Convert into a definite pubkey. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn definite(self) -> Result<DefiniteDescriptorKey>;

    /// Convert into a derived pubkey. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn derive_definite(self) -> Result<bitcoin::PublicKey> {
        Ok(self.definite()?.derive_public_key(&EC)?)
    }

    /// Convert into a derived x-only pubkey. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn derive_xonly(self) -> Result<bitcoin::XOnlyPublicKey> {
        Ok(self.derive_definite()?.inner.into())
    }

    /// Return the derivation paths from the key itself, excluding the path from the origin key (unlike full_derivation_paths())
    fn derivation_paths(&self) -> Vec<DerivationPath>;

    /// Get the key 4-byte fingerprint
    fn fingerprint(&self) -> Result<bip32::Fingerprint>;

    /// Get the key HASH160 identifier
    fn identifier(&self) -> Result<bip32::XKeyIdentifier>;
}
impl DescriptorPubKeyExt for DescriptorPublicKey {
    fn definite(self) -> Result<DefiniteDescriptorKey> {
        ensure!(
            !self.has_wildcard(),
            Error::UnexpectedWildcardPubKey(self.clone().into())
        );
        ensure!(
            !self.is_multipath(),
            Error::UnexpectedMultiPathPubKey(self.clone().into())
        );
        Ok(self.at_derivation_index(0).expect("index is valid"))
    }

    fn derivation_paths(&self) -> Vec<DerivationPath> {
        match self {
            DescriptorPublicKey::MultiXPub(mxpub) => mxpub.derivation_paths.paths().clone(),
            DescriptorPublicKey::XPub(xpub) => vec![xpub.derivation_path.clone()],
            DescriptorPublicKey::Single(_) => vec![DerivationPath::master()],
        }
    }

    fn fingerprint(&self) -> Result<bip32::Fingerprint> {
        Ok(self.identifier()?[0..4].try_into().expect("valid length"))
    }

    fn identifier(&self) -> Result<bip32::XKeyIdentifier> {
        Ok(match self {
            // For xpubs, get the fingerprint of the final derivation key (not the master_fingerprint()'s)
            DescriptorPublicKey::XPub(dxpub) => dxpub
                .xkey
                .derive_pub(&EC, &dxpub.derivation_path)?
                .identifier(),
            // For single keys, use bitcoin's traditional PubkeyHash, which use the same HASH160 as BIP32 Key Identifiers,
            // and convert into an XKeyIdentifier
            DescriptorPublicKey::Single(single) => match single.key {
                SinglePubKey::FullKey(pk) => pk.pubkey_hash(),
                SinglePubKey::XOnly(pk) => bitcoin::PubkeyHash::hash(&pk.serialize()),
            }
            .to_raw_hash()
            .into(),
            DescriptorPublicKey::MultiXPub(_) => bail!(Error::InvalidMultiXpub),
        })
    }
}

pub trait DescriptorSecretKeyExt {
    // Mimicking the methods available on `DescriptorPublicKey`, which are not natively available for secret keys
    fn full_derivation_path(&self) -> Option<DerivationPath>;
    fn full_derivation_paths(&self) -> Vec<DerivationPath>;
    fn master_fingerprint(&self) -> bip32::Fingerprint;

    /// Return the derivation paths from the key itself, excluding the path from the origin key (unlike full_derivation_paths())
    fn derivation_paths(&self) -> Vec<DerivationPath>;

    // Pending https://github.com/rust-bitcoin/rust-miniscript/pull/757
    fn to_public_(&self) -> Result<DescriptorPublicKey>;
}
impl DescriptorSecretKeyExt for DescriptorSecretKey {
    fn master_fingerprint(&self) -> bip32::Fingerprint {
        match *self {
            DescriptorSecretKey::XPrv(ref xpub) => match xpub.origin {
                Some((fingerprint, _)) => fingerprint,
                None => xpub.xkey.fingerprint(&EC),
            },
            DescriptorSecretKey::MultiXPrv(ref xpub) => match xpub.origin {
                Some((fingerprint, _)) => fingerprint,
                None => xpub.xkey.fingerprint(&EC),
            },
            DescriptorSecretKey::Single(_) => self
                .to_public(&EC)
                .expect("cannot fail")
                .master_fingerprint(),
        }
    }
    fn full_derivation_path(&self) -> Option<DerivationPath> {
        match self {
            DescriptorSecretKey::XPrv(ref xpub) => {
                let origin_path = if let Some((_, ref path)) = xpub.origin {
                    path.clone()
                } else {
                    DerivationPath::from(vec![])
                };
                Some(origin_path.extend(&xpub.derivation_path))
            }
            DescriptorSecretKey::Single(ref single) => {
                Some(if let Some((_, ref path)) = single.origin {
                    path.clone()
                } else {
                    DerivationPath::from(vec![])
                })
            }
            DescriptorSecretKey::MultiXPrv(_) => None,
        }
    }

    fn full_derivation_paths(&self) -> Vec<DerivationPath> {
        match self {
            DescriptorSecretKey::MultiXPrv(xprv) => {
                let origin_path = if let Some((_, ref path)) = xprv.origin {
                    path.clone()
                } else {
                    DerivationPath::from(vec![])
                };
                xprv.derivation_paths
                    .paths()
                    .iter()
                    .map(|p| origin_path.extend(p))
                    .collect()
            }
            DescriptorSecretKey::XPrv(_) | DescriptorSecretKey::Single(_) => vec![self
                .full_derivation_path()
                .expect("Must be Some for non-multipath keys")],
        }
    }

    fn derivation_paths(&self) -> Vec<DerivationPath> {
        match self {
            DescriptorSecretKey::MultiXPrv(mxprv) => mxprv.derivation_paths.paths().clone(),
            DescriptorSecretKey::XPrv(xprv) => vec![xprv.derivation_path.clone()],
            DescriptorSecretKey::Single(_) => vec![DerivationPath::master()],
        }
    }

    fn to_public_(&self) -> Result<DescriptorPublicKey> {
        Ok(match self {
            DescriptorSecretKey::Single(_) | DescriptorSecretKey::XPrv(_) => self.to_public(&EC)?,
            DescriptorSecretKey::MultiXPrv(mxprv) => {
                DescriptorPublicKey::MultiXPub(multi_xpriv_to_public(mxprv)?)
            }
        })
    }
}

//
// Miniscript
//

pub trait MiniscriptExt<T: miniscript::ScriptContext> {
    fn derive_keys(self) -> Result<miniscript::Miniscript<PublicKey, T>>;
}

impl<Ctx: miniscript::ScriptContext> MiniscriptExt<Ctx>
    for miniscript::Miniscript<DescriptorPublicKey, Ctx>
{
    fn derive_keys(self) -> Result<miniscript::Miniscript<PublicKey, Ctx>> {
        Ok(
            self.translate_pk(&mut FnTranslator::new(|xpk: &DescriptorPublicKey| {
                xpk.clone().derive_definite()
            }))?,
        )
    }
}

//
// Descriptors
//

pub trait DescriptorExt {
    /// Convert into a Descriptor over definite pubkeys. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn definite(&self) -> Result<Descriptor<DefiniteDescriptorKey>>;

    /// Convert into a Descriptor over derived pubkeys. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn derive_definite(&self) -> Result<Descriptor<PublicKey>> {
        Ok(self.definite()?.derived_descriptor(&EC)?)
    }

    /// Get the scriptPubKey. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn to_script_pubkey(&self) -> Result<bitcoin::ScriptBuf> {
        Ok(self.derive_definite()?.script_pubkey())
    }

    /// Get the explicit script. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn to_explicit_script(&self) -> Result<bitcoin::ScriptBuf> {
        Ok(self.derive_definite()?.explicit_script()?)
    }

    /// Get the address. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn to_address(&self, network: bitcoin::Network) -> Result<bitcoin::Address> {
        Ok(self.derive_definite()?.address(network)?)
    }

    /// Get the witness program. Errors if the descriptor contains underived wildcards or multi-path derivations.
    fn witness_program(&self) -> Result<Option<bitcoin::WitnessProgram>> {
        Ok(self
            .to_address(bitcoin::Network::Bitcoin)?
            .witness_program())
    }

    /// Get the inner Tr, if it is a Tr descriptors
    fn tr(&self) -> Option<&descriptor::Tr<DescriptorPublicKey>>;

    /// Get a TaprootSpendInfo representation of this Tr descriptor
    /// Returna an Ok(None) for non-Taproot descriptors, or an Err for Taproot
    /// descriptors that are not definite (contain underived wildcards).
    fn tap_info(&self) -> Result<Option<Arc<TaprootSpendInfo>>>;
}

impl DescriptorExt for Descriptor<DescriptorPublicKey> {
    fn definite(&self) -> Result<Descriptor<DefiniteDescriptorKey>> {
        ensure!(
            !self.has_wildcard(),
            Error::UnexpectedWildcardDescriptor(self.clone().into())
        );
        ensure!(
            !self.is_multipath(),
            Error::UnexpectedMultiPathDescriptor(self.clone().into())
        );
        Ok(self.at_derivation_index(0).expect("index is valid"))
    }

    fn tr(&self) -> Option<&descriptor::Tr<DescriptorPublicKey>> {
        match self {
            Descriptor::Tr(tr) => Some(tr),
            _ => None,
        }
    }

    fn tap_info(&self) -> Result<Option<Arc<TaprootSpendInfo>>> {
        if matches!(self, Descriptor::Tr(_)) {
            Ok(match self.definite()? {
                Descriptor::Tr(tr) => Some(tr.spend_info().clone()),
                _ => unreachable!(),
            })
        } else {
            Ok(None)
        }
    }
}

//
// BIP32 derivation
//

pub trait DeriveExt: Sized {
    /// Always derives when called directly on Xpubs/Xprivs, even if their wildcard modifier
    /// was not enabled. Calling directly on single keys raises an error.
    /// For Policies/Descriptors, inner xpubs with wildcards are derived (at least
    /// one is required) while non-wildcard/single inner keys are left as-is.
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self>;

    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self>;

    /// Whether there are any Xpubs/Xprivs with wildcards
    fn has_wildcards(&self) -> bool;

    /// Derive if there are wildcards. Unlike derive_path(), this is a no-op for single and non-wildcard keys
    fn maybe_derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self>
    where
        Self: Sized,
    {
        if self.has_wildcards() {
            self.derive_path(path, wildcard)
        } else {
            Ok(self)
        }
    }

    fn maybe_derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self>
    where
        Self: Sized,
    {
        if self.has_wildcards() {
            self.derive_multi(paths, wildcard)
        } else {
            Ok(self)
        }
    }
}

pub trait DerivePath: IntoDerivationPath + Clone {} // trait alias
impl<T: IntoDerivationPath + Clone> DerivePath for T {}

impl DeriveExt for DescriptorPublicKey {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        let path = path.into_derivation_path()?;
        match self {
            DescriptorPublicKey::XPub(mut xpub) => {
                xpub.derivation_path = xpub.derivation_path.extend(path);
                xpub.wildcard = wildcard;
                Ok(DescriptorPublicKey::XPub(xpub))
            }
            DescriptorPublicKey::MultiXPub(mut mxpub) => {
                mxpub.derivation_paths = DerivPaths::new(
                    mxpub
                        .derivation_paths
                        .into_paths()
                        .into_iter()
                        .map(|mx_path| mx_path.extend(&path))
                        .collect(),
                )
                .expect("path cannot be empty");
                mxpub.wildcard = wildcard;
                Ok(DescriptorPublicKey::MultiXPub(mxpub))
            }
            DescriptorPublicKey::Single(_) => bail!(Error::NonDeriveableSingle),
        }
    }

    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        let paths = paths
            .iter()
            .map(|p| Ok(p.clone().into_derivation_path()?))
            .collect::<Result<Vec<_>>>()?;

        let parent_paths = self.derivation_paths();

        let derived_paths = parent_paths
            .into_iter()
            .flat_map(|parent_path| paths.iter().map(move |path| parent_path.extend(path)))
            .collect::<Vec<_>>();

        let (origin, xkey) = match self {
            DescriptorPublicKey::XPub(xpub) => (xpub.origin, xpub.xkey),
            DescriptorPublicKey::MultiXPub(mxpub) => (mxpub.origin, mxpub.xkey),
            DescriptorPublicKey::Single(_) => bail!(Error::NonDeriveableSingle),
        };
        Ok(DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin,
            xkey,
            derivation_paths: DerivPaths::new(derived_paths).expect("cannot be empty"),
            wildcard,
        }))
    }
    fn has_wildcards(&self) -> bool {
        self.has_wildcard()
    }
}

// much code duplication, so wow ^.^
impl DeriveExt for DescriptorSecretKey {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        let path = path.into_derivation_path()?;
        match self {
            DescriptorSecretKey::XPrv(mut xprv) => {
                xprv.derivation_path = xprv.derivation_path.extend(path);
                xprv.wildcard = wildcard;
                Ok(DescriptorSecretKey::XPrv(xprv))
            }
            DescriptorSecretKey::MultiXPrv(mut mxprv) => {
                mxprv.derivation_paths = DerivPaths::new(
                    mxprv
                        .derivation_paths
                        .into_paths()
                        .into_iter()
                        .map(|mx_path| mx_path.extend(&path))
                        .collect(),
                )
                .expect("path cannot be empty");
                mxprv.wildcard = wildcard;
                Ok(DescriptorSecretKey::MultiXPrv(mxprv))
            }
            DescriptorSecretKey::Single(_) => bail!(Error::NonDeriveableSingle),
        }
    }

    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        let paths = paths
            .iter()
            .map(|p| Ok(p.clone().into_derivation_path()?))
            .collect::<Result<Vec<DerivationPath>>>()?;

        let parent_paths = self.derivation_paths();

        let derived_paths = parent_paths
            .into_iter()
            .flat_map(|parent_path| paths.iter().map(move |path| parent_path.extend(path)))
            .collect::<Vec<_>>();

        let (origin, xkey) = match self {
            DescriptorSecretKey::XPrv(xprv) => (xprv.origin, xprv.xkey),
            DescriptorSecretKey::MultiXPrv(mxpriv) => (mxpriv.origin, mxpriv.xkey),
            DescriptorSecretKey::Single(_) => bail!(Error::NonDeriveableSingle),
        };
        Ok(DescriptorSecretKey::MultiXPrv(DescriptorMultiXKey {
            origin,
            xkey,
            derivation_paths: DerivPaths::new(derived_paths).expect("cannot be empty"),
            wildcard,
        }))
    }
    fn has_wildcards(&self) -> bool {
        match self {
            DescriptorSecretKey::Single(..) => false,
            DescriptorSecretKey::XPrv(xprv) => xprv.wildcard != Wildcard::None,
            DescriptorSecretKey::MultiXPrv(xprv) => xprv.wildcard != Wildcard::None,
        }
    }
}

impl DeriveExt for crate::PolicyDpk {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        let path = path.into_derivation_path()?;
        self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
            pk.clone().maybe_derive_path(path.clone(), wildcard)
        }))
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
            pk.clone().maybe_derive_multi(paths, wildcard)
        }))
    }
    fn has_wildcards(&self) -> bool {
        self.for_any_key(DeriveExt::has_wildcards)
    }
}

impl DeriveExt for crate::DescriptorDpk {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        let path = path.into_derivation_path()?;
        Ok(
            self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
                pk.clone().maybe_derive_path(path.clone(), wildcard)
            }))?,
        )
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        Ok(
            self.translate_pk(&mut FnTranslator::new(|pk: &DescriptorPublicKey| {
                pk.clone().maybe_derive_multi(paths, wildcard)
            }))?,
        )
    }
    fn has_wildcards(&self) -> bool {
        self.has_wildcard()
    }
}

impl DeriveExt for Value {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        Ok(match self {
            Value::PubKey(pubkey) => pubkey.derive_path(path, wildcard)?.into(),
            Value::SecKey(seckey) => seckey.derive_path(path, wildcard)?.into(),
            Value::Descriptor(desc) => desc.derive_path(path, wildcard)?.into(),
            Value::Policy(policy) => policy.derive_path(path, wildcard)?.into(),
            Value::Array(array) => array.derive_path(path, wildcard)?.into(),
            _ => bail!(Error::NonDeriveableType),
        })
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        Ok(match self {
            Value::PubKey(pubkey) => pubkey.derive_multi(paths, wildcard)?.into(),
            Value::SecKey(seckey) => seckey.derive_multi(paths, wildcard)?.into(),
            Value::Descriptor(desc) => desc.derive_multi(paths, wildcard)?.into(),
            Value::Policy(policy) => policy.derive_multi(paths, wildcard)?.into(),
            Value::Array(array) => array.derive_multi(paths, wildcard)?.into(),
            _ => bail!(Error::NonDeriveableType),
        })
    }
    fn has_wildcards(&self) -> bool {
        match self {
            Value::PubKey(pubkey) => pubkey.has_wildcards(),
            Value::SecKey(seckey) => seckey.has_wildcards(),
            Value::Descriptor(desc) => desc.has_wildcards(),
            Value::Policy(policy) => policy.has_wildcards(),
            Value::Array(array) => array.has_wildcards(),
            _ => false,
        }
    }
}

impl DeriveExt for Array {
    fn derive_path<P: DerivePath>(self, path: P, wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        Ok(Array(
            self.into_iter()
                .map(|v| v.maybe_derive_path(path.clone(), wildcard))
                .collect::<Result<_>>()?,
        ))
    }
    fn derive_multi<P: DerivePath>(self, paths: &[P], wildcard: Wildcard) -> Result<Self> {
        ensure!(self.has_wildcards(), Error::NonDeriveableNoWildcard);
        Ok(Array(
            self.into_iter()
                .map(|v| v.maybe_derive_multi(paths, wildcard))
                .collect::<Result<_>>()?,
        ))
    }
    fn has_wildcards(&self) -> bool {
        self.iter().any(DeriveExt::has_wildcards)
    }
}

// A `Translator` for keys using a closure function, similar to
// the `TranslatePk2` available in prior rust-miniscript releases
struct FnTranslator<P: MiniscriptKey, Q: MiniscriptKey, F: Fn(&P) -> Result<Q>> {
    func: F,
    _marker: PhantomData<(P, Q)>,
}

impl<P: MiniscriptKey, Q: MiniscriptKey, F: Fn(&P) -> Result<Q>> FnTranslator<P, Q, F> {
    pub fn new(func: F) -> Self {
        FnTranslator {
            func,
            _marker: PhantomData,
        }
    }
}

impl<P, Q, F> Translator<P, Q, Error> for FnTranslator<P, Q, F>
where
    P: MiniscriptKey,
    // hashes are passed through as-is, P and Q must share the same hash types
    Q: MiniscriptKey<
        Sha256 = P::Sha256,
        Hash256 = P::Hash256,
        Ripemd160 = P::Ripemd160,
        Hash160 = P::Hash160,
    >,
    F: Fn(&P) -> Result<Q>,
{
    fn pk(&mut self, pk: &P) -> Result<Q> {
        (self.func)(pk)
    }

    fn sha256(&mut self, sha256: &P::Sha256) -> Result<Q::Sha256> {
        Ok(sha256.clone())
    }
    fn hash256(&mut self, hash256: &P::Hash256) -> Result<Q::Hash256> {
        Ok(hash256.clone())
    }
    fn ripemd160(&mut self, ripemd160: &P::Ripemd160) -> Result<Q::Ripemd160> {
        Ok(ripemd160.clone())
    }
    fn hash160(&mut self, ripemd160: &P::Hash160) -> Result<Q::Hash160> {
        Ok(ripemd160.clone())
    }
    // XXX could use miniscript::translate_hash_clone!() if is used std::result:Result or if we avoided replacing Result with a type alias
}

// Pending https://github.com/rust-bitcoin/rust-miniscript/pull/757
fn multi_xpriv_to_public(
    mxprv: &DescriptorMultiXKey<bip32::Xpriv>,
) -> Result<DescriptorMultiXKey<bip32::Xpub>> {
    assert!(
        !mxprv.derivation_paths.paths().is_empty(),
        "MultiXkey is never empty"
    );

    let deriv_paths = mxprv.derivation_paths.paths();

    let shared_prefix: Vec<_> = deriv_paths[0]
        .into_iter()
        .enumerate()
        .take_while(|(index, child_num)| {
            deriv_paths[1..]
                .iter()
                .all(|other_path| other_path.len() > *index && other_path[*index] == **child_num)
        })
        .map(|(_, child_num)| *child_num)
        .collect();

    let suffixes: Vec<Vec<_>> = deriv_paths
        .iter()
        .map(|path| {
            path.into_iter()
                .skip(shared_prefix.len())
                .map(|child_num| {
                    // Hardended derivation steps are only allowed within the shared prefix
                    ensure!(child_num.is_normal(), Error::InvalidHardenedMultiXprvToXpub);
                    Ok(*child_num)
                })
                .collect()
        })
        .collect::<Result<_>>()?;

    let unhardened = shared_prefix
        .iter()
        .rev()
        .take_while(|c| c.is_normal())
        .count();
    let last_hardened_idx = shared_prefix.len() - unhardened;

    let hardened_path = &shared_prefix[..last_hardened_idx];
    let unhardened_path = &shared_prefix[last_hardened_idx..];

    let xprv = mxprv.xkey.derive_priv(&EC, &hardened_path)?;
    let xpub = bip32::Xpub::from_priv(&EC, &xprv);

    let origin = match &mxprv.origin {
        Some((fingerprint, path)) => Some((
            *fingerprint,
            path.into_iter()
                .chain(hardened_path.iter())
                .copied()
                .collect(),
        )),
        None if !hardened_path.is_empty() => {
            Some((mxprv.xkey.fingerprint(&EC), hardened_path.into()))
        }
        None => None,
    };
    let new_deriv_paths = suffixes
        .into_iter()
        .map(|suffix| {
            let path = unhardened_path.iter().copied().chain(suffix);
            path.collect::<Vec<_>>().into()
        })
        .collect();

    Ok(DescriptorMultiXKey {
        origin,
        xkey: xpub,
        derivation_paths: DerivPaths::new(new_deriv_paths).expect("not empty"),
        wildcard: mxprv.wildcard,
    })
}
pub trait PeekableExt: Iterator {
    /// Like take_while(), but borrows checked items and doesn't consume the last non-matching one
    /// Similarly to https://docs.rs/itertools/latest/itertools/trait.Itertools.html#method.peeking_take_while
    fn peeking_take_while<F>(&mut self, accept: F) -> impl Iterator<Item = Self::Item>
    where
        F: FnMut(&Self::Item) -> bool + Copy;
}

impl<I: Iterator> PeekableExt for iter::Peekable<I> {
    fn peeking_take_while<F>(&mut self, accept: F) -> impl Iterator<Item = Self::Item>
    where
        F: FnMut(&Self::Item) -> bool + Copy,
    {
        // h/t https://www.reddit.com/r/rust/comments/f8ae6q/comment/jwuyzgo/
        iter::from_fn(move || self.next_if(accept))
    }
}
