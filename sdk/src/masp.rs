//! MASP verification wrappers.

use std::collections::{btree_map, BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::fmt::Debug;
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;

// use async_std::io::prelude::WriteExt;
// use async_std::io::{self};
use borsh::{BorshDeserialize, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use itertools::Either;
use lazy_static::lazy_static;
use masp_primitives::asset_type::AssetType;
#[cfg(feature = "mainnet")]
use masp_primitives::consensus::MainNetwork;
#[cfg(not(feature = "mainnet"))]
use masp_primitives::consensus::TestNetwork;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::ff::PrimeField;
use masp_primitives::group::GroupEncoding;
use masp_primitives::memo::MemoBytes;
use masp_primitives::merkle_tree::{
    CommitmentTree, IncrementalWitness, MerklePath,
};
use masp_primitives::sapling::keys::FullViewingKey;
use masp_primitives::sapling::note_encryption::*;
use masp_primitives::sapling::redjubjub::PublicKey;
use masp_primitives::sapling::{
    Diversifier, Node, Note, Nullifier, ViewingKey,
};
use masp_primitives::transaction::builder::{self, *};
use masp_primitives::transaction::components::sapling::builder::SaplingMetadata;
use masp_primitives::transaction::components::transparent::builder::TransparentBuilder;
use masp_primitives::transaction::components::{
    ConvertDescription, I128Sum, OutputDescription, SpendDescription, TxOut,
    U64Sum,
};
use masp_primitives::transaction::fees::fixed::FeeRule;
use masp_primitives::transaction::sighash::{signature_hash, SignableInput};
use masp_primitives::transaction::txid::TxIdDigester;
use masp_primitives::transaction::{
    Authorization, Authorized, Transaction, TransactionData,
    TransparentAddress, Unauthorized,
};
use masp_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use masp_proofs::bellman::groth16::PreparedVerifyingKey;
use masp_proofs::bls12_381::Bls12;
use masp_proofs::prover::LocalTxProver;
use masp_proofs::sapling::SaplingVerificationContext;
use namada_core::ledger::ibc::IbcMessage;
use namada_core::types::address::{Address, MASP};
use namada_core::types::ibc::IbcShieldedTransfer;
use namada_core::types::masp::{
    BalanceOwner, ExtendedViewingKey, PaymentAddress, TransferSource,
    TransferTarget,
};
use namada_core::types::storage::{BlockHeight, Epoch, IndexedTx, TxIndex};
use namada_core::types::time::{DateTimeUtc, DurationSecs};
use namada_core::types::token;
use namada_core::types::token::{Change, MaspDenom, Transfer};
use namada_core::types::transaction::{TxResult, WrapperTx};
use rand_core::{CryptoRng, OsRng, RngCore};
use ripemd::Digest as RipemdDigest;
use sha2::Digest;
use thiserror::Error;

#[cfg(feature = "testing")]
use crate::error::EncodingError;
use crate::error::{Error, PinnedBalanceError, QueryError};
use crate::io::Io;
use crate::proto::Tx;
use crate::queries::Client;
use crate::rpc::{query_block, query_conversion, query_epoch_at_height};
use crate::tendermint_rpc::query::Query;
use crate::tendermint_rpc::Order;
use crate::tx::decode_component;
use crate::{display_line, edisplay_line, rpc, MaybeSend, MaybeSync, Namada};

/// Env var to point to a dir with MASP parameters. When not specified,
/// the default OS specific path is used.
pub const ENV_VAR_MASP_PARAMS_DIR: &str = "NAMADA_MASP_PARAMS_DIR";

/// Env var to either "save" proofs into files or to "load" them from
/// files.
pub const ENV_VAR_MASP_TEST_PROOFS: &str = "NAMADA_MASP_TEST_PROOFS";

/// Randomness seed for MASP integration tests to build proofs with
/// deterministic rng.
pub const ENV_VAR_MASP_TEST_SEED: &str = "NAMADA_MASP_TEST_SEED";

/// A directory to save serialized proofs for tests.
pub const MASP_TEST_PROOFS_DIR: &str = "test_fixtures/masp_proofs";

/// The network to use for MASP
#[cfg(feature = "mainnet")]
const NETWORK: MainNetwork = MainNetwork;
#[cfg(not(feature = "mainnet"))]
const NETWORK: TestNetwork = TestNetwork;

// TODO these could be exported from masp_proof crate
/// Spend circuit name
pub const SPEND_NAME: &str = "masp-spend.params";
/// Output circuit name
pub const OUTPUT_NAME: &str = "masp-output.params";
/// Convert circuit name
pub const CONVERT_NAME: &str = "masp-convert.params";

/// Shielded transfer
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ShieldedTransfer {
    /// Shielded transfer builder
    pub builder: Builder<(), (), ExtendedFullViewingKey, ()>,
    /// MASP transaction
    pub masp_tx: Transaction,
    /// Metadata
    pub metadata: SaplingMetadata,
    /// Epoch in which the transaction was created
    pub epoch: Epoch,
}

#[cfg(feature = "testing")]
#[derive(Clone, Copy, Debug)]
enum LoadOrSaveProofs {
    Load,
    Save,
    Neither,
}

/// A return type for gen_shielded_transfer
#[derive(Error, Debug)]
pub enum TransferErr {
    /// Build error for masp errors
    #[error("{0}")]
    Build(#[from] builder::Error<std::convert::Infallible>),
    /// errors
    #[error("{0}")]
    General(#[from] Error),
}

/// MASP verifying keys
pub struct PVKs {
    /// spend verifying key
    spend_vk: PreparedVerifyingKey<Bls12>,
    /// convert verifying key
    convert_vk: PreparedVerifyingKey<Bls12>,
    /// output verifying key
    output_vk: PreparedVerifyingKey<Bls12>,
}

lazy_static! {
    /// MASP verifying keys load from parameters
    static ref VERIFIYING_KEYS: PVKs =
        {
        let params_dir = get_params_dir();
        let [spend_path, convert_path, output_path] =
            [SPEND_NAME, CONVERT_NAME, OUTPUT_NAME].map(|p| params_dir.join(p));

        #[cfg(feature = "download-params")]
        if !spend_path.exists() || !convert_path.exists() || !output_path.exists() {
            let paths = masp_proofs::download_masp_parameters(None).expect(
                "MASP parameters were not present, expected the download to \
                succeed",
            );
            if paths.spend != spend_path
                || paths.convert != convert_path
                || paths.output != output_path
            {
                panic!(
                    "unrecoverable: downloaded missing masp params, but to an \
                    unfamiliar path"
                )
            }
        }
        // size and blake2b checked here
        let params = masp_proofs::load_parameters(
            spend_path.as_path(),
            output_path.as_path(),
            convert_path.as_path(),
        );
        PVKs {
            spend_vk: params.spend_vk,
            convert_vk: params.convert_vk,
            output_vk: params.output_vk
        }
    };
}

/// Make sure the MASP params are present and load verifying keys into memory
pub fn preload_verifying_keys() -> &'static PVKs {
    &VERIFIYING_KEYS
}

fn load_pvks() -> &'static PVKs {
    &VERIFIYING_KEYS
}

/// check_spend wrapper
pub fn check_spend(
    spend: &SpendDescription<<Authorized as Authorization>::SaplingAuth>,
    sighash: &[u8; 32],
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(spend.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };
    ctx.check_spend(
        spend.cv,
        spend.anchor,
        &spend.nullifier.0,
        PublicKey(spend.rk.0),
        sighash,
        spend.spend_auth_sig,
        zkproof,
        parameters,
    )
}

/// check_output wrapper
pub fn check_output(
    output: &OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>,
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(output.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };
    let epk =
        masp_proofs::jubjub::ExtendedPoint::from_bytes(&output.ephemeral_key.0);
    let epk = match epk.into() {
        Some(p) => p,
        None => return false,
    };
    ctx.check_output(output.cv, output.cmu, epk, zkproof, parameters)
}

/// check convert wrapper
pub fn check_convert(
    convert: &ConvertDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>,
    ctx: &mut SaplingVerificationContext,
    parameters: &PreparedVerifyingKey<Bls12>,
) -> bool {
    let zkproof =
        masp_proofs::bellman::groth16::Proof::read(convert.zkproof.as_slice());
    let zkproof = match zkproof {
        Ok(zkproof) => zkproof,
        _ => return false,
    };
    ctx.check_convert(convert.cv, convert.anchor, zkproof, parameters)
}

/// Represents an authorization where the Sapling bundle is authorized and the
/// transparent bundle is unauthorized.
pub struct PartialAuthorized;

impl Authorization for PartialAuthorized {
    type SaplingAuth = <Authorized as Authorization>::SaplingAuth;
    type TransparentAuth = <Unauthorized as Authorization>::TransparentAuth;
}

/// Partially deauthorize the transparent bundle
fn partial_deauthorize(
    tx_data: &TransactionData<Authorized>,
) -> Option<TransactionData<PartialAuthorized>> {
    let transp = tx_data.transparent_bundle().and_then(|x| {
        let mut tb = TransparentBuilder::empty();
        for vin in &x.vin {
            tb.add_input(TxOut {
                asset_type: vin.asset_type,
                value: vin.value,
                address: vin.address,
            })
            .ok()?;
        }
        for vout in &x.vout {
            tb.add_output(&vout.address, vout.asset_type, vout.value)
                .ok()?;
        }
        tb.build()
    });
    if tx_data.transparent_bundle().is_some() != transp.is_some() {
        return None;
    }
    Some(TransactionData::from_parts(
        tx_data.version(),
        tx_data.consensus_branch_id(),
        tx_data.lock_time(),
        tx_data.expiry_height(),
        transp,
        tx_data.sapling_bundle().cloned(),
    ))
}

/// Verify a shielded transaction.
pub fn verify_shielded_tx(transaction: &Transaction) -> bool {
    tracing::info!("entered verify_shielded_tx()");

    let sapling_bundle = if let Some(bundle) = transaction.sapling_bundle() {
        bundle
    } else {
        return false;
    };
    let tx_data = transaction.deref();

    // Partially deauthorize the transparent bundle
    let unauth_tx_data = match partial_deauthorize(tx_data) {
        Some(tx_data) => tx_data,
        None => return false,
    };

    let txid_parts = unauth_tx_data.digest(TxIdDigester);
    // the commitment being signed is shared across all Sapling inputs; once
    // V4 transactions are deprecated this should just be the txid, but
    // for now we need to continue to compute it here.
    let sighash =
        signature_hash(&unauth_tx_data, &SignableInput::Shielded, &txid_parts);

    tracing::info!("sighash computed");

    let PVKs {
        spend_vk,
        convert_vk,
        output_vk,
    } = load_pvks();

    let mut ctx = SaplingVerificationContext::new(true);
    let spends_valid = sapling_bundle
        .shielded_spends
        .iter()
        .all(|spend| check_spend(spend, sighash.as_ref(), &mut ctx, spend_vk));
    let converts_valid = sapling_bundle
        .shielded_converts
        .iter()
        .all(|convert| check_convert(convert, &mut ctx, convert_vk));
    let outputs_valid = sapling_bundle
        .shielded_outputs
        .iter()
        .all(|output| check_output(output, &mut ctx, output_vk));

    if !(spends_valid && outputs_valid && converts_valid) {
        return false;
    }

    tracing::info!("passed spend/output verification");

    let assets_and_values: I128Sum = sapling_bundle.value_balance.clone();

    tracing::info!(
        "accumulated {} assets/values",
        assets_and_values.components().len()
    );

    let result = ctx.final_check(
        assets_and_values,
        sighash.as_ref(),
        sapling_bundle.authorization.binding_sig,
    );
    tracing::info!("final check result {result}");
    result
}

/// Get the path to MASP parameters from [`ENV_VAR_MASP_PARAMS_DIR`] env var or
/// use the default.
pub fn get_params_dir() -> PathBuf {
    if let Ok(params_dir) = env::var(ENV_VAR_MASP_PARAMS_DIR) {
        println!("Using {} as masp parameter folder.", params_dir);
        PathBuf::from(params_dir)
    } else {
        masp_proofs::default_params_folder().unwrap()
    }
}

/// Freeze a Builder into the format necessary for inclusion in a Tx. This is
/// the format used by hardware wallets to validate a MASP Transaction.
struct WalletMap;

impl<P1>
    masp_primitives::transaction::components::sapling::builder::MapBuilder<
        P1,
        ExtendedSpendingKey,
        (),
        ExtendedFullViewingKey,
    > for WalletMap
{
    fn map_params(&self, _s: P1) {}

    fn map_key(&self, s: ExtendedSpendingKey) -> ExtendedFullViewingKey {
        (&s).into()
    }
}

impl<P1, R1, N1>
    MapBuilder<
        P1,
        R1,
        ExtendedSpendingKey,
        N1,
        (),
        (),
        ExtendedFullViewingKey,
        (),
    > for WalletMap
{
    fn map_rng(&self, _s: R1) {}

    fn map_notifier(&self, _s: N1) {}
}

/// Abstracts platform specific details away from the logic of shielded pool
/// operations.
#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
pub trait ShieldedUtils:
    Sized + BorshDeserialize + BorshSerialize + Default + Clone
{
    /// Get a MASP transaction prover
    fn local_tx_prover(&self) -> LocalTxProver;

    /// Load up the currently saved ShieldedContext
    async fn load<U: ShieldedUtils + MaybeSend>(
        &self,
        ctx: &mut ShieldedContext<U>,
    ) -> std::io::Result<()>;

    /// Save the given ShieldedContext for future loads
    async fn save<U: ShieldedUtils + MaybeSync>(
        &self,
        ctx: &ShieldedContext<U>,
    ) -> std::io::Result<()>;
}

/// Make a ViewingKey that can view notes encrypted by given ExtendedSpendingKey
pub fn to_viewing_key(esk: &ExtendedSpendingKey) -> FullViewingKey {
    ExtendedFullViewingKey::from(esk).fvk
}

/// Generate a valid diversifier, i.e. one that has a diversified base. Return
/// also this diversified base.
pub fn find_valid_diversifier<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (Diversifier, masp_primitives::jubjub::SubgroupPoint) {
    let mut diversifier;
    let g_d;
    // Keep generating random diversifiers until one has a diversified base
    loop {
        let mut d = [0; 11];
        rng.fill_bytes(&mut d);
        diversifier = Diversifier(d);
        if let Some(val) = diversifier.g_d() {
            g_d = val;
            break;
        }
    }
    (diversifier, g_d)
}

/// Determine if using the current note would actually bring us closer to our
/// target
pub fn is_amount_required(src: I128Sum, dest: I128Sum, delta: I128Sum) -> bool {
    let gap = dest - src;
    for (asset_type, value) in gap.components() {
        if *value >= 0 && delta[asset_type] >= 0 {
            return true;
        }
    }
    false
}

// #[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
// pub struct MaspAmount {
//     pub asset: Address,
//     pub amount: token::Amount,
// }

/// a masp change
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct MaspChange {
    /// the token address
    pub asset: Address,
    /// the change in the token
    pub change: token::Change,
}

/// a masp amount
#[derive(
    BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct MaspAmount(HashMap<(Epoch, Address), token::Change>);

impl std::ops::Deref for MaspAmount {
    type Target = HashMap<(Epoch, Address), token::Change>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for MaspAmount {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::ops::Add for MaspAmount {
    type Output = MaspAmount;

    fn add(mut self, mut rhs: MaspAmount) -> Self::Output {
        for (key, value) in rhs.drain() {
            self.entry(key)
                .and_modify(|val| *val += value)
                .or_insert(value);
        }
        self.retain(|_, v| !v.is_zero());
        self
    }
}

impl std::ops::AddAssign for MaspAmount {
    fn add_assign(&mut self, amount: MaspAmount) {
        *self = self.clone() + amount
    }
}

// please stop copying and pasting make a function
impl std::ops::Sub for MaspAmount {
    type Output = MaspAmount;

    fn sub(mut self, mut rhs: MaspAmount) -> Self::Output {
        for (key, value) in rhs.drain() {
            self.entry(key)
                .and_modify(|val| *val -= value)
                .or_insert(-value);
        }
        self.0.retain(|_, v| !v.is_zero());
        self
    }
}

impl std::ops::SubAssign for MaspAmount {
    fn sub_assign(&mut self, amount: MaspAmount) {
        *self = self.clone() - amount
    }
}

impl std::ops::Mul<Change> for MaspAmount {
    type Output = Self;

    fn mul(mut self, rhs: Change) -> Self::Output {
        for (_, value) in self.iter_mut() {
            *value = *value * rhs
        }
        self
    }
}

impl<'a> From<&'a MaspAmount> for I128Sum {
    fn from(masp_amount: &'a MaspAmount) -> I128Sum {
        let mut res = I128Sum::zero();
        for ((epoch, token), val) in masp_amount.iter() {
            for denom in MaspDenom::iter() {
                let asset =
                    make_asset_type(Some(*epoch), token, denom).unwrap();
                res += I128Sum::from_pair(asset, denom.denominate_i128(val))
                    .unwrap();
            }
        }
        res
    }
}

impl From<MaspAmount> for I128Sum {
    fn from(amt: MaspAmount) -> Self {
        Self::from(&amt)
    }
}

/// Represents the amount used of different conversions
pub type Conversions =
    BTreeMap<AssetType, (AllowedConversion, MerklePath<Node>, i128)>;

/// Represents the changes that were made to a list of transparent accounts
pub type TransferDelta = HashMap<Address, MaspChange>;

/// Represents the changes that were made to a list of shielded accounts
pub type TransactionDelta = HashMap<ViewingKey, MaspAmount>;

/// Represents the current state of the shielded pool from the perspective of
/// the chosen viewing keys.
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct ShieldedContext<U: ShieldedUtils> {
    /// Location where this shielded context is saved
    #[borsh(skip)]
    pub utils: U,
    /// The last indexed transaction to be processed in this context
    pub last_indexed: Option<IndexedTx>,
    /// The commitment tree produced by scanning all transactions up to tx_pos
    pub tree: CommitmentTree<Node>,
    /// Maps viewing keys to applicable note positions
    pub pos_map: HashMap<ViewingKey, BTreeSet<usize>>,
    /// Maps a nullifier to the note position to which it applies
    pub nf_map: HashMap<Nullifier, usize>,
    /// Maps note positions to their corresponding notes
    pub note_map: HashMap<usize, Note>,
    /// Maps note positions to their corresponding memos
    pub memo_map: HashMap<usize, MemoBytes>,
    /// Maps note positions to the diversifier of their payment address
    pub div_map: HashMap<usize, Diversifier>,
    /// Maps note positions to their witness (used to make merkle paths)
    pub witness_map: HashMap<usize, IncrementalWitness<Node>>,
    /// Tracks what each transaction does to various account balances
    pub delta_map:
        BTreeMap<IndexedTx, (Epoch, TransferDelta, TransactionDelta)>,
    /// The set of note positions that have been spent
    pub spents: HashSet<usize>,
    /// Maps asset types to their decodings
    pub asset_types: HashMap<AssetType, (Address, MaspDenom, Epoch)>,
    /// Maps note positions to their corresponding viewing keys
    pub vk_map: HashMap<usize, ViewingKey>,
}

/// Default implementation to ease construction of TxContexts. Derive cannot be
/// used here due to CommitmentTree not implementing Default.
impl<U: ShieldedUtils + Default> Default for ShieldedContext<U> {
    fn default() -> ShieldedContext<U> {
        ShieldedContext::<U> {
            utils: U::default(),
            last_indexed: None,
            tree: CommitmentTree::empty(),
            pos_map: HashMap::default(),
            nf_map: HashMap::default(),
            note_map: HashMap::default(),
            memo_map: HashMap::default(),
            div_map: HashMap::default(),
            witness_map: HashMap::default(),
            spents: HashSet::default(),
            delta_map: BTreeMap::default(),
            asset_types: HashMap::default(),
            vk_map: HashMap::default(),
        }
    }
}

impl<U: ShieldedUtils + MaybeSend + MaybeSync> ShieldedContext<U> {
    /// Try to load the last saved shielded context from the given context
    /// directory. If this fails, then leave the current context unchanged.
    pub async fn load(&mut self) -> std::io::Result<()> {
        self.utils.clone().load(self).await
    }

    /// Save this shielded context into its associated context directory
    pub async fn save(&self) -> std::io::Result<()> {
        self.utils.save(self).await
    }

    /// Merge data from the given shielded context into the current shielded
    /// context. It must be the case that the two shielded contexts share the
    /// same last transaction ID and share identical commitment trees.
    pub fn merge(&mut self, new_ctx: ShieldedContext<U>) {
        debug_assert_eq!(self.last_indexed, new_ctx.last_indexed);
        // Merge by simply extending maps. Identical keys should contain
        // identical values, so overwriting should not be problematic.
        self.pos_map.extend(new_ctx.pos_map);
        self.nf_map.extend(new_ctx.nf_map);
        self.note_map.extend(new_ctx.note_map);
        self.memo_map.extend(new_ctx.memo_map);
        self.div_map.extend(new_ctx.div_map);
        self.witness_map.extend(new_ctx.witness_map);
        self.spents.extend(new_ctx.spents);
        self.asset_types.extend(new_ctx.asset_types);
        self.vk_map.extend(new_ctx.vk_map);
        // The deltas are the exception because different keys can reveal
        // different parts of the same transaction. Hence each delta needs to be
        // merged separately.
        for (height, (ep, ntfer_delta, ntx_delta)) in new_ctx.delta_map {
            let (_ep, tfer_delta, tx_delta) = self
                .delta_map
                .entry(height)
                .or_insert((ep, TransferDelta::new(), TransactionDelta::new()));
            tfer_delta.extend(ntfer_delta);
            tx_delta.extend(ntx_delta);
        }
    }

    /// Fetch the current state of the multi-asset shielded pool into a
    /// ShieldedContext
    pub async fn fetch<C: Client + Sync>(
        &mut self,
        client: &C,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) -> Result<(), Error> {
        // First determine which of the keys requested to be fetched are new.
        // Necessary because old transactions will need to be scanned for new
        // keys.
        let mut unknown_keys = Vec::new();
        for esk in sks {
            let vk = to_viewing_key(esk).vk;
            if !self.pos_map.contains_key(&vk) {
                unknown_keys.push(vk);
            }
        }
        for vk in fvks {
            if !self.pos_map.contains_key(vk) {
                unknown_keys.push(*vk);
            }
        }

        // If unknown keys are being used, we need to scan older transactions
        // for any unspent notes
        let (txs, mut tx_iter);
        if !unknown_keys.is_empty() {
            // Load all transactions accepted until this point
            txs = Self::fetch_shielded_transfers(client, None).await?;
            tx_iter = txs.iter();
            // Do this by constructing a shielding context only for unknown keys
            let mut tx_ctx = Self {
                utils: self.utils.clone(),
                ..Default::default()
            };
            for vk in unknown_keys {
                tx_ctx.pos_map.entry(vk).or_insert_with(BTreeSet::new);
            }
            // Update this unknown shielded context until it is level with self
            while tx_ctx.last_indexed != self.last_indexed {
                if let Some((indexed_tx, (epoch, tx, stx))) = tx_iter.next() {
                    tx_ctx
                        .scan_tx(client, *indexed_tx, *epoch, tx, stx)
                        .await?;
                } else {
                    break;
                }
            }
            // Merge the context data originating from the unknown keys into the
            // current context
            self.merge(tx_ctx);
        } else {
            // Load only transactions accepted from last_txid until this point
            txs = Self::fetch_shielded_transfers(client, self.last_indexed)
                .await?;
            tx_iter = txs.iter();
        }
        // Now that we possess the unspent notes corresponding to both old and
        // new keys up until tx_pos, proceed to scan the new transactions.
        for (indexed_tx, (epoch, tx, stx)) in &mut tx_iter {
            self.scan_tx(client, *indexed_tx, *epoch, tx, stx).await?;
        }
        Ok(())
    }

    /// Obtain a chronologically-ordered list of all accepted shielded
    /// transactions from a node.
    pub async fn fetch_shielded_transfers<C: Client + Sync>(
        client: &C,
        last_indexed_tx: Option<IndexedTx>,
    ) -> Result<BTreeMap<IndexedTx, (Epoch, Transfer, Transaction)>, Error>
    {
        // Query for the last produced block height
        let last_block_height = query_block(client)
            .await?
            .map_or_else(BlockHeight::first, |block| block.height);

        let mut shielded_txs = BTreeMap::new();
        // Fetch all the transactions we do not have yet
        let first_height_to_query =
            last_indexed_tx.map_or_else(|| 1, |last| last.height.0);
        let first_idx_to_query =
            last_indexed_tx.map_or_else(|| 0, |last| last.index.0 + 1);
        for height in first_height_to_query..=last_block_height.0 {
            // Get the valid masp transactions at the specified height
            let epoch = query_epoch_at_height(client, height.into())
                .await?
                .ok_or_else(|| {
                    Error::from(QueryError::General(
                        "Queried height is greater than the last committed \
                         block height"
                            .to_string(),
                    ))
                })?;

            let first_index_to_query = if height == first_height_to_query {
                Some(TxIndex(first_idx_to_query))
            } else {
                None
            };

            let txs_results = match get_indexed_masp_events_at_height(
                client,
                height.into(),
                first_index_to_query,
            )
            .await?
            {
                Some(events) => events,
                None => continue,
            };

            // Query the actual block to get the txs bytes. If we only need one
            // tx it might be slightly better to query the /tx endpoint to
            // reduce the amount of data sent over the network, but this is a
            // minimal improvement and it's even hard to tell how many times
            // we'd need a single masp tx to make this worth it
            let block = client
                .block(height as u32)
                .await
                .map_err(|e| Error::from(QueryError::General(e.to_string())))?
                .block
                .data;

            for (idx, tx_event) in txs_results {
                let tx = Tx::try_from(block[idx.0 as usize].as_ref())
                    .map_err(|e| Error::Other(e.to_string()))?;
                let (transfer, masp_transaction) = Self::extract_masp_tx(
                    &tx,
                    ExtractShieldedActionArg::Event::<C>(tx_event),
                    true,
                )
                .await?;

                // Collect the current transaction
                shielded_txs.insert(
                    IndexedTx {
                        height: height.into(),
                        index: idx,
                    },
                    (epoch, transfer, masp_transaction),
                );
            }
        }

        Ok(shielded_txs)
    }

    /// Extract the relevant shield portions of a [`Tx`], if any.
    async fn extract_masp_tx<'args, C: Client + Sync>(
        tx: &Tx,
        action_arg: ExtractShieldedActionArg<'args, C>,
        check_header: bool,
    ) -> Result<(Transfer, Transaction), Error> {
        let maybe_transaction = if check_header {
            let tx_header = tx.header();
            // NOTE: simply looking for masp sections attached to the tx
            // is not safe. We don't validate the sections attached to a
            // transaction se we could end up with transactions carrying
            // an unnecessary masp section. We must instead look for the
            // required masp sections in the signed commitments (hashes)
            // of the transactions' headers/data sections
            if let Some(wrapper_header) = tx_header.wrapper() {
                let hash =
                    wrapper_header.unshield_section_hash.ok_or_else(|| {
                        Error::Other(
                            "Missing expected fee unshielding section hash"
                                .to_string(),
                        )
                    })?;

                let masp_transaction = tx
                    .get_section(&hash)
                    .ok_or_else(|| {
                        Error::Other(
                            "Missing expected masp section".to_string(),
                        )
                    })?
                    .masp_tx()
                    .ok_or_else(|| {
                        Error::Other("Missing masp transaction".to_string())
                    })?;

                // Transfer objects for fee unshielding are absent from
                // the tx because they are completely constructed in
                // protocol, need to recreate it here
                let transfer = Transfer {
                    source: MASP,
                    target: wrapper_header.fee_payer(),
                    token: wrapper_header.fee.token.clone(),
                    amount: wrapper_header
                        .get_tx_fee()
                        .map_err(|e| Error::Other(e.to_string()))?,
                    key: None,
                    shielded: Some(hash),
                };
                Some((transfer, masp_transaction))
            } else {
                None
            }
        } else {
            None
        };

        let tx = if let Some(tx) = maybe_transaction {
            tx
        } else {
            // Expect decrypted transaction
            let tx_data = tx.data().ok_or_else(|| {
                Error::Other("Missing data section".to_string())
            })?;
            match Transfer::try_from_slice(&tx_data) {
                Ok(transfer) => {
                    let masp_transaction = tx
                        .get_section(&transfer.shielded.ok_or_else(|| {
                            Error::Other(
                                "Missing masp section hash".to_string(),
                            )
                        })?)
                        .ok_or_else(|| {
                            Error::Other(
                                "Missing masp section in transaction"
                                    .to_string(),
                            )
                        })?
                        .masp_tx()
                        .ok_or_else(|| {
                            Error::Other("Missing masp transaction".to_string())
                        })?;

                    (transfer, masp_transaction)
                }
                Err(_) => {
                    // This should be a MASP over IBC transaction, it
                    // could be a ShieldedTransfer or an Envelop
                    // message, need to try both
                    let shielded_transfer =
                        extract_payload_from_shielded_action::<C>(
                            &tx_data, action_arg,
                        )
                        .await?;
                    (shielded_transfer.transfer, shielded_transfer.masp_tx)
                }
            }
        };
        Ok(tx)
    }

    /// Applies the given transaction to the supplied context. More precisely,
    /// the shielded transaction's outputs are added to the commitment tree.
    /// Newly discovered notes are associated to the supplied viewing keys. Note
    /// nullifiers are mapped to their originating notes. Note positions are
    /// associated to notes, memos, and diversifiers. And the set of notes that
    /// we have spent are updated. The witness map is maintained to make it
    /// easier to construct note merkle paths in other code. See
    /// <https://zips.z.cash/protocol/protocol.pdf#scan>
    pub async fn scan_tx<C: Client + Sync>(
        &mut self,
        client: &C,
        indexed_tx: IndexedTx,
        epoch: Epoch,
        tx: &Transfer,
        shielded: &Transaction,
    ) -> Result<(), Error> {
        // For tracking the account changes caused by this Transaction
        let mut transaction_delta = TransactionDelta::new();
        // Listen for notes sent to our viewing keys
        for so in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_outputs)
        {
            // Create merkle tree leaf node from note commitment
            let node = Node::new(so.cmu.to_repr());
            // Update each merkle tree in the witness map with the latest
            // addition
            for (_, witness) in self.witness_map.iter_mut() {
                witness.append(node).map_err(|()| {
                    Error::Other("note commitment tree is full".to_string())
                })?;
            }
            let note_pos = self.tree.size();
            self.tree.append(node).map_err(|()| {
                Error::Other("note commitment tree is full".to_string())
            })?;
            // Finally, make it easier to construct merkle paths to this new
            // note
            let witness = IncrementalWitness::<Node>::from_tree(&self.tree);
            self.witness_map.insert(note_pos, witness);
            // Let's try to see if any of our viewing keys can decrypt latest
            // note
            let mut pos_map = HashMap::new();
            std::mem::swap(&mut pos_map, &mut self.pos_map);
            for (vk, notes) in pos_map.iter_mut() {
                let decres = try_sapling_note_decryption::<_, OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>>(
                    &NETWORK,
                    1.into(),
                    &PreparedIncomingViewingKey::new(&vk.ivk()),
                    so,
                );
                // So this current viewing key does decrypt this current note...
                if let Some((note, pa, memo)) = decres {
                    // Add this note to list of notes decrypted by this viewing
                    // key
                    notes.insert(note_pos);
                    // Compute the nullifier now to quickly recognize when spent
                    let nf = note.nf(
                        &vk.nk,
                        note_pos.try_into().map_err(|_| {
                            Error::Other("Can not get nullifier".to_string())
                        })?,
                    );
                    self.note_map.insert(note_pos, note);
                    self.memo_map.insert(note_pos, memo);
                    // The payment address' diversifier is required to spend
                    // note
                    self.div_map.insert(note_pos, *pa.diversifier());
                    self.nf_map.insert(nf, note_pos);
                    // Note the account changes
                    let balance = transaction_delta
                        .entry(*vk)
                        .or_insert_with(MaspAmount::default);
                    *balance += self
                        .decode_all_amounts(
                            client,
                            I128Sum::from_nonnegative(
                                note.asset_type,
                                note.value as i128,
                            )
                            .map_err(|()| {
                                Error::Other(
                                    "found note with invalid value or asset \
                                     type"
                                        .to_string(),
                                )
                            })?,
                        )
                        .await;

                    self.vk_map.insert(note_pos, *vk);
                    break;
                }
            }
            std::mem::swap(&mut pos_map, &mut self.pos_map);
        }
        // Cancel out those of our notes that have been spent
        for ss in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_spends)
        {
            // If the shielded spend's nullifier is in our map, then target note
            // is rendered unusable
            if let Some(note_pos) = self.nf_map.get(&ss.nullifier) {
                self.spents.insert(*note_pos);
                // Note the account changes
                let balance = transaction_delta
                    .entry(self.vk_map[note_pos])
                    .or_insert_with(MaspAmount::default);
                let note = self.note_map[note_pos];
                *balance -= self
                    .decode_all_amounts(
                        client,
                        I128Sum::from_nonnegative(
                            note.asset_type,
                            note.value as i128,
                        )
                        .map_err(|()| {
                            Error::Other(
                                "found note with invalid value or asset type"
                                    .to_string(),
                            )
                        })?,
                    )
                    .await;
            }
        }
        // Record the changes to the transparent accounts
        let mut transfer_delta = TransferDelta::new();
        let token_addr = tx.token.clone();
        transfer_delta.insert(
            tx.source.clone(),
            MaspChange {
                asset: token_addr,
                change: -tx.amount.amount().change(),
            },
        );
        self.last_indexed = Some(indexed_tx);

        self.delta_map
            .insert(indexed_tx, (epoch, transfer_delta, transaction_delta));
        Ok(())
    }

    /// Summarize the effects on shielded and transparent accounts of each
    /// Transfer in this context
    pub fn get_tx_deltas(
        &self,
    ) -> &BTreeMap<IndexedTx, (Epoch, TransferDelta, TransactionDelta)> {
        &self.delta_map
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    pub async fn compute_shielded_balance<C: Client + Sync>(
        &mut self,
        client: &C,
        vk: &ViewingKey,
    ) -> Result<Option<MaspAmount>, Error> {
        // Cannot query the balance of a key that's not in the map
        if !self.pos_map.contains_key(vk) {
            return Ok(None);
        }
        let mut val_acc = I128Sum::zero();
        // Retrieve the notes that can be spent by this key
        if let Some(avail_notes) = self.pos_map.get(vk) {
            for note_idx in avail_notes {
                // Spent notes cannot contribute a new transaction's pool
                if self.spents.contains(note_idx) {
                    continue;
                }
                // Get note associated with this ID
                let note = self.note_map.get(note_idx).ok_or_else(|| {
                    Error::Other(format!("Unable to get note {note_idx}"))
                })?;
                // Finally add value to multi-asset accumulator
                val_acc += I128Sum::from_nonnegative(
                    note.asset_type,
                    note.value as i128,
                )
                .map_err(|()| {
                    Error::Other(
                        "found note with invalid value or asset type"
                            .to_string(),
                    )
                })?
            }
        }
        Ok(Some(self.decode_all_amounts(client, val_acc).await))
    }

    /// Query the ledger for the decoding of the given asset type and cache it
    /// if it is found.
    pub async fn decode_asset_type<C: Client + Sync>(
        &mut self,
        client: &C,
        asset_type: AssetType,
    ) -> Option<(Address, MaspDenom, Epoch)> {
        // Try to find the decoding in the cache
        if let decoded @ Some(_) = self.asset_types.get(&asset_type) {
            return decoded.cloned();
        }
        // Query for the ID of the last accepted transaction
        let (addr, denom, ep, _conv, _path): (
            Address,
            MaspDenom,
            _,
            I128Sum,
            MerklePath<Node>,
        ) = rpc::query_conversion(client, asset_type).await?;
        self.asset_types
            .insert(asset_type, (addr.clone(), denom, ep));
        Some((addr, denom, ep))
    }

    /// Query the ledger for the conversion that is allowed for the given asset
    /// type and cache it.
    async fn query_allowed_conversion<'a, C: Client + Sync>(
        &'a mut self,
        client: &C,
        asset_type: AssetType,
        conversions: &'a mut Conversions,
    ) {
        if let btree_map::Entry::Vacant(conv_entry) =
            conversions.entry(asset_type)
        {
            // Query for the ID of the last accepted transaction
            if let Some((addr, denom, ep, conv, path)) =
                query_conversion(client, asset_type).await
            {
                self.asset_types.insert(asset_type, (addr, denom, ep));
                // If the conversion is 0, then we just have a pure decoding
                if !conv.is_zero() {
                    conv_entry.insert((conv.into(), path, 0));
                }
            }
        }
    }

    /// Compute the total unspent notes associated with the viewing key in the
    /// context and express that value in terms of the currently timestamped
    /// asset types. If the key is not in the context, then we do not know the
    /// balance and hence we return None.
    pub async fn compute_exchanged_balance(
        &mut self,
        client: &(impl Client + Sync),
        io: &impl Io,
        vk: &ViewingKey,
        target_epoch: Epoch,
    ) -> Result<Option<MaspAmount>, Error> {
        // First get the unexchanged balance
        if let Some(balance) = self.compute_shielded_balance(client, vk).await?
        {
            let exchanged_amount = self
                .compute_exchanged_amount(
                    client,
                    io,
                    balance,
                    target_epoch,
                    BTreeMap::new(),
                )
                .await?
                .0;
            // And then exchange balance into current asset types
            Ok(Some(
                self.decode_all_amounts(client, exchanged_amount).await,
            ))
        } else {
            Ok(None)
        }
    }

    /// Try to convert as much of the given asset type-value pair using the
    /// given allowed conversion. usage is incremented by the amount of the
    /// conversion used, the conversions are applied to the given input, and
    /// the trace amount that could not be converted is moved from input to
    /// output.
    #[allow(clippy::too_many_arguments)]
    async fn apply_conversion(
        &mut self,
        client: &(impl Client + Sync),
        io: &impl Io,
        conv: AllowedConversion,
        asset_type: (Epoch, Address, MaspDenom),
        value: i128,
        usage: &mut i128,
        input: &mut MaspAmount,
        output: &mut MaspAmount,
    ) -> Result<(), Error> {
        // we do not need to convert negative values
        if value <= 0 {
            return Ok(());
        }
        // If conversion if possible, accumulate the exchanged amount
        let conv: I128Sum = I128Sum::from_sum(conv.into());
        // The amount required of current asset to qualify for conversion
        let masp_asset =
            make_asset_type(Some(asset_type.0), &asset_type.1, asset_type.2)?;
        let threshold = -conv[&masp_asset];
        if threshold == 0 {
            edisplay_line!(
                io,
                "Asset threshold of selected conversion for asset type {} is \
                 0, this is a bug, please report it.",
                masp_asset
            );
        }
        // We should use an amount of the AllowedConversion that almost
        // cancels the original amount
        let required = value / threshold;
        // Forget about the trace amount left over because we cannot
        // realize its value
        let trace = MaspAmount(HashMap::from([(
            (asset_type.0, asset_type.1),
            Change::from(value % threshold),
        )]));
        // Record how much more of the given conversion has been used
        *usage += required;
        // Apply the conversions to input and move the trace amount to output
        *input += self
            .decode_all_amounts(client, conv.clone() * required)
            .await
            - trace.clone();
        *output += trace;
        Ok(())
    }

    /// Convert the given amount into the latest asset types whilst making a
    /// note of the conversions that were used. Note that this function does
    /// not assume that allowed conversions from the ledger are expressed in
    /// terms of the latest asset types.
    pub async fn compute_exchanged_amount(
        &mut self,
        client: &(impl Client + Sync),
        io: &impl Io,
        mut input: MaspAmount,
        target_epoch: Epoch,
        mut conversions: Conversions,
    ) -> Result<(I128Sum, Conversions), Error> {
        // Where we will store our exchanged value
        let mut output = MaspAmount::default();
        // Repeatedly exchange assets until it is no longer possible
        while let Some(((asset_epoch, token_addr), value)) = input.iter().next()
        {
            let value = *value;
            let asset_epoch = *asset_epoch;
            let token_addr = token_addr.clone();
            for denom in MaspDenom::iter() {
                let target_asset_type =
                    make_asset_type(Some(target_epoch), &token_addr, denom)?;
                let asset_type =
                    make_asset_type(Some(asset_epoch), &token_addr, denom)?;
                let at_target_asset_type = target_epoch == asset_epoch;

                let denom_value = denom.denominate_i128(&value);
                self.query_allowed_conversion(
                    client,
                    target_asset_type,
                    &mut conversions,
                )
                .await;
                self.query_allowed_conversion(
                    client,
                    asset_type,
                    &mut conversions,
                )
                .await;
                if let (Some((conv, _wit, usage)), false) =
                    (conversions.get_mut(&asset_type), at_target_asset_type)
                {
                    display_line!(
                        io,
                        "converting current asset type to latest asset type..."
                    );
                    // Not at the target asset type, not at the latest asset
                    // type. Apply conversion to get from
                    // current asset type to the latest
                    // asset type.
                    self.apply_conversion(
                        client,
                        io,
                        conv.clone(),
                        (asset_epoch, token_addr.clone(), denom),
                        denom_value,
                        usage,
                        &mut input,
                        &mut output,
                    )
                    .await?;
                } else if let (Some((conv, _wit, usage)), false) = (
                    conversions.get_mut(&target_asset_type),
                    at_target_asset_type,
                ) {
                    display_line!(
                        io,
                        "converting latest asset type to target asset type..."
                    );
                    // Not at the target asset type, yet at the latest asset
                    // type. Apply inverse conversion to get
                    // from latest asset type to the target
                    // asset type.
                    self.apply_conversion(
                        client,
                        io,
                        conv.clone(),
                        (asset_epoch, token_addr.clone(), denom),
                        denom_value,
                        usage,
                        &mut input,
                        &mut output,
                    )
                    .await?;
                } else {
                    // At the target asset type. Then move component over to
                    // output.
                    let mut comp = MaspAmount::default();
                    comp.insert(
                        (asset_epoch, token_addr.clone()),
                        denom_value.into(),
                    );
                    for ((e, token), val) in input.iter() {
                        if *token == token_addr && *e == asset_epoch {
                            comp.insert((*e, token.clone()), *val);
                        }
                    }
                    output += comp.clone();
                    input -= comp;
                }
            }
        }
        Ok((output.into(), conversions))
    }

    /// Collect enough unspent notes in this context to exceed the given amount
    /// of the specified asset type. Return the total value accumulated plus
    /// notes and the corresponding diversifiers/merkle paths that were used to
    /// achieve the total value.
    pub async fn collect_unspent_notes(
        &mut self,
        context: &impl Namada,
        vk: &ViewingKey,
        target: I128Sum,
        target_epoch: Epoch,
    ) -> Result<
        (
            I128Sum,
            Vec<(Diversifier, Note, MerklePath<Node>)>,
            Conversions,
        ),
        Error,
    > {
        // Establish connection with which to do exchange rate queries
        let mut conversions = BTreeMap::new();
        let mut val_acc = I128Sum::zero();
        let mut notes = Vec::new();
        // Retrieve the notes that can be spent by this key
        if let Some(avail_notes) = self.pos_map.get(vk).cloned() {
            for note_idx in &avail_notes {
                // No more transaction inputs are required once we have met
                // the target amount
                if val_acc >= target {
                    break;
                }
                // Spent notes cannot contribute a new transaction's pool
                if self.spents.contains(note_idx) {
                    continue;
                }
                // Get note, merkle path, diversifier associated with this ID
                let note = *self.note_map.get(note_idx).ok_or_else(|| {
                    Error::Other(format!("Unable to get note {note_idx}"))
                })?;

                // The amount contributed by this note before conversion
                let pre_contr =
                    I128Sum::from_pair(note.asset_type, note.value as i128)
                        .map_err(|()| {
                            Error::Other(
                                "received note has invalid value or asset type"
                                    .to_string(),
                            )
                        })?;
                let input =
                    self.decode_all_amounts(context.client(), pre_contr).await;
                let (contr, proposed_convs) = self
                    .compute_exchanged_amount(
                        context.client(),
                        context.io(),
                        input,
                        target_epoch,
                        conversions.clone(),
                    )
                    .await?;

                // Use this note only if it brings us closer to our target
                if is_amount_required(
                    val_acc.clone(),
                    target.clone(),
                    contr.clone(),
                ) {
                    // Be sure to record the conversions used in computing
                    // accumulated value
                    val_acc += contr;
                    // Commit the conversions that were used to exchange
                    conversions = proposed_convs;
                    let merkle_path = self
                        .witness_map
                        .get(note_idx)
                        .ok_or_else(|| {
                            Error::Other(format!(
                                "Unable to get note {note_idx}"
                            ))
                        })?
                        .path()
                        .ok_or_else(|| {
                            Error::Other(format!(
                                "Unable to get path: {}",
                                line!()
                            ))
                        })?;
                    let diversifier =
                        self.div_map.get(note_idx).ok_or_else(|| {
                            Error::Other(format!(
                                "Unable to get note {note_idx}"
                            ))
                        })?;
                    // Commit this note to our transaction
                    notes.push((*diversifier, note, merkle_path));
                }
            }
        }
        Ok((val_acc, notes, conversions))
    }

    /// Compute the combined value of the output notes of the transaction pinned
    /// at the given payment address. This computation uses the supplied viewing
    /// keys to try to decrypt the output notes. If no transaction is pinned at
    /// the given payment address fails with
    /// `PinnedBalanceError::NoTransactionPinned`.
    pub async fn compute_pinned_balance<C: Client + Sync>(
        client: &C,
        owner: PaymentAddress,
        viewing_key: &ViewingKey,
    ) -> Result<(I128Sum, Epoch), Error> {
        // Check that the supplied viewing key corresponds to given payment
        // address
        let counter_owner = viewing_key.to_payment_address(
            *masp_primitives::sapling::PaymentAddress::diversifier(
                &owner.into(),
            ),
        );
        match counter_owner {
            Some(counter_owner) if counter_owner == owner.into() => {}
            _ => {
                return Err(Error::from(PinnedBalanceError::InvalidViewingKey));
            }
        }
        // Construct the key for where the transaction ID would be stored
        let pin_key = namada_core::types::token::masp_pin_tx_key(&owner.hash());
        // Obtain the transaction pointer at the key
        // If we don't discard the error message then a test fails,
        // however the error underlying this will go undetected
        let indexed_tx =
            rpc::query_storage_value::<C, IndexedTx>(client, &pin_key)
                .await
                .map_err(|_| PinnedBalanceError::NoTransactionPinned)?;
        let tx_epoch = query_epoch_at_height(client, indexed_tx.height)
            .await?
            .ok_or_else(|| {
                Error::from(QueryError::General(
                    "Queried height is greater than the last committed block \
                     height"
                        .to_string(),
                ))
            })?;

        let block = client
            .block(indexed_tx.height.0 as u32)
            .await
            .map_err(|e| Error::from(QueryError::General(e.to_string())))?
            .block
            .data;

        let tx = Tx::try_from(block[indexed_tx.index.0 as usize].as_ref())
            .map_err(|e| Error::Other(e.to_string()))?;
        let (_, shielded) = Self::extract_masp_tx(
            &tx,
            ExtractShieldedActionArg::Request((
                client,
                indexed_tx.height,
                Some(indexed_tx.index),
            )),
            false,
        )
        .await?;

        // Accumulate the combined output note value into this Amount
        let mut val_acc = I128Sum::zero();
        for so in shielded
            .sapling_bundle()
            .map_or(&vec![], |x| &x.shielded_outputs)
        {
            // Let's try to see if our viewing key can decrypt current note
            let decres = try_sapling_note_decryption::<_, OutputDescription<<<Authorized as Authorization>::SaplingAuth as masp_primitives::transaction::components::sapling::Authorization>::Proof>>(
                &NETWORK,
                1.into(),
                &PreparedIncomingViewingKey::new(&viewing_key.ivk()),
                so,
            );
            match decres {
                // So the given viewing key does decrypt this current note...
                Some((note, pa, _memo)) if pa == owner.into() => {
                    val_acc += I128Sum::from_nonnegative(
                        note.asset_type,
                        note.value as i128,
                    )
                    .map_err(|()| {
                        Error::Other(
                            "found note with invalid value or asset type"
                                .to_string(),
                        )
                    })?;
                }
                _ => {}
            }
        }
        Ok((val_acc, tx_epoch))
    }

    /// Compute the combined value of the output notes of the pinned transaction
    /// at the given payment address if there's any. The asset types may be from
    /// the epoch of the transaction or even before, so exchange all these
    /// amounts to the epoch of the transaction in order to get the value that
    /// would have been displayed in the epoch of the transaction.
    pub async fn compute_exchanged_pinned_balance(
        &mut self,
        context: &impl Namada,
        owner: PaymentAddress,
        viewing_key: &ViewingKey,
    ) -> Result<(MaspAmount, Epoch), Error> {
        // Obtain the balance that will be exchanged
        let (amt, ep) =
            Self::compute_pinned_balance(context.client(), owner, viewing_key)
                .await?;
        display_line!(context.io(), "Pinned balance: {:?}", amt);
        // Establish connection with which to do exchange rate queries
        let amount = self.decode_all_amounts(context.client(), amt).await;
        display_line!(context.io(), "Decoded pinned balance: {:?}", amount);
        // Finally, exchange the balance to the transaction's epoch
        let computed_amount = self
            .compute_exchanged_amount(
                context.client(),
                context.io(),
                amount,
                ep,
                BTreeMap::new(),
            )
            .await?
            .0;
        display_line!(context.io(), "Exchanged amount: {:?}", computed_amount);
        Ok((
            self.decode_all_amounts(context.client(), computed_amount)
                .await,
            ep,
        ))
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to. All asset types not corresponding to
    /// the given epoch are ignored.
    pub async fn decode_amount<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: I128Sum,
        target_epoch: Epoch,
    ) -> HashMap<Address, token::Change> {
        let mut res = HashMap::new();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            let decoded = self.decode_asset_type(client, *asset_type).await;
            // Only assets with the target timestamp count
            match decoded {
                Some(asset_type @ (_, _, epoch)) if epoch == target_epoch => {
                    decode_component(
                        asset_type,
                        *val,
                        &mut res,
                        |address, _| address,
                    );
                }
                _ => {}
            }
        }
        res
    }

    /// Convert an amount whose units are AssetTypes to one whose units are
    /// Addresses that they decode to.
    pub async fn decode_all_amounts<C: Client + Sync>(
        &mut self,
        client: &C,
        amt: I128Sum,
    ) -> MaspAmount {
        let mut res: HashMap<(Epoch, Address), Change> = HashMap::default();
        for (asset_type, val) in amt.components() {
            // Decode the asset type
            if let Some(decoded) =
                self.decode_asset_type(client, *asset_type).await
            {
                decode_component(decoded, *val, &mut res, |address, epoch| {
                    (epoch, address)
                })
            }
        }
        MaspAmount(res)
    }

    /// Make shielded components to embed within a Transfer object. If no
    /// shielded payment address nor spending key is specified, then no
    /// shielded components are produced. Otherwise a transaction containing
    /// nullifiers and/or note commitments are produced. Dummy transparent
    /// UTXOs are sometimes used to make transactions balanced, but it is
    /// understood that transparent account changes are effected only by the
    /// amounts and signatures specified by the containing Transfer object.
    pub async fn gen_shielded_transfer(
        context: &impl Namada,
        source: &TransferSource,
        target: &TransferTarget,
        token: &Address,
        amount: token::DenominatedAmount,
    ) -> Result<Option<ShieldedTransfer>, TransferErr> {
        // No shielded components are needed when neither source nor destination
        // are shielded

        use rand::rngs::StdRng;
        use rand_core::SeedableRng;

        let spending_key = source.spending_key();
        let payment_address = target.payment_address();
        // No shielded components are needed when neither source nor
        // destination are shielded
        if spending_key.is_none() && payment_address.is_none() {
            return Ok(None);
        }
        // We want to fund our transaction solely from supplied spending key
        let spending_key = spending_key.map(|x| x.into());
        let spending_keys: Vec<_> = spending_key.into_iter().collect();
        {
            // Load the current shielded context given the spending key we
            // possess
            let mut shielded = context.shielded_mut().await;
            let _ = shielded.load().await;
            shielded
                .fetch(context.client(), &spending_keys, &[])
                .await?;
            // Save the update state so that future fetches can be
            // short-circuited
            let _ = shielded.save().await;
        }
        // Determine epoch in which to submit potential shielded transaction
        let epoch = rpc::query_epoch(context.client()).await?;
        // Context required for storing which notes are in the source's
        // possession
        let memo = MemoBytes::empty();

        // Try to get a seed from env var, if any.
        let rng = if let Ok(seed) = env::var(ENV_VAR_MASP_TEST_SEED)
            .map_err(|e| Error::Other(e.to_string()))
            .and_then(|seed| {
                let exp_str =
                    format!("Env var {ENV_VAR_MASP_TEST_SEED} must be a u64.");
                let parsed_seed: u64 = FromStr::from_str(&seed)
                    .map_err(|_| Error::Other(exp_str))?;
                Ok(parsed_seed)
            }) {
            tracing::warn!(
                "UNSAFE: Using a seed from {ENV_VAR_MASP_TEST_SEED} env var \
                 to build proofs."
            );
            StdRng::seed_from_u64(seed)
        } else {
            StdRng::from_rng(OsRng).unwrap()
        };

        // Now we build up the transaction within this object
        let expiration_height: u32 = match context.tx_builder().expiration {
            Some(expiration) => {
                // Try to match a DateTime expiration with a plausible
                // corresponding block height
                let last_block_height: u64 =
                    crate::rpc::query_block(context.client())
                        .await?
                        .map_or_else(|| 1, |block| u64::from(block.height));
                let current_time = DateTimeUtc::now();
                let delta_time =
                    expiration.0.signed_duration_since(current_time.0);

                let max_expected_time_per_block_key =
                    namada_core::ledger::parameters::storage::get_max_expected_time_per_block_key();
                let max_block_time =
                    crate::rpc::query_storage_value::<_, DurationSecs>(
                        context.client(),
                        &max_expected_time_per_block_key,
                    )
                    .await?;

                let delta_blocks = u32::try_from(
                    delta_time.num_seconds() / max_block_time.0 as i64,
                )
                .map_err(|e| Error::Other(e.to_string()))?;
                u32::try_from(last_block_height)
                    .map_err(|e| Error::Other(e.to_string()))?
                    + delta_blocks
            }
            None => {
                // NOTE: The masp library doesn't support optional expiration so
                // we set the max to mimic a never-expiring tx. We also need to
                // remove 20 which is going to be added back by the builder
                u32::MAX - 20
            }
        };
        let mut builder = Builder::<TestNetwork, _>::new_with_rng(
            NETWORK,
            // NOTE: this is going to add 20 more blocks to the actual
            // expiration but there's no other exposed function that we could
            // use from the masp crate to specify the expiration better
            expiration_height.into(),
            rng,
        );

        // Convert transaction amount into MASP types
        let (asset_types, masp_amount) =
            convert_amount(epoch, token, amount.amount())?;

        // If there are shielded inputs
        if let Some(sk) = spending_key {
            // Locate unspent notes that can help us meet the transaction amount
            let (_, unspent_notes, used_convs) = context
                .shielded_mut()
                .await
                .collect_unspent_notes(
                    context,
                    &to_viewing_key(&sk).vk,
                    I128Sum::from_sum(masp_amount),
                    epoch,
                )
                .await?;
            // Commit the notes found to our transaction
            for (diversifier, note, merkle_path) in unspent_notes {
                builder
                    .add_sapling_spend(sk, diversifier, note, merkle_path)
                    .map_err(builder::Error::SaplingBuild)?;
            }
            // Commit the conversion notes used during summation
            for (conv, wit, value) in used_convs.values() {
                if value.is_positive() {
                    builder
                        .add_sapling_convert(
                            conv.clone(),
                            *value as u64,
                            wit.clone(),
                        )
                        .map_err(builder::Error::SaplingBuild)?;
                }
            }
        } else {
            // We add a dummy UTXO to our transaction, but only the source of
            // the parent Transfer object is used to validate fund
            // availability
            let source_enc = source
                .address()
                .ok_or_else(|| {
                    Error::Other(
                        "source address should be transparent".to_string(),
                    )
                })?
                .serialize_to_vec();

            let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(
                source_enc.as_ref(),
            ));
            let script = TransparentAddress(hash.into());
            for (denom, asset_type) in MaspDenom::iter().zip(asset_types.iter())
            {
                builder
                    .add_transparent_input(TxOut {
                        asset_type: *asset_type,
                        value: denom.denominate(&amount.amount()),
                        address: script,
                    })
                    .map_err(builder::Error::TransparentBuild)?;
            }
        }

        // Now handle the outputs of this transaction
        // If there is a shielded output
        if let Some(pa) = payment_address {
            let ovk_opt = spending_key.map(|x| x.expsk.ovk);
            for (denom, asset_type) in MaspDenom::iter().zip(asset_types.iter())
            {
                builder
                    .add_sapling_output(
                        ovk_opt,
                        pa.into(),
                        *asset_type,
                        denom.denominate(&amount.amount()),
                        memo.clone(),
                    )
                    .map_err(builder::Error::SaplingBuild)?;
            }
        } else {
            // Embed the transparent target address into the shielded
            // transaction so that it can be signed
            let target_enc = target
                .address()
                .ok_or_else(|| {
                    Error::Other(
                        "source address should be transparent".to_string(),
                    )
                })?
                .serialize_to_vec();
            let hash = ripemd::Ripemd160::digest(sha2::Sha256::digest(
                target_enc.as_ref(),
            ));
            for (denom, asset_type) in MaspDenom::iter().zip(asset_types.iter())
            {
                let vout = denom.denominate(&amount.amount());
                if vout != 0 {
                    builder
                        .add_transparent_output(
                            &TransparentAddress(hash.into()),
                            *asset_type,
                            vout,
                        )
                        .map_err(builder::Error::TransparentBuild)?;
                }
            }
        }

        // Now add outputs representing the change from this payment
        if let Some(sk) = spending_key {
            // Represents the amount of inputs we are short by
            let mut additional = I128Sum::zero();
            for (asset_type, amt) in builder
                .value_balance()
                .map_err(|e| {
                    Error::Other(format!(
                        "unable to complete value balance: {}",
                        e
                    ))
                })?
                .components()
            {
                if *amt >= 0 {
                    // Send the change in this asset type back to the sender
                    builder
                        .add_sapling_output(
                            Some(sk.expsk.ovk),
                            sk.default_address().1,
                            *asset_type,
                            *amt as u64,
                            memo.clone(),
                        )
                        .map_err(builder::Error::SaplingBuild)?;
                } else {
                    // Record how much of the current asset type we are short by
                    additional += I128Sum::from_nonnegative(*asset_type, -*amt)
                        .map_err(|()| {
                            Error::Other(format!(
                                "from non negative conversion: {}",
                                line!()
                            ))
                        })?;
                }
            }
            // If we are short by a non-zero amount, then we have insufficient
            // funds
            if !additional.is_zero() {
                return Err(TransferErr::from(
                    builder::Error::InsufficientFunds(additional),
                ));
            }
        }

        // To speed up integration tests, we can save and load proofs
        #[cfg(feature = "testing")]
        let load_or_save = if let Ok(masp_proofs) =
            env::var(ENV_VAR_MASP_TEST_PROOFS)
        {
            let parsed = match masp_proofs.to_ascii_lowercase().as_str() {
                "load" => LoadOrSaveProofs::Load,
                "save" => LoadOrSaveProofs::Save,
                env_var => Err(Error::Other(format!(
                    "Unexpected value for {ENV_VAR_MASP_TEST_PROOFS} env var. \
                     Expecting \"save\" or \"load\", but got \"{env_var}\"."
                )))?,
            };
            if env::var(ENV_VAR_MASP_TEST_SEED).is_err() {
                Err(Error::Other(format!(
                    "Ensure to set a seed with {ENV_VAR_MASP_TEST_SEED} env \
                     var when using {ENV_VAR_MASP_TEST_PROOFS} for \
                     deterministic proofs."
                )))?;
            }
            parsed
        } else {
            LoadOrSaveProofs::Neither
        };

        let builder_clone = builder.clone().map_builder(WalletMap);
        #[cfg(feature = "testing")]
        let builder_bytes = borsh::to_vec(&builder_clone).map_err(|e| {
            Error::from(EncodingError::Conversion(e.to_string()))
        })?;

        let build_transfer = |prover: LocalTxProver| -> Result<
            ShieldedTransfer,
            builder::Error<std::convert::Infallible>,
        > {
            let (masp_tx, metadata) = builder
                .build(&prover, &FeeRule::non_standard(U64Sum::zero()))?;
            Ok(ShieldedTransfer {
                builder: builder_clone,
                masp_tx,
                metadata,
                epoch,
            })
        };

        #[cfg(feature = "testing")]
        {
            let builder_hash =
                namada_core::types::hash::Hash::sha256(&builder_bytes);

            let saved_filepath = env::current_dir()
                .map_err(|e| Error::Other(e.to_string()))?
                // One up from "tests" dir to the root dir
                .parent()
                .ok_or_else(|| {
                    Error::Other(
                        "Can not get parent directory of the current dir"
                            .to_string(),
                    )
                })?
                .join(MASP_TEST_PROOFS_DIR)
                .join(format!("{builder_hash}.bin"));

            if let LoadOrSaveProofs::Load = load_or_save {
                let recommendation = format!(
                    "Re-run the tests with {ENV_VAR_MASP_TEST_PROOFS}=save to \
                     re-generate proofs."
                );
                let exp_str = format!(
                    "Read saved MASP proofs from {}. {recommendation}",
                    saved_filepath.to_string_lossy()
                );
                let loaded_bytes = tokio::fs::read(&saved_filepath)
                    .await
                    .map_err(|_e| Error::Other(exp_str))?;

                let exp_str = format!(
                    "Valid `ShieldedTransfer` bytes in {}. {recommendation}",
                    saved_filepath.to_string_lossy()
                );
                let loaded: ShieldedTransfer =
                    BorshDeserialize::try_from_slice(&loaded_bytes)
                        .map_err(|_e| Error::Other(exp_str))?;

                Ok(Some(loaded))
            } else {
                // Build and return the constructed transaction
                let built = build_transfer(
                    context.shielded().await.utils.local_tx_prover(),
                )?;
                if let LoadOrSaveProofs::Save = load_or_save {
                    let built_bytes = borsh::to_vec(&built).map_err(|e| {
                        Error::from(EncodingError::Conversion(e.to_string()))
                    })?;
                    tokio::fs::write(&saved_filepath, built_bytes)
                        .await
                        .map_err(|e| Error::Other(e.to_string()))?;
                }
                Ok(Some(built))
            }
        }

        #[cfg(not(feature = "testing"))]
        {
            // Build and return the constructed transaction
            let built = build_transfer(
                context.shielded().await.utils.local_tx_prover(),
            )?;
            Ok(Some(built))
        }
    }

    /// Obtain the known effects of all accepted shielded and transparent
    /// transactions. If an owner is specified, then restrict the set to only
    /// transactions crediting/debiting the given owner. If token is specified,
    /// then restrict set to only transactions involving the given token.
    pub async fn query_tx_deltas<C: Client + Sync>(
        &mut self,
        client: &C,
        query_owner: &Either<BalanceOwner, Vec<Address>>,
        query_token: &Option<Address>,
        viewing_keys: &HashMap<String, ExtendedViewingKey>,
    ) -> Result<
        BTreeMap<IndexedTx, (Epoch, TransferDelta, TransactionDelta)>,
        Error,
    > {
        const TXS_PER_PAGE: u8 = 100;
        let _ = self.load().await;
        let vks = viewing_keys;
        let fvks: Vec<_> = vks
            .values()
            .map(|fvk| ExtendedFullViewingKey::from(*fvk).fvk.vk)
            .collect();
        self.fetch(client, &[], &fvks).await?;
        // Save the update state so that future fetches can be short-circuited
        let _ = self.save().await;
        // Required for filtering out rejected transactions from Tendermint
        // responses
        let block_results = rpc::query_results(client).await?;
        let mut transfers = self.get_tx_deltas().clone();
        // Construct the set of addresses relevant to user's query
        let relevant_addrs = match &query_owner {
            Either::Left(BalanceOwner::Address(owner)) => vec![owner.clone()],
            // MASP objects are dealt with outside of tx_search
            Either::Left(BalanceOwner::FullViewingKey(_viewing_key)) => vec![],
            Either::Left(BalanceOwner::PaymentAddress(_owner)) => vec![],
            // Unspecified owner means all known addresses are considered
            // relevant
            Either::Right(addrs) => addrs.clone(),
        };
        // Find all transactions to or from the relevant address set
        for addr in relevant_addrs {
            for prop in ["transfer.source", "transfer.target"] {
                // Query transactions involving the current address
                let mut tx_query = Query::eq(prop, addr.encode());
                // Elaborate the query if requested by the user
                if let Some(token) = &query_token {
                    tx_query =
                        tx_query.and_eq("transfer.token", token.encode());
                }
                for page in 1.. {
                    let txs = &client
                        .tx_search(
                            tx_query.clone(),
                            true,
                            page,
                            TXS_PER_PAGE,
                            Order::Ascending,
                        )
                        .await
                        .map_err(|e| {
                            Error::from(QueryError::General(format!(
                                "for transaction: {e}"
                            )))
                        })?
                        .txs;
                    for response_tx in txs {
                        let height = BlockHeight(response_tx.height.value());
                        let idx = TxIndex(response_tx.index);
                        // Only process yet unprocessed transactions which have
                        // been accepted by node VPs
                        let should_process = !transfers
                            .contains_key(&IndexedTx { height, index: idx })
                            && block_results[u64::from(height) as usize]
                                .is_accepted(idx.0 as usize);
                        if !should_process {
                            continue;
                        }
                        let tx = Tx::try_from(response_tx.tx.as_ref())
                            .map_err(|e| Error::Other(e.to_string()))?;
                        let mut wrapper = None;
                        let mut transfer = None;
                        extract_payload(tx, &mut wrapper, &mut transfer)?;
                        // Epoch data is not needed for transparent transactions
                        let epoch =
                            wrapper.map(|x| x.epoch).unwrap_or_default();
                        if let Some(transfer) = transfer {
                            // Skip MASP addresses as they are already handled
                            // by ShieldedContext
                            if transfer.source == MASP
                                || transfer.target == MASP
                            {
                                continue;
                            }
                            // Describe how a Transfer simply subtracts from one
                            // account and adds the same to another

                            let delta = TransferDelta::from([(
                                transfer.source.clone(),
                                MaspChange {
                                    asset: transfer.token.clone(),
                                    change: -transfer.amount.amount().change(),
                                },
                            )]);

                            // No shielded accounts are affected by this
                            // Transfer
                            transfers.insert(
                                IndexedTx { height, index: idx },
                                (epoch, delta, TransactionDelta::new()),
                            );
                        }
                    }
                    // An incomplete page signifies no more transactions
                    if (txs.len() as u8) < TXS_PER_PAGE {
                        break;
                    }
                }
            }
        }
        Ok(transfers)
    }
}

/// Extract the payload from the given Tx object
fn extract_payload(
    tx: Tx,
    wrapper: &mut Option<WrapperTx>,
    transfer: &mut Option<Transfer>,
) -> Result<(), Error> {
    *wrapper = tx.header.wrapper();
    let _ = tx.data().map(|signed| {
        Transfer::try_from_slice(&signed[..]).map(|tfer| *transfer = Some(tfer))
    });
    Ok(())
}

/// Make asset type corresponding to given address and epoch
pub fn make_asset_type(
    epoch: Option<Epoch>,
    token: &Address,
    denom: MaspDenom,
) -> Result<AssetType, Error> {
    // Typestamp the chosen token with the current epoch
    let token_bytes = match epoch {
        None => (token, denom).serialize_to_vec(),
        Some(epoch) => (token, denom, epoch.0).serialize_to_vec(),
    };
    // Generate the unique asset identifier from the unique token address
    AssetType::new(token_bytes.as_ref())
        .map_err(|_| Error::Other("unable to create asset type".to_string()))
}

/// Convert Anoma amount and token type to MASP equivalents
fn convert_amount(
    epoch: Epoch,
    token: &Address,
    val: token::Amount,
) -> Result<([AssetType; 4], U64Sum), Error> {
    let mut amount = U64Sum::zero();
    let asset_types: [AssetType; 4] = MaspDenom::iter()
        .map(|denom| {
            let asset_type = make_asset_type(Some(epoch), token, denom)?;
            // Combine the value and unit into one amount
            amount +=
                U64Sum::from_nonnegative(asset_type, denom.denominate(&val))
                    .map_err(|_| {
                        Error::Other("invalid value for amount".to_string())
                    })?;
            Ok(asset_type)
        })
        .collect::<Result<Vec<AssetType>, Error>>()?
        .try_into()
        .map_err(|_| Error::Other(format!("This can't fail: {}", line!())))?;
    Ok((asset_types, amount))
}

// Retrieves all the indexes and tx events at the specified height which refer
// to a valid masp transaction. If an index is given, it filters only the
// transactions with an index equal or greater to the provided one.
async fn get_indexed_masp_events_at_height<C: Client + Sync>(
    client: &C,
    height: BlockHeight,
    first_idx_to_query: Option<TxIndex>,
) -> Result<Option<Vec<(TxIndex, crate::tendermint::abci::Event)>>, Error> {
    let first_idx_to_query = first_idx_to_query.unwrap_or_default();

    Ok(client
        .block_results(height.0 as u32)
        .await
        .map_err(|e| Error::from(QueryError::General(e.to_string())))?
        .end_block_events
        .map(|events| {
            events
                .into_iter()
                .filter_map(|event| {
                    let tx_index =
                        event.attributes.iter().find_map(|attribute| {
                            if attribute.key == "is_valid_masp_tx" {
                                Some(TxIndex(
                                    u32::from_str(&attribute.value).unwrap(),
                                ))
                            } else {
                                None
                            }
                        });

                    match tx_index {
                        Some(idx) => {
                            if idx >= first_idx_to_query {
                                Some((idx, event))
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                })
                .collect::<Vec<_>>()
        }))
}

enum ExtractShieldedActionArg<'args, C: Client + Sync> {
    Event(crate::tendermint::abci::Event),
    Request((&'args C, BlockHeight, Option<TxIndex>)),
}

// Extract the Transfer and Transaction objects from a masp over ibc message
async fn extract_payload_from_shielded_action<'args, C: Client + Sync>(
    tx_data: &[u8],
    args: ExtractShieldedActionArg<'args, C>,
) -> Result<IbcShieldedTransfer, Error> {
    let message = namada_core::ledger::ibc::decode_message(tx_data)
        .map_err(|e| Error::Other(e.to_string()))?;

    let shielded_transfer = match message {
        IbcMessage::Transfer(msg) => {
            msg.shielded_transfer.ok_or_else(|| {
                Error::Other(
                    "Missing required shielded transfer in IBC message"
                        .to_string(),
                )
            })?
        }
        IbcMessage::NftTransfer(msg) => {
            msg.shielded_transfer.ok_or_else(|| {
                Error::Other(
                    "Missing required shielded transfer in IBC message"
                        .to_string(),
                )
            })?
        }
        IbcMessage::Envelope(_) => {
            let tx_event = match args {
                ExtractShieldedActionArg::Event(event) => event,
                ExtractShieldedActionArg::Request((client, height, index)) => {
                    get_indexed_masp_events_at_height(client, height, index)
                        .await?
                        .ok_or_else(|| {
                            Error::Other(format!(
                                "Missing required ibc event at block height {}",
                                height
                            ))
                        })?
                        .first()
                        .ok_or_else(|| {
                            Error::Other(format!(
                                "Missing required ibc event at block height {}",
                                height
                            ))
                        })?
                        .1
                        .to_owned()
                }
            };

            tx_event
                .attributes
                .iter()
                .find_map(|attribute| {
                    if attribute.key == "inner_tx" {
                        let tx_result =
                            TxResult::from_str(&attribute.value).unwrap();
                        for ibc_event in &tx_result.ibc_events {
                            let event =
                                namada_core::types::ibc::get_shielded_transfer(
                                    ibc_event,
                                )
                                .ok()
                                .flatten();
                            if event.is_some() {
                                return event;
                            }
                        }
                        None
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    Error::Other(
                        "Couldn't deserialize masp tx to ibc message envelope"
                            .to_string(),
                    )
                })?
        }
    };

    Ok(shielded_transfer)
}

mod tests {
    /// quick and dirty test. will fail on size check
    #[test]
    #[should_panic(expected = "parameter file size is not correct")]
    fn test_wrong_masp_params() {
        use std::io::Write;

        use super::{CONVERT_NAME, OUTPUT_NAME, SPEND_NAME};

        let tempdir = tempfile::tempdir()
            .expect("expected a temp dir")
            .into_path();
        let fake_params_paths =
            [SPEND_NAME, OUTPUT_NAME, CONVERT_NAME].map(|p| tempdir.join(p));
        for path in &fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            f.write_all(b"fake params")
                .expect("expected a writable temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        std::env::set_var(super::ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
        // should panic here
        masp_proofs::load_parameters(
            &fake_params_paths[0],
            &fake_params_paths[1],
            &fake_params_paths[2],
        );
    }

    /// a more involved test, using dummy parameters with the right
    /// size but the wrong hash.
    #[test]
    #[should_panic(expected = "parameter file is not correct")]
    fn test_wrong_masp_params_hash() {
        use masp_primitives::ff::PrimeField;
        use masp_proofs::bellman::groth16::{
            generate_random_parameters, Parameters,
        };
        use masp_proofs::bellman::{Circuit, ConstraintSystem, SynthesisError};
        use masp_proofs::bls12_381::{Bls12, Scalar};

        use super::{CONVERT_NAME, OUTPUT_NAME, SPEND_NAME};

        struct FakeCircuit<E: PrimeField> {
            x: E,
        }

        impl<E: PrimeField> Circuit<E> for FakeCircuit<E> {
            fn synthesize<CS: ConstraintSystem<E>>(
                self,
                cs: &mut CS,
            ) -> Result<(), SynthesisError> {
                let x = cs.alloc(|| "x", || Ok(self.x)).unwrap();
                cs.enforce(
                    || {
                        "this is an extra long constraint name so that rustfmt \
                         is ok with wrapping the params of enforce()"
                    },
                    |lc| lc + x,
                    |lc| lc + x,
                    |lc| lc + x,
                );
                Ok(())
            }
        }

        let dummy_circuit = FakeCircuit { x: Scalar::zero() };
        let mut rng = rand::thread_rng();
        let fake_params: Parameters<Bls12> =
            generate_random_parameters(dummy_circuit, &mut rng)
                .expect("expected to generate fake params");

        let tempdir = tempfile::tempdir()
            .expect("expected a temp dir")
            .into_path();
        // TODO: get masp to export these consts
        let fake_params_paths = [
            (SPEND_NAME, 49848572u64),
            (OUTPUT_NAME, 16398620u64),
            (CONVERT_NAME, 22570940u64),
        ]
        .map(|(p, s)| (tempdir.join(p), s));
        for (path, size) in &fake_params_paths {
            let mut f =
                std::fs::File::create(path).expect("expected a temp file");
            fake_params
                .write(&mut f)
                .expect("expected a writable temp file");
            // the dummy circuit has one constraint, and therefore its
            // params should always be smaller than the large masp
            // circuit params. so this truncate extends the file, and
            // extra bytes at the end do not make it invalid.
            f.set_len(*size)
                .expect("expected to truncate the temp file");
            f.sync_all()
                .expect("expected a writable temp file (on sync)");
        }

        std::env::set_var(super::ENV_VAR_MASP_PARAMS_DIR, tempdir.as_os_str());
        // should panic here
        masp_proofs::load_parameters(
            &fake_params_paths[0].0,
            &fake_params_paths[1].0,
            &fake_params_paths[2].0,
        );
    }
}

#[cfg(feature = "std")]
/// Implementation of MASP functionality depending on a standard filesystem
pub mod fs {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};

    use super::*;

    /// Shielded context file name
    const FILE_NAME: &str = "shielded.dat";
    const TMP_FILE_NAME: &str = "shielded.tmp";

    #[derive(Debug, BorshSerialize, BorshDeserialize, Clone)]
    /// An implementation of ShieldedUtils for standard filesystems
    pub struct FsShieldedUtils {
        #[borsh(skip)]
        context_dir: PathBuf,
    }

    impl FsShieldedUtils {
        /// Initialize a shielded transaction context that identifies notes
        /// decryptable by any viewing key in the given set
        pub fn new(context_dir: PathBuf) -> ShieldedContext<Self> {
            // Make sure that MASP parameters are downloaded to enable MASP
            // transaction building and verification later on
            let params_dir = get_params_dir();
            let spend_path = params_dir.join(SPEND_NAME);
            let convert_path = params_dir.join(CONVERT_NAME);
            let output_path = params_dir.join(OUTPUT_NAME);
            if !(spend_path.exists()
                && convert_path.exists()
                && output_path.exists())
            {
                println!("MASP parameters not present, downloading...");
                masp_proofs::download_masp_parameters(None)
                    .expect("MASP parameters not present or downloadable");
                println!(
                    "MASP parameter download complete, resuming execution..."
                );
            }
            // Finally initialize a shielded context with the supplied directory
            let utils = Self { context_dir };
            ShieldedContext {
                utils,
                ..Default::default()
            }
        }
    }

    impl Default for FsShieldedUtils {
        fn default() -> Self {
            Self {
                context_dir: PathBuf::from(FILE_NAME),
            }
        }
    }

    #[cfg_attr(feature = "async-send", async_trait::async_trait)]
    #[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
    impl ShieldedUtils for FsShieldedUtils {
        fn local_tx_prover(&self) -> LocalTxProver {
            if let Ok(params_dir) = env::var(ENV_VAR_MASP_PARAMS_DIR) {
                let params_dir = PathBuf::from(params_dir);
                let spend_path = params_dir.join(SPEND_NAME);
                let convert_path = params_dir.join(CONVERT_NAME);
                let output_path = params_dir.join(OUTPUT_NAME);
                LocalTxProver::new(&spend_path, &output_path, &convert_path)
            } else {
                LocalTxProver::with_default_location()
                    .expect("unable to load MASP Parameters")
            }
        }

        /// Try to load the last saved shielded context from the given context
        /// directory. If this fails, then leave the current context unchanged.
        async fn load<U: ShieldedUtils + MaybeSend>(
            &self,
            ctx: &mut ShieldedContext<U>,
        ) -> std::io::Result<()> {
            // Try to load shielded context from file
            let mut ctx_file = File::open(self.context_dir.join(FILE_NAME))?;
            let mut bytes = Vec::new();
            ctx_file.read_to_end(&mut bytes)?;
            // Fill the supplied context with the deserialized object
            *ctx = ShieldedContext {
                utils: ctx.utils.clone(),
                ..ShieldedContext::<U>::deserialize(&mut &bytes[..])?
            };
            Ok(())
        }

        /// Save this shielded context into its associated context directory
        async fn save<U: ShieldedUtils + MaybeSync>(
            &self,
            ctx: &ShieldedContext<U>,
        ) -> std::io::Result<()> {
            // TODO: use mktemp crate?
            let tmp_path = self.context_dir.join(TMP_FILE_NAME);
            {
                // First serialize the shielded context into a temporary file.
                // Inability to create this file implies a simultaneuous write
                // is in progress. In this case, immediately
                // fail. This is unproblematic because the data
                // intended to be stored can always be re-fetched
                // from the blockchain.
                let mut ctx_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(tmp_path.clone())?;
                let mut bytes = Vec::new();
                ctx.serialize(&mut bytes)
                    .expect("cannot serialize shielded context");
                ctx_file.write_all(&bytes[..])?;
            }
            // Atomically update the old shielded context file with new data.
            // Atomicity is required to prevent other client instances from
            // reading corrupt data.
            std::fs::rename(
                tmp_path.clone(),
                self.context_dir.join(FILE_NAME),
            )?;
            // Finally, remove our temporary file to allow future saving of
            // shielded contexts.
            std::fs::remove_file(tmp_path)?;
            Ok(())
        }
    }
}
