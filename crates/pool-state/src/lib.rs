//! AMM pool state reconstruction + counterfactual replay.
//!
//! The detector crates identify sandwich *patterns* but cannot say how much a
//! victim actually lost — that requires replaying the swaps through the AMM's
//! math with real reserves. This crate provides that replay primitive.
//!
//! Two sources of truth for reserves:
//!   1. **Pool config** (vault addresses, fee rate) — fetched once per pool via
//!      `getAccountInfo` and cached. See [`RaydiumV4Config`], [`RaydiumCpmmConfig`].
//!   2. **Vault balances at a given tx** — extracted from the tx meta's
//!      `pre_token_balances` / `post_token_balances`. No historical RPC needed.
//!      See [`reserves`] module.
//!
//! The [`counterfactual::compute_loss`] function combines these to produce a
//! [`counterfactual::LossEstimate`] with AMM-correct victim loss and attacker profit.

pub mod constant_product;
pub mod counterfactual;
pub mod diff_test;
pub mod enrichment;
pub mod fixed_point;
pub mod lookup;
pub mod meteora_dlmm;
pub mod orca_whirlpool;
pub mod pump_fun;
pub mod raydium_cpmm;
pub mod raydium_v4;
pub mod reserves;
pub mod rpc;
pub mod spl_mint;

pub use constant_product::ConstantProduct;
pub use counterfactual::{
    compute_loss, compute_loss_dlmm, compute_loss_dlmm_with_trace, compute_loss_whirlpool,
    compute_loss_whirlpool_with_trace, compute_loss_with_trace, LossEstimate,
};
pub use diff_test::{
    compare_clmm_replay_to_archival, cross_check_victim_balance, diff_against_observed_tx,
    diff_attack_against_archival, reserves_divergence_bps, BalanceDiffReport, CrossCheckError,
    WhirlpoolDiffReport, PASS_THRESHOLD_BPS,
};
pub use enrichment::{enrich_attack, EnrichmentResult};
pub use lookup::{
    AmmKind, DynamicPoolState, NoPoolLookup, NoSlotLeaderLookup, PoolConfig, PoolStateLookup,
    SlotLeaderLookup,
};
pub use orca_whirlpool::tick_array::{ParsedTickArray, TickData};
pub use rpc::{
    AccountFetcher, LatestAccountFetcher, RpcPoolLookup, RpcSlotLeaderLookup, SLOT_LEADER_PAGE_SIZE,
};
