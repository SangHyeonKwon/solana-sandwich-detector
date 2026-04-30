//! Traits for resolving pool configuration (vault addresses, fee rate) by pool id.
//!
//! Pool config is static per pool (doesn't change per swap), so lookups should
//! cache aggressively. See [`raydium_v4::fetch_config`] etc for the concrete
//! fetchers.

use async_trait::async_trait;
use swap_events::types::DexType;

/// Kind of AMM that backs a pool — determines which math to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmmKind {
    RaydiumV4,
    RaydiumCpmm,
    /// Orca Whirlpool concentrated-liquidity AMM. Config (vault / mint /
    /// fee) and pool-state (sqrt_price / liquidity / tick) parsing are
    /// in [`crate::orca_whirlpool`]; replay support lands in a follow-up
    /// — `enrich_attack` currently routes this kind to
    /// [`EnrichmentResult::UnsupportedDex`](crate::EnrichmentResult).
    OrcaWhirlpool,
}

impl AmmKind {
    /// Map a [`DexType`] to an AMM kind this crate can recognise. Returns
    /// `None` for DEXes we have neither config parsing nor replay for
    /// (Pump.fun, Phoenix, Jupiter, Meteora DLMM, Raydium CLMM).
    pub fn from_dex(dex: DexType) -> Option<Self> {
        match dex {
            DexType::RaydiumV4 => Some(AmmKind::RaydiumV4),
            DexType::RaydiumCpmm => Some(AmmKind::RaydiumCpmm),
            DexType::OrcaWhirlpool => Some(AmmKind::OrcaWhirlpool),
            _ => None,
        }
    }
}

/// Static configuration for a single pool.
///
/// `vault_base` / `vault_quote` are the SPL token accounts that hold the pool's
/// reserves — the [`reserves`](crate::reserves) module uses these addresses to
/// extract balances from a tx's `pre_token_balances` / `post_token_balances`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolConfig {
    pub kind: AmmKind,
    pub pool: String,
    pub vault_base: String,
    pub vault_quote: String,
    pub base_mint: String,
    pub quote_mint: String,
    pub fee_num: u64,
    pub fee_den: u64,
}

/// Slot-anchored *dynamic* pool state — the swap-relevant fields that
/// evolve with every trade and which Whirlpool replay needs but
/// `getAccountInfo` log scraping can't recover (Whirlpool doesn't emit
/// sqrt_price into instruction logs).
///
/// Constant-product AMMs aren't represented here: their dynamic state
/// (vault reserves) is already extractable from the tx's
/// `pre_token_balances` via [`crate::reserves`], so they don't need a
/// separate slot-anchored fetch path. New variants land alongside new
/// concentrated-liquidity DEXes (e.g. DLMM bin price math).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicPoolState {
    /// Whirlpool concentrated-liquidity snapshot. Mirrors the subset of
    /// [`crate::orca_whirlpool::WhirlpoolPool`] that within-tick replay
    /// needs.
    Whirlpool {
        sqrt_price_q64: u128,
        liquidity: u128,
        tick_current_index: i32,
        tick_spacing: u16,
    },
}

/// Resolve pool configuration. Typically backed by a cached RPC client.
///
/// Takes [`DexType`] to decide which on-chain layout to parse — each AMM has its
/// own account layout, so the caller needs to tell us what kind of pool it is.
#[async_trait]
pub trait PoolStateLookup: Send + Sync {
    async fn pool_config(&self, pool: &str, dex: DexType) -> Option<PoolConfig>;

    /// Fetch slot-anchored dynamic pool state for AMMs whose replay needs
    /// state beyond vault reserves (Whirlpool sqrt_price / liquidity /
    /// tick). Default returns `None`, so implementations that don't speak
    /// the dynamic-state protocol stay opt-in and the caller falls back
    /// to whatever short-circuit the dispatch layer prefers.
    ///
    /// `slot` is currently passed through but unused — `getAccountInfo`
    /// returns latest-confirmed state, which is good enough for streamed
    /// detection but not for backfill from archival data. Plumbing the
    /// argument now lets archival-aware implementations land later
    /// without breaking the trait shape.
    async fn pool_dynamic_state(
        &self,
        _pool: &str,
        _dex: DexType,
        _slot: u64,
    ) -> Option<DynamicPoolState> {
        None
    }
}

/// No-op lookup: returns `None` for every pool. Used when pool-state
/// enrichment is disabled.
pub struct NoPoolLookup;

#[async_trait]
impl PoolStateLookup for NoPoolLookup {
    async fn pool_config(&self, _pool: &str, _dex: DexType) -> Option<PoolConfig> {
        None
    }
}

/// Resolve the validator identity (base58 pubkey) that produced a given slot.
///
/// Solana's leader schedule is fixed per-epoch and exposed via `getSlotLeaders`.
/// Implementations should batch and cache aggressively — a typical scan asks
/// for hundreds of thousands of slots, so per-slot RPC roundtrips are out of
/// the question. The trait exists so detector consumers can drop in a no-op
/// implementation when validator metadata isn't needed.
#[async_trait]
pub trait SlotLeaderLookup: Send + Sync {
    /// Returns the validator identity for `slot`, or `None` if unknown
    /// (RPC failure, slot too far in the future, etc.). `None` is also the
    /// expected return for [`NoSlotLeaderLookup`].
    async fn slot_leader(&self, slot: u64) -> Option<String>;
}

/// No-op slot-leader lookup: returns `None` for every slot. Used when the
/// caller doesn't want to make extra RPC calls (e.g. fixture replay) or hasn't
/// configured a leader-aware RPC.
pub struct NoSlotLeaderLookup;

#[async_trait]
impl SlotLeaderLookup for NoSlotLeaderLookup {
    async fn slot_leader(&self, _slot: u64) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_slot_leader_lookup_always_returns_none() {
        let lookup = NoSlotLeaderLookup;
        assert_eq!(lookup.slot_leader(0).await, None);
        assert_eq!(lookup.slot_leader(123_456_789).await, None);
    }

    /// `NoPoolLookup` doesn't override `pool_dynamic_state`, so it must
    /// inherit the default `None`. Pins the contract that disabling
    /// enrichment also disables dynamic-state fetches.
    #[tokio::test]
    async fn no_pool_lookup_dynamic_state_returns_none() {
        let lookup = NoPoolLookup;
        assert!(lookup
            .pool_dynamic_state("any-pool", DexType::OrcaWhirlpool, 0)
            .await
            .is_none());
    }
}
