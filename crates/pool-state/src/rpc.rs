//! RPC-backed [`PoolStateLookup`] / [`SlotLeaderLookup`] with in-memory caching.
//!
//! Pool config is static per pool (vault addresses and fee rates don't change),
//! so the first request for each pool hits `getAccountInfo` and subsequent
//! requests — including failed lookups — are served from cache.
//!
//! Slot leaders are paginated by [`SLOT_LEADER_PAGE_SIZE`]; the first slot in a
//! page triggers a `getSlotLeaders(start, page)` fetch and the entire page is
//! cached, so a long scan amortizes one RPC call per ~1k slots.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use swap_events::types::DexType;
use tokio::sync::Mutex;
use tracing::warn;

use crate::lookup::{DynamicPoolState, PoolConfig, PoolStateLookup, SlotLeaderLookup};
use crate::{orca_whirlpool, raydium_cpmm, raydium_v4};

pub struct RpcPoolLookup {
    client: Arc<RpcClient>,
    cache: Mutex<HashMap<String, Option<PoolConfig>>>,
}

impl RpcPoolLookup {
    pub fn new(rpc_url: &str) -> Self {
        Self::with_client(Arc::new(RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        )))
    }

    pub fn with_client(client: Arc<RpcClient>) -> Self {
        Self {
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }

    async fn fetch(&self, pool: &str, dex: DexType) -> Option<PoolConfig> {
        let pubkey = match pool.parse::<Pubkey>() {
            Ok(p) => p,
            Err(e) => {
                warn!(pool, error = %e, "invalid pool pubkey");
                return None;
            }
        };
        let account = match self.client.get_account(&pubkey).await {
            Ok(a) => a,
            Err(e) => {
                warn!(pool, error = %e, "pool account fetch failed");
                return None;
            }
        };
        match dex {
            DexType::RaydiumV4 => raydium_v4::parse_config(pool, &account.data),
            DexType::RaydiumCpmm => raydium_cpmm::parse_config(pool, &account.data),
            DexType::OrcaWhirlpool => orca_whirlpool::parse_config(pool, &account.data),
            _ => None,
        }
    }
}

#[async_trait]
impl PoolStateLookup for RpcPoolLookup {
    async fn pool_config(&self, pool: &str, dex: DexType) -> Option<PoolConfig> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = cache.get(pool) {
                return entry.clone();
            }
        }
        let fetched = self.fetch(pool, dex).await;
        let mut cache = self.cache.lock().await;
        // Handle races: another task may have fetched while we were busy.
        cache
            .entry(pool.to_string())
            .or_insert(fetched.clone())
            .clone()
    }

    /// Fetch the pool's dynamic state via `getAccountInfo`, parsing the
    /// account blob with the same layout reader the static-config path
    /// uses. Not cached — dynamic state evolves every swap, so a stale
    /// snapshot is worse than a fresh round-trip. Whirlpool is the only
    /// kind we can serve today; other dynamic-state DEXes return `None`
    /// (the trait default) and stay opt-in.
    ///
    /// `slot` is accepted but unused. Mainnet `getAccountInfo` returns
    /// latest-confirmed state, which lines up with stream-mode detection
    /// where enrichment runs within a few hundred ms of the frontrun
    /// landing. Archival-anchored fetches (slot-precise pre-frontrun
    /// state) need a different RPC and land in a follow-up.
    async fn pool_dynamic_state(
        &self,
        pool: &str,
        dex: DexType,
        _slot: u64,
    ) -> Option<DynamicPoolState> {
        if !matches!(dex, DexType::OrcaWhirlpool) {
            return None;
        }
        let pubkey = match pool.parse::<Pubkey>() {
            Ok(p) => p,
            Err(e) => {
                warn!(pool, error = %e, "invalid pool pubkey for dynamic state");
                return None;
            }
        };
        let account = match self.client.get_account(&pubkey).await {
            Ok(a) => a,
            Err(e) => {
                warn!(pool, error = %e, "pool account fetch failed for dynamic state");
                return None;
            }
        };
        let pool_state = orca_whirlpool::parse_pool_state(&account.data)?;
        Some(DynamicPoolState::Whirlpool {
            sqrt_price_q64: pool_state.sqrt_price_q64,
            liquidity: pool_state.liquidity,
            tick_current_index: pool_state.tick_current_index,
            tick_spacing: pool_state.tick_spacing,
        })
    }
}

/// Page size for `getSlotLeaders` fetches. RPC providers cap this around
/// 5000; 1000 keeps each call well under the cap and bounds memory at
/// ~32KB/page. One page covers ~7 minutes of mainnet activity, which is
/// more than enough for a single scan window.
pub const SLOT_LEADER_PAGE_SIZE: u64 = 1000;

/// RPC-backed [`SlotLeaderLookup`] with page-level caching.
///
/// Each page covers `[page_start, page_start + SLOT_LEADER_PAGE_SIZE)`. The
/// page is fetched on first miss and cached as `Arc<Vec<String>>`; subsequent
/// lookups within the page are O(1). Failed fetches cache an empty page so we
/// don't retry a known-bad slot range on every detection.
pub struct RpcSlotLeaderLookup {
    client: Arc<RpcClient>,
    /// page_start (slot floored to a [`SLOT_LEADER_PAGE_SIZE`] boundary) →
    /// page contents. Empty `Vec` means the fetch failed; we cache the
    /// failure to avoid hammering the RPC.
    cache: Mutex<HashMap<u64, Arc<Vec<String>>>>,
}

impl RpcSlotLeaderLookup {
    pub fn new(rpc_url: &str) -> Self {
        Self::with_client(Arc::new(RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        )))
    }

    pub fn with_client(client: Arc<RpcClient>) -> Self {
        Self {
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn page_start(slot: u64) -> u64 {
        (slot / SLOT_LEADER_PAGE_SIZE) * SLOT_LEADER_PAGE_SIZE
    }

    async fn fetch_page(&self, page_start: u64) -> Vec<String> {
        match self
            .client
            .get_slot_leaders(page_start, SLOT_LEADER_PAGE_SIZE)
            .await
        {
            Ok(leaders) => leaders.into_iter().map(|p| p.to_string()).collect(),
            Err(e) => {
                warn!(page_start, error = %e, "getSlotLeaders failed");
                Vec::new()
            }
        }
    }
}

#[async_trait]
impl SlotLeaderLookup for RpcSlotLeaderLookup {
    async fn slot_leader(&self, slot: u64) -> Option<String> {
        let page_start = Self::page_start(slot);
        let offset = (slot - page_start) as usize;
        {
            let cache = self.cache.lock().await;
            if let Some(page) = cache.get(&page_start) {
                return page.get(offset).cloned();
            }
        }
        let page = Arc::new(self.fetch_page(page_start).await);
        let result = page.get(offset).cloned();
        let mut cache = self.cache.lock().await;
        // Handle races: another task may have populated this page while we
        // were waiting on the RPC.
        cache.entry(page_start).or_insert(page);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_start_floors_to_boundary() {
        assert_eq!(RpcSlotLeaderLookup::page_start(0), 0);
        assert_eq!(RpcSlotLeaderLookup::page_start(999), 0);
        assert_eq!(RpcSlotLeaderLookup::page_start(1000), 1000);
        assert_eq!(RpcSlotLeaderLookup::page_start(1234), 1000);
        assert_eq!(RpcSlotLeaderLookup::page_start(2_000_000), 2_000_000);
    }
}
