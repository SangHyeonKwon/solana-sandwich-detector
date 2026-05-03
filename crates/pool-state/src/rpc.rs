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
use solana_epoch_schedule::EpochSchedule;
use solana_sdk::account::Account;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use swap_events::types::DexType;
use tokio::sync::{Mutex, OnceCell};
use tracing::warn;

use crate::lookup::{DynamicPoolState, PoolConfig, PoolStateLookup, SlotLeaderLookup};
use crate::meteora_dlmm::bin_array::ParsedBinArray;
use crate::orca_whirlpool::tick_array::ParsedTickArray;
use crate::spl_mint::{self, MintInfo};
use crate::{meteora_dlmm, orca_whirlpool, raydium_clmm, raydium_cpmm, raydium_v4};

/// Slot-aware account-fetch surface for archival providers.
///
/// The standard `solana-client` `getAccountInfo` always returns
/// latest-confirmed state — fine for stream-mode detection (the
/// frontrun landed seconds ago) but wrong for backfill replay against
/// historical sandwiches. Archival providers expose proprietary
/// slot-precise lookup methods that don't fit the public RPC surface;
/// this trait is the integration point.
///
/// The default [`LatestAccountFetcher`] ignores `slot` and serves
/// latest-confirmed state — same behaviour the codebase had before
/// this trait existed. To wire archival, implement this trait against
/// your provider's API (Helius `getAccountInfoAtSlot`, Triton's
/// archival endpoint, etc.) and hand it to
/// [`RpcPoolLookup::with_account_fetcher`].
#[async_trait]
pub trait AccountFetcher: Send + Sync {
    /// Fetch a single account at the given slot. Returns `None` when
    /// the fetch fails (RPC error, archival provider rejected the
    /// slot, account doesn't exist).
    ///
    /// Implementations that don't support slot-precise lookups should
    /// document that and ignore `slot`.
    async fn fetch_account(&self, pubkey: &Pubkey, slot: u64) -> Option<Account>;

    /// Fetch multiple accounts at the same slot. Result is **1:1
    /// aligned** with `pubkeys` — `None` at index `i` means that
    /// account's fetch failed or the account doesn't exist. Callers
    /// rely on the alignment to match results back to their inputs.
    async fn fetch_multiple_accounts(&self, pubkeys: &[Pubkey], slot: u64) -> Vec<Option<Account>>;
}

/// Default [`AccountFetcher`] — wraps an [`RpcClient`] and serves
/// latest-confirmed state via `getAccountInfo` / `getMultipleAccounts`.
/// `slot` is ignored. Suitable for stream-mode detection where the
/// frontrun landed within the last few hundred ms; **not suitable**
/// for backfill replay where slot-precise pre-frontrun state matters.
pub struct LatestAccountFetcher {
    client: Arc<RpcClient>,
}

impl LatestAccountFetcher {
    pub fn new(client: Arc<RpcClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AccountFetcher for LatestAccountFetcher {
    async fn fetch_account(&self, pubkey: &Pubkey, _slot: u64) -> Option<Account> {
        match self.client.get_account(pubkey).await {
            Ok(a) => Some(a),
            Err(e) => {
                warn!(pubkey = %pubkey, error = %e, "get_account failed");
                None
            }
        }
    }

    async fn fetch_multiple_accounts(
        &self,
        pubkeys: &[Pubkey],
        _slot: u64,
    ) -> Vec<Option<Account>> {
        if pubkeys.is_empty() {
            return Vec::new();
        }
        match self.client.get_multiple_accounts(pubkeys).await {
            Ok(accounts) => accounts,
            Err(e) => {
                warn!(error = %e, "get_multiple_accounts failed");
                pubkeys.iter().map(|_| None).collect()
            }
        }
    }
}

pub struct RpcPoolLookup {
    /// Static-config client. Pool config (vault addrs, fee rate) is
    /// invariant per pool, so latest-confirmed is always correct here
    /// — no archival routing needed.
    client: Arc<RpcClient>,
    /// Slot-aware fetcher for *dynamic* state. Defaults to
    /// [`LatestAccountFetcher`]; swap in a provider-specific impl via
    /// [`Self::with_account_fetcher`] for archival backfill.
    fetcher: Arc<dyn AccountFetcher>,
    cache: Mutex<HashMap<String, Option<PoolConfig>>>,
    /// `EpochSchedule` is invariant for the life of a Solana cluster
    /// (governance change required), so one `getEpochSchedule` round
    /// trip per `RpcPoolLookup` instance suffices. `OnceCell` runs the
    /// init future exactly once even under concurrent calls; the
    /// inner `Option<EpochSchedule>` is `None` when the RPC fetch
    /// failed (cached so we don't retry on every enrichment call).
    epoch_schedule: OnceCell<Option<EpochSchedule>>,
}

impl RpcPoolLookup {
    pub fn new(rpc_url: &str) -> Self {
        Self::with_client(Arc::new(RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        )))
    }

    pub fn with_client(client: Arc<RpcClient>) -> Self {
        let fetcher: Arc<dyn AccountFetcher> = Arc::new(LatestAccountFetcher::new(client.clone()));
        Self {
            client,
            fetcher,
            cache: Mutex::new(HashMap::new()),
            epoch_schedule: OnceCell::new(),
        }
    }

    /// Construct an [`RpcPoolLookup`] that routes dynamic-state and
    /// tick-array fetches through a custom [`AccountFetcher`]. Static
    /// pool-config lookups continue to use `rpc_url` directly because
    /// pool config doesn't vary by slot.
    ///
    /// Use this when you have an archival provider integration —
    /// `enrich_attack` will pass `attack.slot` through to the fetcher,
    /// and the provider's slot-precise lookup serves pre-frontrun
    /// pool state for backfill replay.
    pub fn with_account_fetcher(rpc_url: &str, fetcher: Arc<dyn AccountFetcher>) -> Self {
        let client = Arc::new(RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        ));
        Self {
            client,
            fetcher,
            cache: Mutex::new(HashMap::new()),
            epoch_schedule: OnceCell::new(),
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
            DexType::MeteoraDlmm => meteora_dlmm::parse_config(pool, &account.data),
            DexType::RaydiumClmm => self.fetch_raydium_clmm_config(pool, &account.data).await,
            _ => None,
        }
    }

    /// Two-step config fetch unique to Raydium CLMM: the pool's `PoolState`
    /// account points at a shared `AmmConfig` (one config per
    /// tick-spacing tier, many pools share each), and the trade-fee
    /// numerator we need lives on that second account. Whirlpool
    /// inlines `fee_rate` directly so its single-fetch path stays
    /// outside this branch.
    ///
    /// `pool_state_data` is the `PoolState` blob the caller already
    /// fetched; we extract the `amm_config` pubkey from it, fetch
    /// the config blob, and hand both to the parsing layer.
    async fn fetch_raydium_clmm_config(
        &self,
        pool: &str,
        pool_state_data: &[u8],
    ) -> Option<PoolConfig> {
        let amm_config_pubkey = raydium_clmm::parse_amm_config_pubkey(pool_state_data)?;
        let amm_config_account = match self.client.get_account(&amm_config_pubkey).await {
            Ok(a) => a,
            Err(e) => {
                warn!(
                    pool,
                    amm_config = %amm_config_pubkey,
                    error = %e,
                    "raydium clmm amm_config account fetch failed",
                );
                return None;
            }
        };
        raydium_clmm::parse_config(pool, pool_state_data, &amm_config_account.data)
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

    /// Fetch the pool's dynamic state via the configured
    /// [`AccountFetcher`], parsing the account blob with the same
    /// layout reader the static-config path uses. Not cached — dynamic
    /// state evolves every swap, so a stale snapshot is worse than a
    /// fresh round-trip. Whirlpool is the only kind we can serve
    /// today; other dynamic-state DEXes return `None` (the trait
    /// default) and stay opt-in.
    ///
    /// `slot` is forwarded to the fetcher. The default
    /// [`LatestAccountFetcher`] ignores it (returns latest-confirmed,
    /// fine for stream-mode); supply a custom fetcher via
    /// [`Self::with_account_fetcher`] for slot-precise archival
    /// backfill.
    async fn pool_dynamic_state(
        &self,
        pool: &str,
        dex: DexType,
        slot: u64,
    ) -> Option<DynamicPoolState> {
        let pubkey = match pool.parse::<Pubkey>() {
            Ok(p) => p,
            Err(e) => {
                warn!(pool, error = %e, "invalid pool pubkey for dynamic state");
                return None;
            }
        };
        match dex {
            DexType::OrcaWhirlpool => {
                let account = self.fetcher.fetch_account(&pubkey, slot).await?;
                let pool_state = orca_whirlpool::parse_pool_state(&account.data)?;
                Some(DynamicPoolState::Whirlpool {
                    sqrt_price_q64: pool_state.sqrt_price_q64,
                    liquidity: pool_state.liquidity,
                    tick_current_index: pool_state.tick_current_index,
                    tick_spacing: pool_state.tick_spacing,
                })
            }
            DexType::MeteoraDlmm => {
                let account = self.fetcher.fetch_account(&pubkey, slot).await?;
                let dlmm_pool = meteora_dlmm::parse_pool_state(&account.data)?;
                Some(DynamicPoolState::Dlmm(dlmm_pool))
            }
            DexType::RaydiumClmm => {
                // Raydium CLMM produces the same V3-style sqrt_price /
                // liquidity / tick state as Whirlpool, so it returns
                // through the `Whirlpool` variant of `DynamicPoolState`.
                // Variant naming is a layout-agnostic carrier — the
                // dispatch in `enrich_attack` treats either DEX as a
                // V3 source for the same `compute_loss_whirlpool_with_trace`
                // replay path.
                let account = self.fetcher.fetch_account(&pubkey, slot).await?;
                let pool_state = raydium_clmm::parse_pool_state(&account.data)?;
                Some(DynamicPoolState::Whirlpool {
                    sqrt_price_q64: pool_state.sqrt_price_q64,
                    liquidity: pool_state.liquidity,
                    tick_current_index: pool_state.tick_current_index,
                    tick_spacing: pool_state.tick_spacing,
                })
            }
            _ => None,
        }
    }

    /// Fetch one or more Whirlpool TickArray accounts via the
    /// configured [`AccountFetcher`]. PDA is derived per-slot from
    /// `(pool, start_tick_index)`; missing accounts (slot
    /// uninitialised on-chain or fetcher dropped them) come back as
    /// `None` at the matching index. A whole-call fetch failure fills
    /// the result with `None`s of the right length so callers can
    /// still match `start_indices` slot-by-slot.
    ///
    /// Not cached — TickArray contents change every swap that crosses
    /// or initialises a tick within the array. A stale snapshot would
    /// silently produce wrong replay results.
    async fn tick_arrays(
        &self,
        pool: &str,
        dex: DexType,
        start_indices: &[i32],
        slot: u64,
    ) -> Vec<Option<ParsedTickArray>> {
        if !matches!(dex, DexType::OrcaWhirlpool) || start_indices.is_empty() {
            return Vec::new();
        }
        let pool_pubkey = match pool.parse::<Pubkey>() {
            Ok(p) => p,
            Err(e) => {
                warn!(pool, error = %e, "invalid pool pubkey for tick arrays");
                return start_indices.iter().map(|_| None).collect();
            }
        };
        let pdas: Vec<Pubkey> = start_indices
            .iter()
            .map(|&start| orca_whirlpool::tick_array::tick_array_pda(&pool_pubkey, start).0)
            .collect();
        let accounts = self.fetcher.fetch_multiple_accounts(&pdas, slot).await;
        // Defensive: a misbehaving custom fetcher could return a
        // wrong-length vec. Re-pad with `None` so the caller's
        // by-index matching stays sound.
        if accounts.len() != pdas.len() {
            warn!(
                pool,
                expected = pdas.len(),
                got = accounts.len(),
                "fetcher returned mismatched account count for tick arrays",
            );
            return start_indices.iter().map(|_| None).collect();
        }
        accounts
            .into_iter()
            .map(|opt| opt.and_then(|a| orca_whirlpool::tick_array::parse_tick_array(&a.data)))
            .collect()
    }

    /// Fetch one or more Meteora DLMM `BinArray` accounts. Mirrors
    /// [`Self::tick_arrays`] in shape: 1:1 alignment with `array_indices`,
    /// `None` at index `i` for missing accounts, defensive re-pad on
    /// fetcher misbehaviour. Indices are `i64` per the on-chain
    /// PDA-seed encoding.
    /// Fetch SPL Token / Token-2022 mint accounts via the configured
    /// fetcher and parse each blob through [`crate::spl_mint::parse_mint`].
    /// Owner gating: only accounts owned by either the legacy SPL
    /// Token program or Token-2022 are accepted; foreign owners come
    /// back as `None` (a malformed fixture or a stray address typo
    /// shouldn't pretend to be a mint).
    ///
    /// `slot` propagates to the fetcher exactly as in
    /// [`Self::tick_arrays`]; archival providers that respect the
    /// slot serve pre-frontrun mint state.
    async fn mint_accounts(&self, mints: &[&str], slot: u64) -> Vec<Option<MintInfo>> {
        if mints.is_empty() {
            return Vec::new();
        }
        let mut pubkeys: Vec<Pubkey> = Vec::with_capacity(mints.len());
        for s in mints {
            match s.parse::<Pubkey>() {
                Ok(p) => pubkeys.push(p),
                Err(e) => {
                    warn!(mint = s, error = %e, "invalid mint pubkey");
                    return mints.iter().map(|_| None).collect();
                }
            }
        }
        let accounts = self.fetcher.fetch_multiple_accounts(&pubkeys, slot).await;
        if accounts.len() != pubkeys.len() {
            warn!(
                expected = pubkeys.len(),
                got = accounts.len(),
                "fetcher returned mismatched account count for mint accounts",
            );
            return mints.iter().map(|_| None).collect();
        }
        let token = spl_mint::spl_token_program_id();
        let token_2022 = spl_mint::spl_token_2022_program_id();
        accounts
            .into_iter()
            .map(|opt| {
                opt.and_then(|a| {
                    if a.owner == token || a.owner == token_2022 {
                        spl_mint::parse_mint(&a.data)
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    async fn bin_arrays(
        &self,
        pool: &str,
        dex: DexType,
        array_indices: &[i64],
        slot: u64,
    ) -> Vec<Option<ParsedBinArray>> {
        if !matches!(dex, DexType::MeteoraDlmm) || array_indices.is_empty() {
            return Vec::new();
        }
        let pool_pubkey = match pool.parse::<Pubkey>() {
            Ok(p) => p,
            Err(e) => {
                warn!(pool, error = %e, "invalid pool pubkey for bin arrays");
                return array_indices.iter().map(|_| None).collect();
            }
        };
        let pdas: Vec<Pubkey> = array_indices
            .iter()
            .map(|&idx| meteora_dlmm::bin_array::bin_array_pda(&pool_pubkey, idx).0)
            .collect();
        let accounts = self.fetcher.fetch_multiple_accounts(&pdas, slot).await;
        if accounts.len() != pdas.len() {
            warn!(
                pool,
                expected = pdas.len(),
                got = accounts.len(),
                "fetcher returned mismatched account count for bin arrays",
            );
            return array_indices.iter().map(|_| None).collect();
        }
        accounts
            .into_iter()
            .map(|opt| opt.and_then(|a| meteora_dlmm::bin_array::parse_bin_array(&a.data)))
            .collect()
    }

    /// Resolve `slot → epoch` via a cached `EpochSchedule`. The schedule
    /// is fetched on first call and reused for the lifetime of this
    /// `RpcPoolLookup`; mainnet `EpochSchedule` is governance-stable, so
    /// stale-after-fetch isn't a concern. A failed fetch is also cached
    /// (as `None`) so we don't retry on every enrichment call.
    async fn epoch_for_slot(&self, slot: u64) -> Option<u64> {
        // `OnceCell::get_or_init` runs the init future exactly once
        // even under concurrent callers — no manual race handling.
        let schedule = self
            .epoch_schedule
            .get_or_init(|| async {
                match self.client.get_epoch_schedule().await {
                    Ok(s) => Some(s),
                    Err(e) => {
                        warn!(error = %e, "get_epoch_schedule failed");
                        None
                    }
                }
            })
            .await;
        schedule.as_ref().map(|s| s.get_epoch(slot))
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
    use std::sync::Mutex as StdMutex;

    #[test]
    fn page_start_floors_to_boundary() {
        assert_eq!(RpcSlotLeaderLookup::page_start(0), 0);
        assert_eq!(RpcSlotLeaderLookup::page_start(999), 0);
        assert_eq!(RpcSlotLeaderLookup::page_start(1000), 1000);
        assert_eq!(RpcSlotLeaderLookup::page_start(1234), 1000);
        assert_eq!(RpcSlotLeaderLookup::page_start(2_000_000), 2_000_000);
    }

    /// Mock [`AccountFetcher`] that records every call (pubkey + slot)
    /// and serves preset blobs. Used to pin slot propagation through
    /// `RpcPoolLookup` without standing up a live RPC.
    struct RecordingFetcher {
        calls: StdMutex<Vec<(Pubkey, u64)>>,
    }

    impl RecordingFetcher {
        fn new() -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(Pubkey, u64)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AccountFetcher for RecordingFetcher {
        async fn fetch_account(&self, pubkey: &Pubkey, slot: u64) -> Option<Account> {
            self.calls.lock().unwrap().push((*pubkey, slot));
            None
        }

        async fn fetch_multiple_accounts(
            &self,
            pubkeys: &[Pubkey],
            slot: u64,
        ) -> Vec<Option<Account>> {
            for pk in pubkeys {
                self.calls.lock().unwrap().push((*pk, slot));
            }
            pubkeys.iter().map(|_| None).collect()
        }
    }

    /// `pool_dynamic_state` must forward the caller-supplied slot to
    /// the configured [`AccountFetcher`]. Pins the contract a custom
    /// archival fetcher relies on — without slot propagation, an
    /// archival impl would always serve latest-confirmed, defeating
    /// the abstraction.
    #[tokio::test]
    async fn pool_dynamic_state_forwards_slot_to_fetcher() {
        let fetcher = Arc::new(RecordingFetcher::new());
        let lookup = RpcPoolLookup::with_account_fetcher(
            // rpc_url is unused for dynamic state — the fetcher owns
            // those calls. Any string parses; only fetcher matters.
            "http://127.0.0.1:1",
            fetcher.clone() as Arc<dyn AccountFetcher>,
        );
        let pool = Pubkey::new_unique();
        let _ = lookup
            .pool_dynamic_state(&pool.to_string(), DexType::OrcaWhirlpool, 12_345)
            .await;
        let calls = fetcher.calls();
        assert_eq!(calls.len(), 1, "expected exactly one fetch_account call");
        assert_eq!(calls[0].0, pool, "pubkey should round-trip");
        assert_eq!(calls[0].1, 12_345, "slot must be propagated");
    }

    /// `tick_arrays` must forward the caller-supplied slot for *every*
    /// PDA in the multi-fetch and align the result vec 1:1 with
    /// `start_indices`. A misbehaving fetcher returning a wrong-length
    /// vec triggers the defensive re-pad branch.
    #[tokio::test]
    async fn tick_arrays_forwards_slot_per_pda() {
        let fetcher = Arc::new(RecordingFetcher::new());
        let lookup = RpcPoolLookup::with_account_fetcher(
            "http://127.0.0.1:1",
            fetcher.clone() as Arc<dyn AccountFetcher>,
        );
        let pool = Pubkey::new_unique();
        let starts = [0i32, 5_632, 11_264];
        let result = lookup
            .tick_arrays(&pool.to_string(), DexType::OrcaWhirlpool, &starts, 99_999)
            .await;
        let calls = fetcher.calls();
        assert_eq!(calls.len(), 3, "one fetch entry per start_index");
        for (_, slot) in &calls {
            assert_eq!(*slot, 99_999, "slot must be propagated to every PDA");
        }
        assert_eq!(
            result.len(),
            starts.len(),
            "result vec must align 1:1 with start_indices",
        );
    }

    /// `mint_accounts` must forward the caller-supplied slot to every
    /// pubkey in the multi-fetch and align the result vec 1:1 with
    /// `mints`. Pins the slot-propagation contract that archival
    /// providers rely on for pre-frontrun mint state.
    #[tokio::test]
    async fn mint_accounts_forwards_slot_per_pubkey() {
        let fetcher = Arc::new(RecordingFetcher::new());
        let lookup = RpcPoolLookup::with_account_fetcher(
            "http://127.0.0.1:1",
            fetcher.clone() as Arc<dyn AccountFetcher>,
        );
        let mint_a = Pubkey::new_unique().to_string();
        let mint_b = Pubkey::new_unique().to_string();
        let result = lookup
            .mint_accounts(&[mint_a.as_str(), mint_b.as_str()], 42_000)
            .await;
        let calls = fetcher.calls();
        assert_eq!(calls.len(), 2, "one entry per mint");
        for (_, slot) in &calls {
            assert_eq!(*slot, 42_000, "slot must be propagated to every mint");
        }
        assert_eq!(result.len(), 2, "result vec aligns 1:1 with input mints");
    }

    /// Empty input ⇒ empty output, no fetcher call. Pin so a future
    /// caller passing zero-length doesn't trigger a useless RPC.
    #[tokio::test]
    async fn mint_accounts_empty_input_short_circuits() {
        let fetcher = Arc::new(RecordingFetcher::new());
        let lookup = RpcPoolLookup::with_account_fetcher(
            "http://127.0.0.1:1",
            fetcher.clone() as Arc<dyn AccountFetcher>,
        );
        let result = lookup.mint_accounts(&[], 0).await;
        assert!(result.is_empty());
        assert!(fetcher.calls().is_empty(), "fetcher must not be called");
    }

    /// Non-Whirlpool DEX short-circuits without invoking the fetcher
    /// at all — pool_dynamic_state returns the trait-default `None`
    /// path (no archival fetch wasted on a config-only AMM).
    #[tokio::test]
    async fn pool_dynamic_state_skips_fetcher_for_non_whirlpool() {
        let fetcher = Arc::new(RecordingFetcher::new());
        let lookup = RpcPoolLookup::with_account_fetcher(
            "http://127.0.0.1:1",
            fetcher.clone() as Arc<dyn AccountFetcher>,
        );
        let pool = Pubkey::new_unique();
        let result = lookup
            .pool_dynamic_state(&pool.to_string(), DexType::RaydiumV4, 12_345)
            .await;
        assert!(
            result.is_none(),
            "non-Whirlpool dex should short-circuit to None",
        );
        assert!(
            fetcher.calls().is_empty(),
            "fetcher should not be called for unsupported dex",
        );
    }
}
