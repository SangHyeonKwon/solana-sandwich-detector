//! End-state model-vs-chain reconciliation (Tier 3.1).
//!
//! After [`compute_loss_with_trace`](crate::compute_loss_with_trace) emits an
//! [`AmmReplayTrace`], `reserves_post_back` records the pool reserves our
//! replay believes the backrun left behind. This module compares those
//! reserves against the *actual* post-backrun vault balances — taken straight
//! from the backrun tx's `post_token_balances` — and quantifies the gap in
//! basis points. A small gap is the strongest single piece of evidence that
//! every step of the replay (frontrun, victim, backrun) lined up with chain
//! reality, which is what `victim_loss` and `attacker_profit_real` rely on.
//!
//! ## Whirlpool extension (archival)
//!
//! ConstantProduct's diff stays inside a single transaction's meta because
//! vault reserves are observable in `post_token_balances`. Whirlpool's
//! dynamic state (sqrt_price, liquidity, tick) **isn't** in tx meta — V3
//! AMMs encode it on the pool account. To diff a Whirlpool replay against
//! chain truth, we have to fetch the pool account *at the slot after the
//! sandwich*. That fetch is provider-specific (archival RPC), so the
//! comparison is split into a pure function
//! ([`compare_whirlpool_replay_to_archival`]) and an async wrapper
//! ([`diff_attack_against_archival`]) that takes an
//! [`AccountFetcher`](crate::AccountFetcher).

/// Maximum side-wise relative gap between predicted and observed reserves
/// before [`Signal::ReservesMatchPostState`](swap_events::types::Signal)
/// flips from Informational to Fail. Calibrated to tolerate routing /
/// multi-hop CPIs that touch the vault outside the recognised swap, while
/// still flagging meaningful model bugs. 100 bps matches the threshold the
/// per-step `InvariantResidual` uses, keeping the two replay-fidelity signals
/// on the same scale.
pub const PASS_THRESHOLD_BPS: u32 = 100;

/// Larger of the two side-wise relative divergences between predicted and
/// observed `(base, quote)` reserves, in basis points. Reports the max
/// rather than the mean so a model bug on one side can't hide behind an
/// accurate other side.
///
/// `observed == 0` on a side is treated specially: if we also predicted
/// zero the side is a perfect match, otherwise the result saturates to
/// `u32::MAX` so the consumer can't accidentally read a huge gap as small.
pub fn reserves_divergence_bps(predicted: (u64, u64), observed: (u64, u64)) -> u32 {
    let base = side_divergence_bps(predicted.0, observed.0);
    let quote = side_divergence_bps(predicted.1, observed.1);
    base.max(quote)
}

fn side_divergence_bps(predicted: u64, observed: u64) -> u32 {
    if observed == 0 {
        return if predicted == 0 { 0 } else { u32::MAX };
    }
    let delta = (predicted as i128 - observed as i128).unsigned_abs();
    let scaled = delta.saturating_mul(10_000) / observed as u128;
    scaled.min(u32::MAX as u128) as u32
}

/// Per-component divergence between a Whirlpool replay's post-back
/// checkpoint and the chain-observed post-state. Returned by
/// [`compare_whirlpool_replay_to_archival`] / [`diff_attack_against_archival`].
///
/// `*_diff_bps` fields use the same relative-bps convention as
/// [`reserves_divergence_bps`]. `tick_diff` is a signed absolute gap
/// (predicted - observed) — ticks are integers and small absolute
/// differences carry direct meaning ("we're 1 tick high"), so a relative
/// metric would be misleading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WhirlpoolDiffReport {
    pub sqrt_price_diff_bps: u32,
    pub liquidity_diff_bps: u32,
    pub tick_diff: i32,
}

/// Compare a Whirlpool replay's post-back checkpoint against an observed
/// chain state. Pure function — caller is responsible for sourcing the
/// observation (typically via [`diff_attack_against_archival`] which
/// pulls it from an [`AccountFetcher`](crate::AccountFetcher)).
///
/// Returns `None` when `observed` isn't the Whirlpool variant — the
/// concentrated-liquidity comparison surface only makes sense for
/// concentrated-liquidity AMMs.
pub fn compare_whirlpool_replay_to_archival(
    predicted: &swap_events::types::WhirlpoolReplayTrace,
    observed: &crate::lookup::DynamicPoolState,
) -> Option<WhirlpoolDiffReport> {
    let crate::lookup::DynamicPoolState::Whirlpool {
        sqrt_price_q64,
        liquidity,
        tick_current_index,
        ..
    } = observed
    else {
        return None;
    };
    Some(WhirlpoolDiffReport {
        sqrt_price_diff_bps: u128_divergence_bps(predicted.sqrt_price_post_back, *sqrt_price_q64),
        liquidity_diff_bps: u128_divergence_bps(predicted.liquidity_post_back, *liquidity),
        tick_diff: predicted.tick_current_post_back - tick_current_index,
    })
}

/// Run the Whirlpool replay-vs-archival diff for a single sandwich
/// attack. Fetches the pool account at `attack.slot + slot_offset` via
/// the supplied fetcher and feeds the result into
/// [`compare_whirlpool_replay_to_archival`].
///
/// `slot_offset` is typically `1` — the state at the start of the slot
/// *after* the sandwich is what we want to compare against the
/// post-backrun trace. Providers that serve "state at exactly slot N
/// (= after slot N-1's apply)" need offset `1`; providers that serve
/// "state after slot N" need offset `0`. Caller picks per provider.
///
/// Returns `None` when:
///   * `attack.dex` isn't [`DexType::OrcaWhirlpool`](swap_events::types::DexType::OrcaWhirlpool),
///   * the attack carries no [`WhirlpoolReplayTrace`] (enrichment
///     didn't run or it bailed),
///   * the archival fetch fails or the account doesn't parse as a
///     Whirlpool pool account.
pub async fn diff_attack_against_archival(
    attack: &swap_events::types::SandwichAttack,
    fetcher: &dyn crate::AccountFetcher,
    slot_offset: u64,
) -> Option<WhirlpoolDiffReport> {
    if attack.dex != swap_events::types::DexType::OrcaWhirlpool {
        return None;
    }
    let predicted = attack.whirlpool_replay.as_ref()?;
    let pubkey = attack.pool.parse::<solana_sdk::pubkey::Pubkey>().ok()?;
    let account = fetcher
        .fetch_account(&pubkey, attack.slot.saturating_add(slot_offset))
        .await?;
    let pool_state = crate::orca_whirlpool::parse_pool_state(&account.data)?;
    let observed = crate::lookup::DynamicPoolState::Whirlpool {
        sqrt_price_q64: pool_state.sqrt_price_q64,
        liquidity: pool_state.liquidity,
        tick_current_index: pool_state.tick_current_index,
        tick_spacing: pool_state.tick_spacing,
    };
    compare_whirlpool_replay_to_archival(predicted, &observed)
}

/// u128 analogue of [`side_divergence_bps`]. Whirlpool sqrt_price
/// (Q64.64, sits around 2^64) and liquidity (deep pools reach 2^70+)
/// don't fit in u64, so the bps-relative diff math runs in u128 here
/// and saturates to u32 on the way out.
fn u128_divergence_bps(predicted: u128, observed: u128) -> u32 {
    if observed == 0 {
        return if predicted == 0 { 0 } else { u32::MAX };
    }
    let delta = predicted.abs_diff(observed);
    // delta * 10_000 fits in u128 for any sqrt_price / liquidity
    // value Whirlpool actually uses; the saturating_mul guards
    // against pathological inputs (e.g. corrupt archival blobs)
    // rather than typical state.
    let scaled = delta.saturating_mul(10_000);
    let bps = scaled / observed;
    bps.min(u32::MAX as u128) as u32
}

// ----- Balance cross-check (parser-vs-RPC sanity) -----

/// Divergence between a sandwich attack's recorded victim `amount_out`
/// (extracted by the swap-events parser at detection time) and the
/// on-chain ground truth observed by re-walking the victim transaction's
/// `pre_token_balances` / `post_token_balances` via a fresh
/// `getTransaction` RPC.
///
/// Unlike [`WhirlpoolDiffReport`] which validates *replay math* against
/// archival pool state, this report validates the *parser* end-to-end:
/// it doesn't re-run any AMM math, just confirms the parser's victim
/// `amount_out` matches what the chain says the victim wallet actually
/// received. A non-zero diff points to a parser-stable failure mode
/// (account-key drift between block snapshot and tx fetch, lookup-table
/// updates, RPC-side serialisation differences) rather than a replay
/// bug. Standard `getTransaction` is fully archival on every major
/// Solana RPC provider, so this surface works on historical sandwich
/// corpora without an account-state archival service.
///
/// **Known blind spot — Token-2022 transfer-fee mints.** Both sides
/// of the diff read the *net-of-fee* received amount (the parser
/// computes it from `post_token_balance - pre_token_balance`; the
/// observation re-runs the same heuristic), so on transfer-fee mints
/// the diff is structurally zero and does *not* validate whether the
/// parser correctly accounted for the gross/net distinction. Use the
/// enrichment-side Token-2022 paths for that audit instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BalanceDiffReport {
    /// `amount_out` recorded by the swap-events parser — the same value
    /// carried in `attack.victim.amount_out`.
    pub recorded_amount_out: u64,
    /// `amount_out` observed by re-walking the victim tx's token-balance
    /// deltas at validation time. Authoritative chain truth.
    pub observed_amount_out: u64,
    /// Relative gap between recorded and observed, in bps of
    /// `observed_amount_out`. Same convention as
    /// [`reserves_divergence_bps`]: an exact match is `0`; `observed == 0`
    /// with non-zero `recorded` saturates to `u32::MAX`.
    pub diff_bps: u32,
}

impl BalanceDiffReport {
    /// Construct a report from an observed (chain truth) and recorded
    /// (parser output) `amount_out` pair. The bps math reuses
    /// [`side_divergence_bps`] so the scale matches the reserves-side
    /// reconciliation surface.
    pub fn new(observed_amount_out: u64, recorded_amount_out: u64) -> Self {
        Self {
            observed_amount_out,
            recorded_amount_out,
            diff_bps: side_divergence_bps(recorded_amount_out, observed_amount_out),
        }
    }
}

/// Why the balance cross-check bailed. Three orthogonal failure modes
/// the operator wants to distinguish at a glance: a malformed signature
/// in the input record (data-shape bug), an RPC fetch error (transient
/// or provider archival-horizon issue — retryable on a different
/// endpoint), or a successful fetch whose tx the observation heuristic
/// can't classify (multi-leg route, signer mismatch, non-Json encoding —
/// real diagnostic, not retryable).
///
/// `RpcFetch` carries the upstream error string so the operator can
/// triage rate limits / 404s / network errors without re-running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCheckError {
    /// `attack.victim.signature` didn't parse as a
    /// [`solana_sdk::signature::Signature`]. Indicates a malformed
    /// JSONL input or upstream parser bug, not an on-chain condition.
    BadSignature,
    /// The `getTransaction` RPC call returned an error. The string is
    /// the upstream `solana_client` error, suitable for diagnostic
    /// logging. Common causes: rate limit, missing tx beyond the
    /// provider's archival horizon, transient network failure.
    RpcFetch(String),
    /// The fetch succeeded but the observation heuristic
    /// ([`swap_events::observe::observe_swap_from_tx`]) couldn't
    /// classify the swap — e.g. multi-leg Jupiter route, victim
    /// signer mismatch, non-Json encoding, or no signer-side balance
    /// change. Real diagnostic, not retryable.
    Unobservable,
}

/// Compare a sandwich attack's recorded `victim.amount_out` against an
/// already-fetched victim transaction. Pure function — caller is
/// responsible for sourcing the transaction (typically via
/// [`cross_check_victim_balance`] which pulls it from an
/// [`solana_client::nonblocking::rpc_client::RpcClient`]).
///
/// Returns [`CrossCheckError::Unobservable`] when
/// [`swap_events::observe::observe_swap_from_tx`] can't classify the
/// deltas — for example when the transaction is not JSON-encoded, the
/// tx's first signer doesn't match `attack.victim.signer`, or the
/// balance deltas don't match the detector's swap heuristic (multi-leg
/// route, no signer-side change, etc.). Sig-parse and RPC-fetch
/// failures don't apply at this layer — they're surfaced by the async
/// wrapper.
pub fn diff_against_observed_tx(
    attack: &swap_events::types::SandwichAttack,
    tx: &solana_transaction_status::EncodedTransactionWithStatusMeta,
) -> Result<BalanceDiffReport, CrossCheckError> {
    let observed = swap_events::observe::observe_swap_from_tx(tx, &attack.victim.signer)
        .ok_or(CrossCheckError::Unobservable)?;
    Ok(BalanceDiffReport::new(
        observed.amount_out,
        attack.victim.amount_out,
    ))
}

/// Run the parser-vs-RPC balance cross-check for a single sandwich
/// attack. Fetches the victim transaction via standard `getTransaction`
/// (fully archival on every major Solana RPC provider — no slot-aware
/// fetcher needed) and feeds it into [`diff_against_observed_tx`].
///
/// Defaults: `Json` encoding, `Finalized` commitment, v0 transaction
/// version support. `Finalized` (not `Confirmed`) so the cross-check
/// can't accidentally read a forked tx — at archival ages the
/// distinction is moot for non-forked txs but rules out noise on the
/// rare edge case.
///
/// Returns:
///   * [`CrossCheckError::BadSignature`] when `attack.victim.signature`
///     doesn't parse as a [`solana_sdk::signature::Signature`],
///   * [`CrossCheckError::RpcFetch`] (with upstream error string) when
///     the `getTransaction` call fails,
///   * [`CrossCheckError::Unobservable`] when the observation heuristic
///     can't classify the resulting tx (see [`diff_against_observed_tx`]).
pub async fn cross_check_victim_balance(
    attack: &swap_events::types::SandwichAttack,
    client: &solana_client::nonblocking::rpc_client::RpcClient,
) -> Result<BalanceDiffReport, CrossCheckError> {
    use std::str::FromStr;
    let sig = solana_sdk::signature::Signature::from_str(&attack.victim.signature)
        .map_err(|_| CrossCheckError::BadSignature)?;
    let config = solana_client::rpc_config::RpcTransactionConfig {
        encoding: Some(solana_transaction_status::UiTransactionEncoding::Json),
        commitment: Some(solana_sdk::commitment_config::CommitmentConfig::finalized()),
        max_supported_transaction_version: Some(0),
    };
    let result = client
        .get_transaction_with_config(&sig, config)
        .await
        .map_err(|e| CrossCheckError::RpcFetch(e.to_string()))?;
    diff_against_observed_tx(attack, &result.transaction)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_when_predicted_matches_observed() {
        assert_eq!(reserves_divergence_bps((1_000, 2_000), (1_000, 2_000)), 0);
        assert_eq!(reserves_divergence_bps((0, 0), (0, 0)), 0);
    }

    #[test]
    fn five_percent_off_returns_500_bps() {
        // Predicted 5% higher than observed on the base side; quote matches.
        assert_eq!(reserves_divergence_bps((1_050, 2_000), (1_000, 2_000)), 500);
        // Predicted 5% lower — same magnitude.
        assert_eq!(reserves_divergence_bps((950, 2_000), (1_000, 2_000)), 500);
    }

    #[test]
    fn returns_max_of_the_two_sides() {
        // Base off by 100 bps, quote off by 250 bps. Max wins.
        let pred = (1_010, 2_050);
        let obs = (1_000, 2_000);
        assert_eq!(reserves_divergence_bps(pred, obs), 250);
    }

    #[test]
    fn saturates_when_observed_zero_and_predicted_nonzero() {
        assert_eq!(reserves_divergence_bps((1, 0), (0, 0)), u32::MAX);
        assert_eq!(reserves_divergence_bps((0, 1), (0, 0)), u32::MAX);
    }

    #[test]
    fn no_overflow_on_max_reserves() {
        // u64::MAX vs (u64::MAX - 1) — single-unit gap on a colossal pool
        // should round to 0 bps without overflowing the i128 / u128 path.
        let huge = u64::MAX;
        assert_eq!(reserves_divergence_bps((huge, huge), (huge - 1, huge)), 0);
    }

    #[test]
    fn pass_threshold_is_within_signed_i32_range() {
        // Sanity: the const fits comfortably in i32 too, in case a downstream
        // consumer does signed math on the bps value.
        assert!(PASS_THRESHOLD_BPS < i32::MAX as u32);
    }

    // ----- Whirlpool archival diff (Tier 3.1 archival extension) ----

    use crate::lookup::DynamicPoolState;
    use swap_events::types::WhirlpoolReplayTrace;

    fn make_trace(sp: u128, liq: u128, tick: i32) -> WhirlpoolReplayTrace {
        WhirlpoolReplayTrace {
            sqrt_price_pre: sp,
            sqrt_price_post_front: sp,
            sqrt_price_post_victim: sp,
            sqrt_price_post_back: sp,
            liquidity_pre: liq,
            liquidity_post_front: liq,
            liquidity_post_victim: liq,
            liquidity_post_back: liq,
            tick_current_pre: tick,
            tick_current_post_front: tick,
            tick_current_post_victim: tick,
            tick_current_post_back: tick,
            counterfactual_victim_out: 0,
            actual_victim_out: 0,
            fee_num: 3_000,
            fee_den: 1_000_000,
        }
    }

    fn make_observed(sp: u128, liq: u128, tick: i32) -> DynamicPoolState {
        DynamicPoolState::Whirlpool {
            sqrt_price_q64: sp,
            liquidity: liq,
            tick_current_index: tick,
            tick_spacing: 64,
        }
    }

    #[test]
    fn whirlpool_diff_zero_on_exact_match() {
        let sp = 1u128 << 64;
        let predicted = make_trace(sp, 1_000_000_000, 10);
        let observed = make_observed(sp, 1_000_000_000, 10);
        let diff =
            compare_whirlpool_replay_to_archival(&predicted, &observed).expect("diff computed");
        assert_eq!(diff.sqrt_price_diff_bps, 0);
        assert_eq!(diff.liquidity_diff_bps, 0);
        assert_eq!(diff.tick_diff, 0);
    }

    #[test]
    fn whirlpool_diff_relative_bps_on_sqrt_price() {
        // Clean numbers to avoid integer-floor noise in the bps math.
        // observed = 1_000_000, predicted = 1_050_000 ⇒ delta = 50_000
        // ⇒ 50_000 * 10_000 / 1_000_000 = 500 bps exactly.
        let predicted = make_trace(1_050_000, 1_000_000, 0);
        let observed = make_observed(1_000_000, 1_000_000, 0);
        let diff = compare_whirlpool_replay_to_archival(&predicted, &observed).unwrap();
        assert_eq!(
            diff.sqrt_price_diff_bps, 500,
            "predicted 5% above observed should be exactly 500 bps",
        );
        assert_eq!(diff.liquidity_diff_bps, 0);
        assert_eq!(diff.tick_diff, 0);
    }

    #[test]
    fn whirlpool_diff_signed_tick_gap() {
        let sp = 1u128 << 64;
        // predicted tick = 100, observed = 95 ⇒ tick_diff = +5 (we're high).
        let predicted = make_trace(sp, 1_000_000, 100);
        let observed = make_observed(sp, 1_000_000, 95);
        let diff = compare_whirlpool_replay_to_archival(&predicted, &observed).unwrap();
        assert_eq!(diff.tick_diff, 5);
        // Reversed: predicted low.
        let predicted = make_trace(sp, 1_000_000, 90);
        let diff = compare_whirlpool_replay_to_archival(&predicted, &observed).unwrap();
        assert_eq!(diff.tick_diff, -5);
    }

    #[test]
    fn whirlpool_diff_observed_zero_saturates() {
        // observed liquidity = 0, predicted nonzero ⇒ saturates to MAX.
        // (A pool with 0 chain liquidity but a non-zero replay trace is
        // a strong signal that the replay model diverged catastrophically.)
        let sp = 1u128 << 64;
        let predicted = make_trace(sp, 1, 0);
        let observed = make_observed(sp, 0, 0);
        let diff = compare_whirlpool_replay_to_archival(&predicted, &observed).unwrap();
        assert_eq!(diff.liquidity_diff_bps, u32::MAX);
    }

    /// Fetcher that records the slot it was called with and returns
    /// `None` for the account body. Lets us pin slot propagation
    /// without standing up a Whirlpool blob fixture.
    struct OffsetRecordingFetcher {
        captured_slot: std::sync::Mutex<Option<u64>>,
    }

    #[async_trait::async_trait]
    impl crate::AccountFetcher for OffsetRecordingFetcher {
        async fn fetch_account(
            &self,
            _pubkey: &solana_sdk::pubkey::Pubkey,
            slot: u64,
        ) -> Option<solana_sdk::account::Account> {
            *self.captured_slot.lock().unwrap() = Some(slot);
            None
        }
        async fn fetch_multiple_accounts(
            &self,
            pubkeys: &[solana_sdk::pubkey::Pubkey],
            _slot: u64,
        ) -> Vec<Option<solana_sdk::account::Account>> {
            pubkeys.iter().map(|_| None).collect()
        }
    }

    fn whirlpool_attack_at_slot(slot: u64) -> swap_events::types::SandwichAttack {
        use swap_events::types::{
            DexType, SandwichAttack, SwapDirection, SwapEvent, WhirlpoolReplayTrace,
        };
        let pool_pubkey = solana_sdk::pubkey::Pubkey::new_unique().to_string();
        fn ev(sig: &str, signer: &str, dir: SwapDirection, pool: &str) -> SwapEvent {
            SwapEvent {
                signature: sig.into(),
                signer: signer.into(),
                dex: DexType::OrcaWhirlpool,
                pool: pool.into(),
                direction: dir,
                token_mint: "M".into(),
                amount_in: 0,
                amount_out: 0,
                tx_index: 0,
                slot: Some(0),
                fee: None,
            }
        }
        SandwichAttack {
            slot,
            attacker: "atk".into(),
            pool: pool_pubkey.clone(),
            dex: DexType::OrcaWhirlpool,
            frontrun: ev("f", "atk", SwapDirection::Buy, &pool_pubkey),
            victim: ev("v", "vic", SwapDirection::Buy, &pool_pubkey),
            backrun: ev("b", "atk", SwapDirection::Sell, &pool_pubkey),
            estimated_attacker_profit: None,
            victim_loss_lamports: None,
            victim_loss_lamports_lower: None,
            victim_loss_lamports_upper: None,
            frontrun_slot: None,
            backrun_slot: None,
            detection_method: None,
            bundle_provenance: None,
            confidence: None,
            net_profit: None,
            attacker_profit: None,
            price_impact_bps: None,
            evidence: None,
            amm_replay: None,
            whirlpool_replay: Some(WhirlpoolReplayTrace {
                sqrt_price_pre: 1u128 << 64,
                sqrt_price_post_front: 1u128 << 64,
                sqrt_price_post_victim: 1u128 << 64,
                sqrt_price_post_back: 1u128 << 64,
                liquidity_pre: 1_000_000,
                liquidity_post_front: 1_000_000,
                liquidity_post_victim: 1_000_000,
                liquidity_post_back: 1_000_000,
                tick_current_pre: 0,
                tick_current_post_front: 0,
                tick_current_post_victim: 0,
                tick_current_post_back: 0,
                counterfactual_victim_out: 0,
                actual_victim_out: 0,
                fee_num: 3_000,
                fee_den: 1_000_000,
            }),
            dlmm_replay: None,
            attack_signature: None,
            timestamp_ms: None,
            attack_type: None,
            severity: None,
            confidence_level: None,
            slot_leader: None,
            is_wide_sandwich: false,
            receipts: vec![],
            victim_signer: None,
            victim_amount_in: None,
            victim_amount_out: None,
            victim_amount_out_expected: None,
        }
    }

    #[tokio::test]
    async fn diff_attack_against_archival_propagates_slot_offset() {
        let fetcher = OffsetRecordingFetcher {
            captured_slot: std::sync::Mutex::new(None),
        };
        let attack = whirlpool_attack_at_slot(1_234_567);
        // Fetcher returns None for the body, so the diff itself is None
        // — but we only care that the slot reaches the fetcher.
        let _ = diff_attack_against_archival(&attack, &fetcher, 1).await;
        let slot = fetcher.captured_slot.lock().unwrap().unwrap();
        assert_eq!(
            slot, 1_234_568,
            "attack.slot + slot_offset should reach the fetcher",
        );
    }

    #[tokio::test]
    async fn diff_attack_against_archival_skips_non_whirlpool() {
        let fetcher = OffsetRecordingFetcher {
            captured_slot: std::sync::Mutex::new(None),
        };
        let mut attack = whirlpool_attack_at_slot(100);
        attack.dex = swap_events::types::DexType::RaydiumV4;
        let result = diff_attack_against_archival(&attack, &fetcher, 1).await;
        assert!(result.is_none(), "non-Whirlpool dex should short-circuit");
        assert!(
            fetcher.captured_slot.lock().unwrap().is_none(),
            "fetcher should not be called when dex doesn't match",
        );
    }

    #[tokio::test]
    async fn diff_attack_against_archival_skips_when_no_trace() {
        let fetcher = OffsetRecordingFetcher {
            captured_slot: std::sync::Mutex::new(None),
        };
        let mut attack = whirlpool_attack_at_slot(100);
        attack.whirlpool_replay = None;
        let result = diff_attack_against_archival(&attack, &fetcher, 1).await;
        assert!(
            result.is_none(),
            "missing whirlpool_replay should short-circuit",
        );
        assert!(
            fetcher.captured_slot.lock().unwrap().is_none(),
            "fetcher should not be called when there's no trace to compare",
        );
    }

    #[test]
    fn u128_divergence_handles_huge_values() {
        // sqrt_price near u128::MAX shouldn't trigger overflow paths
        // catastrophically — saturation is fine, but the function
        // must not panic.
        let huge = u128::MAX / 20_000;
        let bps = u128_divergence_bps(huge, huge);
        assert_eq!(bps, 0);
        // Predicted vs zero observed → saturated (already covered above
        // for the public function, this is the helper's contract).
        assert_eq!(u128_divergence_bps(1, 0), u32::MAX);
        assert_eq!(u128_divergence_bps(0, 0), 0);
    }

    // ----- Balance cross-check -----

    #[test]
    fn balance_diff_zero_on_exact_match() {
        let report = BalanceDiffReport::new(1_000_000, 1_000_000);
        assert_eq!(report.observed_amount_out, 1_000_000);
        assert_eq!(report.recorded_amount_out, 1_000_000);
        assert_eq!(report.diff_bps, 0);
    }

    #[test]
    fn balance_diff_five_percent_off_returns_500_bps() {
        // Parser recorded 5% high vs chain truth.
        let high = BalanceDiffReport::new(1_000_000, 1_050_000);
        assert_eq!(high.diff_bps, 500);
        // Parser recorded 5% low — same magnitude (abs_diff is symmetric).
        let low = BalanceDiffReport::new(1_000_000, 950_000);
        assert_eq!(low.diff_bps, 500);
    }

    #[test]
    fn balance_diff_saturates_when_observed_zero_and_recorded_nonzero() {
        // Chain says victim received nothing but parser recorded a swap —
        // the relative gap is ill-defined, surface it as the maximum so a
        // consumer can't accidentally read the absence as a small diff.
        assert_eq!(BalanceDiffReport::new(0, 1).diff_bps, u32::MAX);
    }

    #[test]
    fn balance_diff_zero_when_both_zero() {
        // Degenerate but legal — neither parser nor chain saw output.
        assert_eq!(BalanceDiffReport::new(0, 0).diff_bps, 0);
    }

    #[test]
    fn balance_diff_no_overflow_on_max_amounts() {
        // Single-unit gap on a u64::MAX position rounds to 0 bps without
        // panicking. amount_out is a token-smallest-unit u64 so this is
        // pathological but the math should still be safe.
        let huge = u64::MAX;
        assert_eq!(BalanceDiffReport::new(huge, huge - 1).diff_bps, 0);
    }

    // ----- diff_against_observed_tx (pure-function half of the cross-check) -----

    /// Build a SandwichAttack with the supplied victim signer + amount_out.
    /// All the structural fields the function doesn't touch are filled
    /// with placeholders that satisfy the type but say nothing.
    fn attack_with_victim(
        victim_signer: &str,
        victim_amount_out: u64,
    ) -> swap_events::types::SandwichAttack {
        use swap_events::types::{DexType, SandwichAttack, SwapDirection, SwapEvent};
        fn ev(signer: &str, amount_out: u64) -> SwapEvent {
            SwapEvent {
                signature: "v".into(),
                signer: signer.into(),
                dex: DexType::OrcaWhirlpool,
                pool: "p".into(),
                direction: SwapDirection::Buy,
                token_mint: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
                amount_in: 1_000,
                amount_out,
                tx_index: 0,
                slot: Some(0),
                fee: None,
            }
        }
        SandwichAttack {
            slot: 0,
            attacker: "atk".into(),
            pool: "p".into(),
            dex: DexType::OrcaWhirlpool,
            frontrun: ev("atk", 0),
            victim: ev(victim_signer, victim_amount_out),
            backrun: ev("atk", 0),
            estimated_attacker_profit: None,
            victim_loss_lamports: None,
            victim_loss_lamports_lower: None,
            victim_loss_lamports_upper: None,
            frontrun_slot: None,
            backrun_slot: None,
            detection_method: None,
            bundle_provenance: None,
            confidence: None,
            net_profit: None,
            attacker_profit: None,
            price_impact_bps: None,
            evidence: None,
            amm_replay: None,
            whirlpool_replay: None,
            dlmm_replay: None,
            attack_signature: None,
            timestamp_ms: None,
            attack_type: None,
            severity: None,
            confidence_level: None,
            slot_leader: None,
            is_wide_sandwich: false,
            receipts: vec![],
            victim_signer: None,
            victim_amount_in: None,
            victim_amount_out: None,
            victim_amount_out_expected: None,
        }
    }

    /// Build a `getTransaction`-shaped payload with the user as fee
    /// payer, swapping `usdc_out` USDC out for `token_in` of a non-quote
    /// mint (i.e. a Buy of TOKEN). The first signature + accountKeys[0]
    /// are "user" so the cross-check's signer match succeeds.
    fn buy_tx_payload(
        usdc_in: u64,
        token_out: u64,
    ) -> solana_transaction_status::EncodedTransactionWithStatusMeta {
        let usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let token = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        serde_json::from_value(serde_json::json!({
            "transaction": {
                "signatures": ["v"],
                "message": {
                    "header": { "numRequiredSignatures": 1, "numReadonlySignedAccounts": 0, "numReadonlyUnsignedAccounts": 0 },
                    "accountKeys": ["user", "user_usdc_acc", "user_token_acc"],
                    "recentBlockhash": "11111111111111111111111111111111",
                    "instructions": [],
                },
            },
            "meta": {
                "err": null,
                "status": { "Ok": null },
                "fee": 5_000,
                "preBalances": [10_000_000u64, 0u64, 0u64],
                "postBalances": [10_000_000u64, 0u64, 0u64],
                "preTokenBalances": [
                    { "accountIndex": 1, "mint": usdc,  "owner": "user", "uiTokenAmount": { "amount": usdc_in.to_string(),  "decimals": 6, "uiAmount": null, "uiAmountString": usdc_in.to_string() } },
                    { "accountIndex": 2, "mint": token, "owner": "user", "uiTokenAmount": { "amount": "0",                  "decimals": 6, "uiAmount": null, "uiAmountString": "0" } },
                ],
                "postTokenBalances": [
                    { "accountIndex": 1, "mint": usdc,  "owner": "user", "uiTokenAmount": { "amount": "0",                   "decimals": 6, "uiAmount": null, "uiAmountString": "0" } },
                    { "accountIndex": 2, "mint": token, "owner": "user", "uiTokenAmount": { "amount": token_out.to_string(), "decimals": 6, "uiAmount": null, "uiAmountString": token_out.to_string() } },
                ],
            },
            "version": null,
        }))
        .expect("payload deserialises")
    }

    #[test]
    fn diff_against_observed_tx_zero_when_amounts_match() {
        let attack = attack_with_victim("user", 500);
        let tx = buy_tx_payload(1_000, 500);
        let report = diff_against_observed_tx(&attack, &tx).expect("observation succeeds");
        assert_eq!(report.observed_amount_out, 500);
        assert_eq!(report.recorded_amount_out, 500);
        assert_eq!(report.diff_bps, 0);
    }

    #[test]
    fn diff_against_observed_tx_surfaces_mismatch_in_bps() {
        // Parser recorded 525, chain says 500 → 5% high.
        let attack = attack_with_victim("user", 525);
        let tx = buy_tx_payload(1_000, 500);
        let report = diff_against_observed_tx(&attack, &tx).expect("observation succeeds");
        assert_eq!(report.observed_amount_out, 500);
        assert_eq!(report.recorded_amount_out, 525);
        assert_eq!(report.diff_bps, 500);
    }

    #[test]
    fn diff_against_observed_tx_returns_unobservable_on_signer_mismatch() {
        // Tx is signed by "user" but we're checking against an attack
        // attributing the victim to "alien" — observation should bail
        // and the cross-check is reported as `Unobservable` rather than
        // silently producing a misleading diff. `BadSignature` /
        // `RpcFetch` only fire in the async wrapper.
        let attack = attack_with_victim("alien", 500);
        let tx = buy_tx_payload(1_000, 500);
        assert_eq!(
            diff_against_observed_tx(&attack, &tx),
            Err(CrossCheckError::Unobservable),
        );
    }
}
