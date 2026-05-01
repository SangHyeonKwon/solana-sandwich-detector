//! Post-processor that attaches AMM-correct victim loss and attacker profit to
//! a detected [`SandwichAttack`].
//!
//! Kept separate from the detector because detectors work on streams of
//! [`SwapEvent`] and don't retain the full [`TransactionData`] — pool-state
//! enrichment needs the tx meta to read vault reserves. So the flow is:
//!
//!   1. Detector produces a [`SandwichAttack`] from [`SwapEvent`]s.
//!   2. Caller (CLI, eval harness) keeps a slot → [`TransactionData`] cache.
//!   3. Caller invokes [`enrich_attack`] with the attack, the frontrun's tx
//!      data, an optional backrun tx (used for the Tier 3.1 post-state
//!      diff check), and a [`PoolStateLookup`]. Fields are filled in place.

use swap_events::types::{
    DetectionEvidence, ReplayStep, SandwichAttack, Severity, Signal, TransactionData,
};

use crate::lookup::{AmmKind, DynamicPoolState};
use crate::meteora_dlmm::bin_array::{bin_id_to_bin_array_index, ParsedBinArray};
use crate::meteora_dlmm::DlmmPool;
use crate::orca_whirlpool::tick_array::{
    start_tick_index_for, ticks_per_array_span, ParsedTickArray,
};
use crate::{
    compute_loss_dlmm, compute_loss_whirlpool_with_trace, compute_loss_with_trace, diff_test,
    reserves, ConstantProduct, PoolStateLookup,
};

/// Outcome of an enrichment attempt. Signals *why* it failed so callers can
/// distinguish transient issues (unsupported DEX) from real problems
/// (pool config resolved but reserves missing — likely a parser bug).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrichmentResult {
    /// Fields filled in.
    Enriched,
    /// DEX not supported by pool-state (e.g. Jupiter, CLMM).
    UnsupportedDex,
    /// Pool config couldn't be fetched (bad pubkey, RPC error, unknown layout).
    ConfigUnavailable,
    /// Pool config resolved but the frontrun tx didn't contain vault balances —
    /// shouldn't happen for a real sandwich in the attacked pool.
    ReservesMissing,
    /// Replay returned `None` (direction mismatch or zero reserves).
    ReplayFailed,
    /// Whirlpool replay exhausted both the within-tick fast path and
    /// the cross-tick fallback without resolving the sandwich — the
    /// caller's lookup didn't return enough TickArrays, the swap
    /// walked off the fetched range, or liquidity drained mid-walk.
    /// Caller treats this like [`EnrichmentResult::UnsupportedDex`]
    /// (replay-derived fields aren't populated) but the variant is
    /// distinct so cross-tick rate can be tracked separately.
    CrossTickUnsupported,
}

/// Attempt to fill `victim_loss_lamports`, `attacker_profit`, and
/// `price_impact_bps` on `attack` using AMM replay. When `backrun_tx` is
/// supplied, also emit the Tier 3.1 [`Signal::ReservesMatchPostState`]
/// signal by comparing the replay's `reserves_post_back` against the
/// backrun tx's actual post-vault balances.
pub async fn enrich_attack(
    attack: &mut SandwichAttack,
    frontrun_tx: &TransactionData,
    backrun_tx: Option<&TransactionData>,
    lookup: &dyn PoolStateLookup,
) -> EnrichmentResult {
    // Short-circuit DEXes we don't yet replay.
    if crate::lookup::AmmKind::from_dex(attack.dex).is_none() {
        return EnrichmentResult::UnsupportedDex;
    }

    let Some(config) = lookup.pool_config(&attack.pool, attack.dex).await else {
        return EnrichmentResult::ConfigUnavailable;
    };

    // Dispatch by AMM kind. Each path produces (loss,
    // amm_replay_trace_opt, whirlpool_replay_trace_opt,
    // pool_quote_tvl). The two trace options are mutually exclusive —
    // ConstantProduct fills `amm_replay_trace_opt`, Whirlpool fills
    // `whirlpool_replay_trace_opt`. Common attack-field / signal
    // wiring runs after the match.
    let (loss, trace_opt, whirlpool_trace_opt, pool_quote_tvl) = match config.kind {
        AmmKind::RaydiumV4 | AmmKind::RaydiumCpmm => {
            let Some(tx_reserves) = reserves::extract(frontrun_tx, &config) else {
                let accounts: Vec<&str> = frontrun_tx
                    .token_balance_changes
                    .iter()
                    .map(|b| b.account.as_str())
                    .collect();
                tracing::debug!(
                    "ReservesMissing: pool={} vault_base={} vault_quote={} tx_accounts={:?}",
                    config.pool,
                    config.vault_base,
                    config.vault_quote,
                    accounts,
                );
                return EnrichmentResult::ReservesMissing;
            };
            let pool_0 = ConstantProduct::new(
                tx_reserves.pre.0,
                tx_reserves.pre.1,
                config.fee_num,
                config.fee_den,
            );
            let Some((loss, trace)) = compute_loss_with_trace(attack, pool_0) else {
                return EnrichmentResult::ReplayFailed;
            };
            (loss, Some(trace), None, tx_reserves.pre.1)
        }
        AmmKind::OrcaWhirlpool => {
            // Within-tick Whirlpool replay (Tier 3.4 step 4-α). Needs
            // slot-anchored dynamic state — sqrt_price / liquidity / tick —
            // that the parser can't recover from logs. ReplayFailed when
            // the lookup can't serve it (RPC error, unsupported provider).
            let Some(state) = lookup
                .pool_dynamic_state(&attack.pool, attack.dex, attack.slot)
                .await
            else {
                return EnrichmentResult::ReplayFailed;
            };
            let pool_0 = match state {
                DynamicPoolState::Whirlpool {
                    sqrt_price_q64,
                    liquidity,
                    tick_current_index,
                    tick_spacing,
                } => crate::orca_whirlpool::WhirlpoolPool {
                    liquidity,
                    sqrt_price_q64,
                    tick_current_index,
                    tick_spacing,
                    // apply_swap_within_tick reads fee from the explicit
                    // fee_num / fee_den arguments below, not from this
                    // field — leave it at 0.
                    fee_rate_hundredths_bps: 0,
                },
                // Mismatched variant (DLMM dynamic state for a Whirlpool
                // dex) is a contract violation; ReplayFailed is the
                // safest exit since it doesn't poison the metrics.
                _ => return EnrichmentResult::ReplayFailed,
            };
            // Fetch a TickArray window centered on the pool's current
            // tick — 5 arrays (center ±2 spans) covers every realistic
            // sandwich amount. `compute_loss_whirlpool` sorts per-leg
            // and falls back to `cross_tick_swap` when the within-tick
            // fast path can't resolve a leg.
            //
            // Implementations that don't speak the TickArray protocol
            // (`NoPoolLookup`, partial mocks) return `Vec::new()` here;
            // the per-leg fallback then sees no arrays and stays on the
            // within-tick path — `CrossTickUnsupported` fires only when
            // *both* paths fail.
            let span = ticks_per_array_span(pool_0.tick_spacing);
            let center = start_tick_index_for(pool_0.tick_current_index, pool_0.tick_spacing);
            let start_indices: [i32; 5] = [
                center - 2 * span,
                center - span,
                center,
                center + span,
                center + 2 * span,
            ];
            let tick_arrays: Vec<ParsedTickArray> = lookup
                .tick_arrays(&attack.pool, attack.dex, &start_indices, attack.slot)
                .await
                .into_iter()
                .flatten()
                .collect();
            let Some((loss, whirlpool_trace)) = compute_loss_whirlpool_with_trace(
                attack,
                pool_0,
                config.fee_num as u128,
                config.fee_den as u128,
                config.base_is_token_a,
                &tick_arrays,
            ) else {
                return EnrichmentResult::CrossTickUnsupported;
            };
            // Severity TVL: the frontrun tx's quote-vault balance, when
            // extractable. Whirlpool vaults hold tokens from out-of-range
            // positions too, so this overstates active-liquidity depth —
            // but it's a depth proxy not a precise measure, and the
            // alternative is leaving severity unset.
            let pool_quote_tvl = reserves::extract(frontrun_tx, &config)
                .map(|r| r.pre.1)
                .unwrap_or(0);
            (loss, None, Some(whirlpool_trace), pool_quote_tvl)
        }
        AmmKind::MeteoraDlmm => {
            // Phase 1 within-bin DLMM replay. Fetch dynamic state
            // (active_id + fee parameters) + the BinArray containing
            // the active bin, then run `compute_loss_dlmm`. Cross-bin
            // legs bail with `CrossTickUnsupported` for Phase 2 follow-up.
            let Some(state) = lookup
                .pool_dynamic_state(&attack.pool, attack.dex, attack.slot)
                .await
            else {
                return EnrichmentResult::ReplayFailed;
            };
            let dlmm_pool: DlmmPool = match state {
                DynamicPoolState::Dlmm(p) => p,
                // Mismatched variant (Whirlpool returned for a DLMM
                // dex) is a contract violation; treat as ReplayFailed.
                _ => return EnrichmentResult::ReplayFailed,
            };

            let array_index = bin_id_to_bin_array_index(dlmm_pool.active_id) as i64;
            // Fetch a 5-array window centered on the active bin's
            // array (mirrors Whirlpool's center±2 fetch). 5 arrays =
            // 350 bins of reach — covers any realistic sandwich
            // amount on a paid-tier pool. Cross-bin walks beyond the
            // window land on `out_of_window_bails` in `cross_bin_swap`
            // and surface as `CrossTickUnsupported`.
            let array_indices: [i64; 5] = [
                array_index - 2,
                array_index - 1,
                array_index,
                array_index + 1,
                array_index + 2,
            ];
            let arrays_raw = lookup
                .bin_arrays(&attack.pool, attack.dex, &array_indices, attack.slot)
                .await;
            // Empty `Vec` from a lookup that doesn't speak BinArray is
            // the "not supported" signal — same convention as Whirlpool's
            // tick_arrays.
            if arrays_raw.is_empty() {
                return EnrichmentResult::CrossTickUnsupported;
            }
            // The active array (slot 2 in the request order) is the
            // *minimum* for any DLMM replay — within-bin or otherwise.
            // Missing it means the lookup couldn't serve the most
            // important account in the window.
            if !matches!(arrays_raw.get(2), Some(Some(_))) {
                return EnrichmentResult::CrossTickUnsupported;
            }
            // Collapse the window to the populated arrays. Cross-bin
            // walker tolerates missing peripherals — it just bails
            // sooner if a leg walks into the gap.
            let arrays: Vec<ParsedBinArray> = arrays_raw.into_iter().flatten().collect();

            let Some(loss) = compute_loss_dlmm(attack, &dlmm_pool, &arrays, config.base_is_token_a)
            else {
                // None ⇒ cross-bin walked off the window, iteration
                // cap fired, or direction-mismatch invariant violation.
                // Map to CrossTickUnsupported so Phase 3 follow-up
                // (variable fee, token-2022) can be tracked separately
                // from invariant-violation cases.
                return EnrichmentResult::CrossTickUnsupported;
            };

            // Severity TVL: same shape as the other paths — frontrun
            // tx's quote-vault balance, when extractable.
            let pool_quote_tvl = reserves::extract(frontrun_tx, &config)
                .map(|r| r.pre.1)
                .unwrap_or(0);
            // No DLMM-specific replay trace yet; step 5 lands that
            // alongside vigil-v1 schema bumps.
            (loss, None, None, pool_quote_tvl)
        }
    };

    attack.victim_loss_lamports = Some(loss.victim_loss);
    attack.victim_loss_lamports_lower = loss.victim_loss_lower;
    attack.victim_loss_lamports_upper = loss.victim_loss_upper;
    attack.attacker_profit = Some(loss.attacker_profit_real);
    attack.price_impact_bps = Some(loss.price_impact_bps);

    // Derive severity from victim_loss vs pool quote-side TVL. The ratio is
    // dimensionless (both values in quote-token smallest units), so it
    // aggregates across pools cleanly. We deliberately use the *pre-
    // frontrun* quote reserve as the depth reference — severity is "how
    // much of the pool's standing depth did this attack consume", not a
    // post-state metric. Zero quote reserve leaves severity unset rather
    // than forcing a divide-by-zero into Critical.
    if attack.severity.is_none() && pool_quote_tvl > 0 {
        let loss_ratio = (loss.victim_loss.max(0) as f64) / (pool_quote_tvl as f64);
        attack.severity = Some(Severity::from_loss_ratio(loss_ratio));
    }

    // ReplayConfidence = 1 - (actual / counterfactual), clamped to [0, 1].
    // A counterfactual of zero means the victim wouldn't have gotten
    // anything even without the frontrun (malformed swap); treat as no
    // signal.
    let replay_confidence: f64 = if loss.counterfactual_victim_out > 0 {
        let ratio = loss.actual_victim_out as f64 / loss.counterfactual_victim_out as f64;
        (1.0f64 - ratio).clamp(0.0, 1.0)
    } else {
        0.0
    };

    let mut amm_signals = vec![
        Signal::AmmProfit {
            attacker_profit_real: loss.attacker_profit_real,
        },
        Signal::VictimLoss {
            lamports: loss.victim_loss,
            impact_bps: loss.price_impact_bps,
        },
        Signal::ReplayConfidence {
            value: replay_confidence,
        },
    ];

    // Per-step model fidelity (Tier 3.2). Emit only the steps where we
    // have a usable observation; missing parser data is silent rather
    // than a misleading zero.
    for (step, residual) in [
        (ReplayStep::Frontrun, loss.residual_bps_frontrun),
        (ReplayStep::Victim, loss.residual_bps_victim),
        (ReplayStep::Backrun, loss.residual_bps_backrun),
    ] {
        if let Some(residual_bps) = residual {
            amm_signals.push(Signal::InvariantResidual { step, residual_bps });
        }
    }

    // Sandwich shape (Tier 3.5): with-victim profit vs without-victim
    // profit. Emit unconditionally so the ensemble can downweight
    // arbitrage profiles where the victim was incidental.
    amm_signals.push(Signal::CounterfactualAttackerProfit {
        with_victim: loss.attacker_profit_real,
        without_victim: loss.counterfactual_attacker_profit_no_victim,
    });

    // Post-state diff (Tier 3.1): constant-product only. Whirlpool's
    // post-state can't be cross-checked with reserves yet — needs the
    // sqrt_price+tick trace surface added in a follow-up.
    if let Some(trace) = trace_opt.as_ref() {
        if let Some(backrun_tx) = backrun_tx {
            if let Some(backrun_reserves) = reserves::extract(backrun_tx, &config) {
                let observed_post_back = (
                    backrun_reserves.post.0.min(u64::MAX as u128) as u64,
                    backrun_reserves.post.1.min(u64::MAX as u128) as u64,
                );
                let divergence_bps = diff_test::reserves_divergence_bps(
                    trace.reserves_post_back,
                    observed_post_back,
                );
                let passed = divergence_bps < diff_test::PASS_THRESHOLD_BPS;
                amm_signals.push(Signal::ReservesMatchPostState {
                    divergence_bps,
                    passed,
                });
            }
        }
    }

    match attack.evidence.as_mut() {
        Some(ev) => ev.extend(amm_signals),
        None => attack.evidence = Some(DetectionEvidence::from_signals(amm_signals)),
    }
    if let Some(trace) = trace_opt {
        attack.amm_replay = Some(trace);
    }
    if let Some(whirlpool_trace) = whirlpool_trace_opt {
        attack.whirlpool_replay = Some(whirlpool_trace);
    }

    EnrichmentResult::Enriched
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup::{AmmKind, PoolConfig};
    use async_trait::async_trait;
    use swap_events::types::{
        DexType, SwapDirection, SwapEvent, TokenBalanceChange, TransactionData,
    };

    struct MockLookup {
        config: PoolConfig,
        /// `Some` lets tests exercise the Whirlpool / DLMM dispatch
        /// path; constant-product tests leave it at `None`.
        dynamic_state: Option<DynamicPoolState>,
        /// Tests that exercise cross-tick replay populate this; the
        /// trait impl returns it verbatim, ignoring the start_indices
        /// the caller asked for. Default is empty — every test that
        /// doesn't care about cross-tick keeps within-tick behaviour.
        tick_arrays: Vec<Option<ParsedTickArray>>,
        /// Tests that exercise DLMM replay populate this. Same opt-in
        /// shape as `tick_arrays`: returned verbatim regardless of
        /// the requested `array_indices`.
        bin_arrays: Vec<Option<ParsedBinArray>>,
    }

    #[async_trait]
    impl PoolStateLookup for MockLookup {
        async fn pool_config(&self, _pool: &str, _dex: DexType) -> Option<PoolConfig> {
            Some(self.config.clone())
        }

        async fn pool_dynamic_state(
            &self,
            _pool: &str,
            _dex: DexType,
            _slot: u64,
        ) -> Option<DynamicPoolState> {
            self.dynamic_state
        }

        async fn tick_arrays(
            &self,
            _pool: &str,
            _dex: DexType,
            _start_indices: &[i32],
            _slot: u64,
        ) -> Vec<Option<ParsedTickArray>> {
            self.tick_arrays.clone()
        }

        async fn bin_arrays(
            &self,
            _pool: &str,
            _dex: DexType,
            _array_indices: &[i64],
            _slot: u64,
        ) -> Vec<Option<ParsedBinArray>> {
            self.bin_arrays.clone()
        }
    }

    fn make_swap(
        sig: &str,
        signer: &str,
        dir: SwapDirection,
        amount_in: u64,
        amount_out: u64,
    ) -> SwapEvent {
        SwapEvent {
            signature: sig.into(),
            signer: signer.into(),
            dex: DexType::RaydiumV4,
            pool: "POOL".into(),
            direction: dir,
            token_mint: "MINT".into(),
            amount_in,
            amount_out,
            tx_index: 0,
            slot: None,
            fee: Some(5000),
        }
    }

    fn make_attack() -> SandwichAttack {
        let frontrun = make_swap("f", "atk", SwapDirection::Buy, 500_000_000, 0);
        let victim = make_swap("v", "vic", SwapDirection::Buy, 100_000_000, 0);
        let backrun = make_swap("b", "atk", SwapDirection::Sell, 499_000_000, 0);
        SandwichAttack {
            slot: 100,
            attacker: "atk".into(),
            pool: "POOL".into(),
            dex: DexType::RaydiumV4,
            frontrun,
            victim,
            backrun,
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

    fn make_frontrun_tx() -> TransactionData {
        TransactionData {
            signature: "f".into(),
            signer: "atk".into(),
            success: true,
            tx_index: 0,
            account_keys: vec![],
            instructions: vec![],
            inner_instructions: vec![],
            // Vault pre_amount are what compute_loss sees as pool reserves just
            // before the frontrun executed.
            token_balance_changes: vec![
                TokenBalanceChange {
                    mint: "BASE_MINT".into(),
                    account: "VAULT_BASE".into(),
                    owner: "POOL_AUTHORITY".into(),
                    pre_amount: 1_000_000_000,
                    post_amount: 999_000_000,
                },
                TokenBalanceChange {
                    mint: "QUOTE_MINT".into(),
                    account: "VAULT_QUOTE".into(),
                    owner: "POOL_AUTHORITY".into(),
                    pre_amount: 1_000_000_000,
                    post_amount: 1_500_000_000,
                },
            ],
            sol_balance_changes: vec![],
            fee: 5000,
            log_messages: vec![],
        }
    }

    fn make_config() -> PoolConfig {
        PoolConfig {
            kind: AmmKind::RaydiumV4,
            pool: "POOL".into(),
            vault_base: "VAULT_BASE".into(),
            vault_quote: "VAULT_QUOTE".into(),
            base_mint: "BASE_MINT".into(),
            quote_mint: "QUOTE_MINT".into(),
            fee_num: 25,
            fee_den: 10_000,
            base_is_token_a: false,
        }
    }

    #[tokio::test]
    async fn enriches_fields_on_happy_path() {
        let mut attack = make_attack();
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::Enriched);
        assert!(attack.victim_loss_lamports.unwrap() > 0);
        assert!(attack.price_impact_bps.unwrap() > 0);
        assert!(attack.attacker_profit.is_some());
        // Severity should be populated alongside the loss number; the exact
        // bucket depends on the loss/TVL ratio, just assert it's set so a
        // future TVL change doesn't silently regress to None.
        assert!(
            attack.severity.is_some(),
            "severity should be derived from victim_loss / pool_quote_tvl"
        );
    }

    #[tokio::test]
    async fn severity_matches_loss_to_tvl_ratio() {
        use swap_events::types::Severity;

        // 500M frontrun against 1B/1B reserves is enough movement that the
        // 100M victim loses a meaningful fraction of pool depth — well above
        // the 0.01% Medium threshold but typically below the 1% Critical mark.
        let mut attack = make_attack();
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        enrich_attack(&mut attack, &tx, None, &lookup).await;
        let loss = attack.victim_loss_lamports.unwrap();
        // tx_reserves.pre.1 (quote vault pre_amount) is 1_000_000_000.
        let expected = Severity::from_loss_ratio((loss.max(0) as f64) / 1_000_000_000.0);
        assert_eq!(attack.severity, Some(expected));
    }

    #[tokio::test]
    async fn severity_caller_set_value_is_preserved() {
        use swap_events::types::Severity;

        let mut attack = make_attack();
        attack.severity = Some(Severity::Critical);
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        enrich_attack(&mut attack, &tx, None, &lookup).await;
        // Pre-existing severity must not be overwritten — keeps callers
        // free to inject a domain-specific severity (e.g. Authority-Hop).
        assert_eq!(attack.severity, Some(Severity::Critical));
    }

    #[tokio::test]
    async fn amm_replay_trace_attached_and_consistent() {
        use swap_events::types::Signal;

        let mut attack = make_attack();
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        enrich_attack(&mut attack, &tx, None, &lookup).await;

        // Replay trace present and matches the tx's pre-balances.
        let trace = attack.amm_replay.as_ref().expect("replay trace attached");
        assert_eq!(trace.reserves_pre, (1_000_000_000, 1_000_000_000));
        // After frontrun (Buy, quote→base), base reserve drops and quote rises.
        assert!(trace.reserves_post_front.0 < trace.reserves_pre.0);
        assert!(trace.reserves_post_front.1 > trace.reserves_pre.1);
        // AMM signals appended to evidence.
        let ev = attack
            .evidence
            .as_ref()
            .expect("evidence present after enrichment");
        let has_amm_profit = ev
            .passing
            .iter()
            .chain(ev.failing.iter())
            .any(|s| matches!(s, Signal::AmmProfit { .. }));
        let has_victim_loss = ev
            .passing
            .iter()
            .chain(ev.failing.iter())
            .any(|s| matches!(s, Signal::VictimLoss { .. }));
        assert!(has_amm_profit, "AmmProfit signal missing");
        assert!(has_victim_loss, "VictimLoss signal missing");
        // Counterfactual > actual victim out when frontrun moved price away.
        assert!(trace.counterfactual_victim_out > trace.actual_victim_out);
    }

    #[tokio::test]
    async fn enrichment_emits_invariant_residual_and_counterfactual_signals() {
        // After enrich_attack runs on a successful happy-path replay, the
        // evidence set must include both Tier 3 signals so downstream
        // consumers can see model fidelity and the sandwich-shape check.
        let mut attack = make_attack();
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::Enriched);

        let ev = attack
            .evidence
            .as_ref()
            .expect("evidence present after enrichment");
        let all_signals = ev
            .passing
            .iter()
            .chain(ev.failing.iter())
            .chain(ev.informational.iter());

        // The synthetic make_attack uses amount_out = 0 on every leg, so
        // residuals come back None and InvariantResidual signals are *not*
        // emitted — that's the contract: silent on missing observations.
        assert!(
            !all_signals
                .clone()
                .any(|s| matches!(s, Signal::InvariantResidual { .. })),
            "InvariantResidual should be silent when amount_out is 0 on every leg",
        );

        // CounterfactualAttackerProfit is always emitted regardless of
        // observation availability, since it's computed entirely from our
        // own AMM math (no parser dependency). Sign assertions on the
        // counterfactual live in `counterfactual.rs` where we control the
        // backrun amount precisely; the enrichment fixture intentionally
        // uses an oversized backrun (the attacker has extra inventory) so
        // we only check that the signal is present and well-formed.
        let counterfactual = all_signals
            .clone()
            .find(|s| matches!(s, Signal::CounterfactualAttackerProfit { .. }));
        let Some(Signal::CounterfactualAttackerProfit {
            with_victim: _,
            without_victim: _,
        }) = counterfactual
        else {
            panic!("CounterfactualAttackerProfit signal missing from evidence");
        };
    }

    #[tokio::test]
    async fn enrichment_emits_invariant_residual_when_observations_present() {
        // Same as above but with non-zero amount_out on every leg, so the
        // residual signals fire (and should land in `informational` because
        // observations match our model exactly — see counterfactual.rs's
        // `residuals_zero_when_observations_match_model`).
        let mut attack = make_attack();

        // Replay the chain ourselves, then plant the same outputs back as
        // parser-observed amount_outs so residuals are exactly zero.
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let (fr_out, pool_1) = pool.apply_swap(500_000_000, SwapDirection::Buy);
        let (victim_out, pool_2) = pool_1.apply_swap(100_000_000, SwapDirection::Buy);
        let (back_out, _) = pool_2.apply_swap(499_000_000, SwapDirection::Sell);
        attack.frontrun.amount_out = fr_out;
        attack.victim.amount_out = victim_out;
        attack.backrun.amount_out = back_out;

        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };
        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::Enriched);

        let ev = attack.evidence.as_ref().expect("evidence");
        // All three steps should have emitted residual signals.
        let residual_count = ev
            .passing
            .iter()
            .chain(ev.failing.iter())
            .chain(ev.informational.iter())
            .filter(|s| matches!(s, Signal::InvariantResidual { .. }))
            .count();
        assert_eq!(
            residual_count, 3,
            "expected one InvariantResidual per step, got {residual_count}",
        );
        // Zero residuals are Informational, not Pass or Fail.
        assert_eq!(
            ev.informational
                .iter()
                .filter(|s| matches!(s, Signal::InvariantResidual { .. }))
                .count(),
            3,
        );
    }

    #[tokio::test]
    async fn reports_unsupported_dex_without_rpc() {
        let mut attack = make_attack();
        attack.dex = DexType::Phoenix;
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::UnsupportedDex);
        assert!(attack.victim_loss_lamports.is_none());
    }

    #[tokio::test]
    async fn whirlpool_dispatch_fails_when_dynamic_state_missing() {
        // Whirlpool config parses fine, but pool_dynamic_state has no
        // state to return (RPC outage, unsupported provider). Within-
        // tick replay can't run without sqrt_price/liquidity, so the
        // result is ReplayFailed — distinct from UnsupportedDex, which
        // is for DEXes we don't speak at all.
        let mut attack = make_attack();
        attack.dex = DexType::OrcaWhirlpool;
        let mut config = make_config();
        config.kind = AmmKind::OrcaWhirlpool;
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config,
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::ReplayFailed);
        assert!(attack.victim_loss_lamports.is_none());
    }

    #[tokio::test]
    async fn whirlpool_within_tick_enriches() {
        // Dynamic state in hand, modest swap amounts ⇒ within-tick replay
        // succeeds, attack picks up victim_loss / attacker_profit and
        // the standard signal set. amm_replay stays None on this path
        // (no trace shape yet for sqrt_price + tick state).
        let mut attack = make_attack();
        attack.dex = DexType::OrcaWhirlpool;
        let mut config = make_config();
        config.kind = AmmKind::OrcaWhirlpool;
        config.base_is_token_a = true;
        let tx = make_frontrun_tx();
        let dynamic_state = DynamicPoolState::Whirlpool {
            sqrt_price_q64: crate::orca_whirlpool::tick_math::sqrt_price_at_tick(10),
            liquidity: 1_000_000_000_000,
            tick_current_index: 10,
            tick_spacing: 64,
        };
        let lookup = MockLookup {
            config,
            dynamic_state: Some(dynamic_state),
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::Enriched);
        assert!(attack.victim_loss_lamports.is_some());
        assert!(attack.attacker_profit.is_some());
        // Whirlpool path doesn't populate the constant-product trace.
        assert!(attack.amm_replay.is_none());
        // It does populate the Whirlpool-specific trace (Tier 3.4 trace-β).
        let trace = attack.whirlpool_replay.expect("whirlpool_replay populated");
        // Pre-state matches the dynamic state the lookup served.
        assert_eq!(
            trace.sqrt_price_pre,
            crate::orca_whirlpool::tick_math::sqrt_price_at_tick(10),
        );
        assert_eq!(trace.liquidity_pre, 1_000_000_000_000);
        assert_eq!(trace.tick_current_pre, 10);
    }

    /// TickArray fixture builder: sparse `(slot, liquidity_net)`
    /// overrides on top of an all-zero, all-uninitialised default.
    /// Same shape as the helper in `counterfactual.rs` tests; kept
    /// local because this module's tests don't share that one.
    fn make_test_tick_array(start_tick_index: i32, slots: &[(usize, i128)]) -> ParsedTickArray {
        use crate::orca_whirlpool::tick_array::{TickData, TICK_ARRAY_SIZE};
        let mut ticks = [TickData::default(); TICK_ARRAY_SIZE];
        for (i, net) in slots {
            ticks[*i] = TickData {
                initialised: true,
                liquidity_net: *net,
            };
        }
        ParsedTickArray {
            start_tick_index,
            ticks,
        }
    }

    #[tokio::test]
    async fn whirlpool_cross_tick_fallback_via_lookup_enriches() {
        // Pool sqrt_price sits exactly on the tick=0 boundary ⇒
        // within-tick a→b bails on the very first leg. lookup serves a
        // multi-LP TickArray window so the cross-tick fallback (step
        // 3-δ-2-a) resolves every leg ⇒ Enriched.
        //
        // Direction: Sell-first sandwich with `base_is_token_a=true` ⇒
        // frontrun maps to a→b, exactly the direction the boundary
        // fixture forces through cross-tick. Buy-first wouldn't trigger
        // the within-tick failure here.
        let mut attack = make_attack();
        attack.dex = DexType::OrcaWhirlpool;
        attack.frontrun.direction = SwapDirection::Sell;
        attack.victim.direction = SwapDirection::Sell;
        attack.backrun.direction = SwapDirection::Buy;
        // Small amounts so each leg's cross-tick walk caps within the
        // first segment after the boundary at 1.5B liquidity. The
        // point of the test is the *fallback path*, not the swap
        // arithmetic — keep amounts well clear of further crossings.
        attack.frontrun.amount_in = 100_000;
        attack.victim.amount_in = 50_000;
        attack.backrun.amount_in = 100_000;
        let mut config = make_config();
        config.kind = AmmKind::OrcaWhirlpool;
        config.base_is_token_a = true;
        let tx = make_frontrun_tx();
        let dynamic_state = DynamicPoolState::Whirlpool {
            sqrt_price_q64: crate::orca_whirlpool::tick_math::sqrt_price_at_tick(0),
            liquidity: 1_500_000_000,
            tick_current_index: 0,
            tick_spacing: 64,
        };
        // LP1 [-128, 128] 1B; LP2 [-2048, 2048] 500M. Exactly the
        // double-LP fixture the cross_tick_swap unit tests use.
        let tick_arrays = vec![
            Some(make_test_tick_array(
                0,
                &[(2, -1_000_000_000), (32, -500_000_000)],
            )),
            Some(make_test_tick_array(
                -5632,
                &[(86, 1_000_000_000), (56, 500_000_000)],
            )),
        ];
        let lookup = MockLookup {
            config,
            dynamic_state: Some(dynamic_state),
            tick_arrays,
            bin_arrays: vec![],
        };

        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::Enriched);
        assert!(attack.victim_loss_lamports.is_some());
        assert!(attack.attacker_profit.is_some());
        // Cross-tick path also populates the Whirlpool trace — the
        // post-front liquidity should differ from pre when a boundary
        // gets crossed (LP1 deactivates as the swap exits its range).
        let trace = attack.whirlpool_replay.expect("whirlpool_replay populated");
        assert_eq!(trace.liquidity_pre, 1_500_000_000);
    }

    #[tokio::test]
    async fn whirlpool_cross_tick_returns_cross_tick_variant() {
        // Tiny liquidity + large frontrun walks past the next tick
        // boundary on the very first leg. apply_swap_within_tick bails,
        // and enrich_attack maps that to CrossTickUnsupported — distinct
        // from ReplayFailed because the failure is a known model
        // limitation, not a parser bug.
        let mut attack = make_attack();
        attack.dex = DexType::OrcaWhirlpool;
        attack.frontrun.amount_in = 1_000_000_000;
        let mut config = make_config();
        config.kind = AmmKind::OrcaWhirlpool;
        config.base_is_token_a = true;
        let tx = make_frontrun_tx();
        let dynamic_state = DynamicPoolState::Whirlpool {
            sqrt_price_q64: crate::orca_whirlpool::tick_math::sqrt_price_at_tick(10),
            liquidity: 1_000,
            tick_current_index: 10,
            tick_spacing: 64,
        };
        let lookup = MockLookup {
            config,
            dynamic_state: Some(dynamic_state),
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::CrossTickUnsupported);
        assert!(attack.victim_loss_lamports.is_none());
    }

    #[tokio::test]
    async fn reports_reserves_missing_when_vault_absent() {
        let mut attack = make_attack();
        let mut tx = make_frontrun_tx();
        tx.token_balance_changes.clear();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::ReservesMissing);
    }

    // ----- Tier 3.1 — ReservesMatchPostState diff signal -----------------

    /// Compute what the AMM replay would predict for `reserves_post_back`
    /// given the standard fixture (1B/1B reserves, 25 bps fee, the same
    /// frontrun/victim/backrun amounts as `make_attack`). Used by the
    /// Tier 3.1 tests to plant matching or mismatching post-balances on a
    /// synthetic backrun tx.
    fn predicted_post_back_reserves() -> (u64, u64) {
        let pool_0 = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let (_fr_out, pool_1) = pool_0.apply_swap(500_000_000, SwapDirection::Buy);
        let (_v_out, pool_2) = pool_1.apply_swap(100_000_000, SwapDirection::Buy);
        let (_b_out, pool_3) = pool_2.apply_swap(499_000_000, SwapDirection::Sell);
        let (b, q) = pool_3.reserves();
        (b as u64, q as u64)
    }

    fn make_backrun_tx(post_base: u64, post_quote: u64) -> TransactionData {
        TransactionData {
            signature: "b".into(),
            signer: "atk".into(),
            success: true,
            tx_index: 0,
            account_keys: vec![],
            instructions: vec![],
            inner_instructions: vec![],
            token_balance_changes: vec![
                TokenBalanceChange {
                    mint: "BASE_MINT".into(),
                    account: "VAULT_BASE".into(),
                    owner: "POOL_AUTHORITY".into(),
                    pre_amount: 0,
                    post_amount: post_base,
                },
                TokenBalanceChange {
                    mint: "QUOTE_MINT".into(),
                    account: "VAULT_QUOTE".into(),
                    owner: "POOL_AUTHORITY".into(),
                    pre_amount: 0,
                    post_amount: post_quote,
                },
            ],
            sol_balance_changes: vec![],
            fee: 5000,
            log_messages: vec![],
        }
    }

    #[tokio::test]
    async fn reserves_match_post_state_passes_when_backrun_balances_match_replay() {
        // Plant the replay's predicted post-back reserves verbatim onto the
        // backrun tx's post-balances. divergence_bps must be exactly 0,
        // passed=true, and the signal lands in `informational` (not Pass —
        // model fidelity isn't itself evidence for a sandwich call).
        let mut attack = make_attack();
        let frontrun_tx = make_frontrun_tx();
        let (post_base, post_quote) = predicted_post_back_reserves();
        let backrun_tx = make_backrun_tx(post_base, post_quote);
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        let result = enrich_attack(&mut attack, &frontrun_tx, Some(&backrun_tx), &lookup).await;
        assert_eq!(result, EnrichmentResult::Enriched);

        let ev = attack.evidence.as_ref().expect("evidence");
        let signal = ev
            .informational
            .iter()
            .find_map(|s| match s {
                Signal::ReservesMatchPostState {
                    divergence_bps,
                    passed,
                } => Some((*divergence_bps, *passed)),
                _ => None,
            })
            .expect("ReservesMatchPostState should land in informational at zero divergence");
        assert_eq!(signal.0, 0);
        assert!(signal.1);
    }

    #[tokio::test]
    async fn reserves_match_post_state_fails_when_backrun_balances_diverge() {
        // Perturb the base side by ~5% — well past the 100 bps pass
        // threshold — so the signal flips to Fail.
        let mut attack = make_attack();
        let frontrun_tx = make_frontrun_tx();
        let (post_base, post_quote) = predicted_post_back_reserves();
        let perturbed_base = (post_base as f64 * 0.95) as u64;
        let backrun_tx = make_backrun_tx(perturbed_base, post_quote);
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        enrich_attack(&mut attack, &frontrun_tx, Some(&backrun_tx), &lookup).await;

        let ev = attack.evidence.as_ref().expect("evidence");
        let signal = ev
            .failing
            .iter()
            .find_map(|s| match s {
                Signal::ReservesMatchPostState {
                    divergence_bps,
                    passed,
                } => Some((*divergence_bps, *passed)),
                _ => None,
            })
            .expect("ReservesMatchPostState should land in failing past threshold");
        assert!(
            signal.0 >= crate::diff_test::PASS_THRESHOLD_BPS,
            "expected divergence_bps ≥ threshold, got {}",
            signal.0,
        );
        assert!(!signal.1);
    }

    #[tokio::test]
    async fn reserves_match_post_state_silent_when_backrun_tx_absent() {
        // Backwards-compat path: existing callers that pass `None` get the
        // same evidence shape as before — no Tier 3.1 signal at all.
        let mut attack = make_attack();
        let frontrun_tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        enrich_attack(&mut attack, &frontrun_tx, None, &lookup).await;
        let ev = attack.evidence.as_ref().expect("evidence");
        let any = ev
            .passing
            .iter()
            .chain(ev.failing.iter())
            .chain(ev.informational.iter())
            .any(|s| matches!(s, Signal::ReservesMatchPostState { .. }));
        assert!(!any, "should be silent when backrun_tx is None");
    }

    // ----- Tier 3.3 — victim_loss CI propagation -------------------------

    #[tokio::test]
    async fn victim_loss_ci_propagates_when_observations_match_model() {
        // All three legs' amount_outs are pre-computed from the same pool
        // math the replay uses, so every residual is exactly zero ⇒ CI
        // collapses to `[point, point]`. Both bounds equal the point
        // estimate exactly.
        let mut attack = make_attack();
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let (fr_out, pool_1) = pool.apply_swap(500_000_000, SwapDirection::Buy);
        let (victim_out, pool_2) = pool_1.apply_swap(100_000_000, SwapDirection::Buy);
        let (back_out, _) = pool_2.apply_swap(499_000_000, SwapDirection::Sell);
        attack.frontrun.amount_out = fr_out;
        attack.victim.amount_out = victim_out;
        attack.backrun.amount_out = back_out;

        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };
        enrich_attack(&mut attack, &tx, None, &lookup).await;

        let point = attack.victim_loss_lamports.unwrap();
        assert!(point > 0);
        assert_eq!(attack.victim_loss_lamports_lower, Some(point));
        assert_eq!(attack.victim_loss_lamports_upper, Some(point));
    }

    #[tokio::test]
    async fn victim_loss_ci_none_when_observations_missing() {
        // make_attack/make_frontrun_tx leave every amount_out = 0 ⇒ all
        // residuals come back None ⇒ no CI is derivable. The point
        // estimate is still emitted; only the bounds stay None.
        let mut attack = make_attack();
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };
        enrich_attack(&mut attack, &tx, None, &lookup).await;

        assert!(attack.victim_loss_lamports.unwrap() > 0);
        assert!(attack.victim_loss_lamports_lower.is_none());
        assert!(attack.victim_loss_lamports_upper.is_none());
    }

    #[tokio::test]
    async fn mev_receipt_inherits_victim_loss_ci() {
        // Tier 3.3 CI fields must round-trip into MevReceipt::from_attack
        // so Vigil's per-receipt rendering can show the band without
        // recomputing.
        let mut attack = make_attack();
        let pool = ConstantProduct::new(1_000_000_000, 1_000_000_000, 25, 10_000);
        let (fr_out, pool_1) = pool.apply_swap(500_000_000, SwapDirection::Buy);
        let (victim_out, pool_2) = pool_1.apply_swap(100_000_000, SwapDirection::Buy);
        let (back_out, _) = pool_2.apply_swap(499_000_000, SwapDirection::Sell);
        attack.frontrun.amount_out = fr_out;
        attack.victim.amount_out = victim_out;
        attack.backrun.amount_out = back_out;

        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };
        enrich_attack(&mut attack, &tx, None, &lookup).await;

        let receipt = swap_events::types::MevReceipt::from_attack(&attack);
        assert_eq!(receipt.loss_amount, attack.victim_loss_lamports);
        assert_eq!(receipt.loss_amount_lower, attack.victim_loss_lamports_lower);
        assert_eq!(receipt.loss_amount_upper, attack.victim_loss_lamports_upper);
        assert!(receipt.loss_amount_lower.is_some());
    }

    #[tokio::test]
    async fn reserves_match_post_state_silent_when_backrun_lacks_vault_meta() {
        // Backrun tx supplied but its token-balance meta doesn't include
        // the pool's vault accounts (e.g. multi-program routing tx). We
        // can't read the actual post-state, so we stay silent rather than
        // emit a misleading saturating value.
        let mut attack = make_attack();
        let frontrun_tx = make_frontrun_tx();
        let backrun_tx = TransactionData {
            signature: "b".into(),
            signer: "atk".into(),
            success: true,
            tx_index: 0,
            account_keys: vec![],
            instructions: vec![],
            inner_instructions: vec![],
            token_balance_changes: vec![],
            sol_balance_changes: vec![],
            fee: 5000,
            log_messages: vec![],
        };
        let lookup = MockLookup {
            config: make_config(),
            dynamic_state: None,
            tick_arrays: vec![],
            bin_arrays: vec![],
        };

        enrich_attack(&mut attack, &frontrun_tx, Some(&backrun_tx), &lookup).await;
        let ev = attack.evidence.as_ref().expect("evidence");
        let any = ev
            .passing
            .iter()
            .chain(ev.failing.iter())
            .chain(ev.informational.iter())
            .any(|s| matches!(s, Signal::ReservesMatchPostState { .. }));
        assert!(
            !any,
            "should be silent when backrun tx has no vault balances",
        );
    }

    // ----- DLMM (Phase 1) Tier 4 corpus ---------------------------------
    //
    // The Phase 1 within-bin DLMM replay produces `victim_loss = 0` by
    // construction (constant-sum mechanic ⇒ frontrun doesn't move price).
    // These integration fixtures pin the end-to-end flow:
    //   1. within-bin sandwich ⇒ Enriched, victim_loss = 0;
    //   2. cross-bin sandwich (bin gets drained) ⇒ CrossTickUnsupported;
    //   3. missing BinArray ⇒ CrossTickUnsupported.

    use crate::meteora_dlmm::bin_array::{ParsedBin, ParsedBinArray, MAX_BIN_PER_ARRAY};
    use crate::meteora_dlmm::price_math::ONE as DLMM_ONE;
    use crate::meteora_dlmm::DlmmPool;
    use solana_sdk::pubkey::Pubkey;

    fn dlmm_config() -> PoolConfig {
        PoolConfig {
            kind: AmmKind::MeteoraDlmm,
            pool: "POOL".into(),
            vault_base: "VAULT_BASE".into(),
            vault_quote: "VAULT_QUOTE".into(),
            base_mint: "BASE_MINT".into(),
            quote_mint: "QUOTE_MINT".into(),
            // base_factor=8000 * bin_step=25 * 10 = 2_000_000 ⇒ 0.2% in 1e9.
            fee_num: 2_000_000,
            fee_den: 1_000_000_000,
            // base = x ⇒ swap_for_y = Sell, !swap_for_y = Buy.
            base_is_token_a: true,
        }
    }

    fn make_dlmm_attack(amount: u64) -> SandwichAttack {
        let frontrun = make_swap("f", "atk", SwapDirection::Buy, amount, 0);
        let mut victim = make_swap("v", "vic", SwapDirection::Buy, amount / 2, 0);
        let mut backrun = make_swap("b", "atk", SwapDirection::Sell, amount, 0);
        // Override DEX so AmmKind::from_dex picks MeteoraDlmm.
        let frontrun = SwapEvent {
            dex: DexType::MeteoraDlmm,
            ..frontrun
        };
        victim.dex = DexType::MeteoraDlmm;
        backrun.dex = DexType::MeteoraDlmm;
        SandwichAttack {
            dex: DexType::MeteoraDlmm,
            frontrun,
            victim,
            backrun,
            ..make_attack()
        }
    }

    /// Build a synthetic ParsedBinArray whose active bin (id = 0) has
    /// the supplied `(amount_x, amount_y)`. Array index 0 covers
    /// bins `[0, 69]`, so bin 0 lands at `bins[0]`.
    fn dlmm_active_array(amount_x: u64, amount_y: u64) -> ParsedBinArray {
        let mut bins = vec![
            ParsedBin {
                amount_x: 0,
                amount_y: 0,
                price: 0,
                liquidity_supply: 0,
            };
            MAX_BIN_PER_ARRAY
        ];
        bins[0] = ParsedBin {
            amount_x,
            amount_y,
            price: DLMM_ONE,
            liquidity_supply: 1_000_000_000,
        };
        ParsedBinArray {
            index: 0,
            version: 1,
            lb_pair: Pubkey::new_unique(),
            bins,
        }
    }

    fn dlmm_state() -> DynamicPoolState {
        DynamicPoolState::Dlmm(DlmmPool {
            active_id: 0,
            bin_step: 25,
            base_factor: 8000,
            base_fee_power_factor: 0,
            protocol_share: 0,
        })
    }

    /// Within-bin sandwich: comfortable bin reserves, modest swap
    /// amounts. Replay should succeed with `victim_loss = 0` (the
    /// constant-sum invariant) and `Enriched` outcome.
    ///
    /// Window layout mirrors enrich's actual fetch: 5-array vec
    /// (center ± 2), with the active array at slot 2. Peripherals
    /// stay `None` since within-bin replay never reaches them.
    #[tokio::test]
    async fn dlmm_within_bin_corpus_yields_zero_loss_enriched() {
        let mut attack = make_dlmm_attack(100_000);
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: dlmm_config(),
            dynamic_state: Some(dlmm_state()),
            tick_arrays: vec![],
            bin_arrays: vec![
                None,
                None,
                Some(dlmm_active_array(1_000_000_000, 1_000_000_000)),
                None,
                None,
            ],
        };

        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::Enriched);
        assert_eq!(attack.victim_loss_lamports, Some(0));
    }

    /// Cross-bin sandwich: tiny bin reserves (100 each) vs. a much
    /// larger frontrun (1B). First leg drains the bin ⇒
    /// `compute_loss_dlmm` returns `None` ⇒ enrich reports
    /// `CrossTickUnsupported`. Phase 2 will pick this up.
    #[tokio::test]
    async fn dlmm_cross_bin_corpus_returns_cross_tick_unsupported() {
        let mut attack = make_dlmm_attack(1_000_000_000);
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: dlmm_config(),
            dynamic_state: Some(dlmm_state()),
            tick_arrays: vec![],
            // 5-array window with tiny active-bin reserves and no
            // peripheral bins — frontrun drains the active bin
            // immediately, then runs out of window.
            bin_arrays: vec![None, None, Some(dlmm_active_array(100, 100)), None, None],
        };
        assert_eq!(
            enrich_attack(&mut attack, &tx, None, &lookup).await,
            EnrichmentResult::CrossTickUnsupported,
        );
    }

    /// Missing BinArray (lookup returns empty Vec) ⇒ enrich can't see
    /// the active bin's reserves and bails with
    /// `CrossTickUnsupported`. Same convention as Whirlpool when
    /// tick_arrays come back empty.
    #[tokio::test]
    async fn dlmm_missing_bin_array_corpus_returns_cross_tick_unsupported() {
        let mut attack = make_dlmm_attack(100_000);
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: dlmm_config(),
            dynamic_state: Some(dlmm_state()),
            tick_arrays: vec![],
            bin_arrays: vec![],
        };
        assert_eq!(
            enrich_attack(&mut attack, &tx, None, &lookup).await,
            EnrichmentResult::CrossTickUnsupported,
        );
    }
}
