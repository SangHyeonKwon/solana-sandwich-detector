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

use crate::{compute_loss_with_trace, diff_test, reserves, ConstantProduct, PoolStateLookup};

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

    attack.victim_loss_lamports = Some(loss.victim_loss);
    attack.attacker_profit = Some(loss.attacker_profit_real);
    attack.price_impact_bps = Some(loss.price_impact_bps);

    // Derive severity from victim_loss vs pool quote-side TVL. Both values are
    // already normalized to quote-token smallest units (see counterfactual.rs),
    // so the ratio is dimensionless. We deliberately use the *pre-frontrun*
    // quote reserve as the depth reference — the severity is "how much of the
    // pool's standing depth did this attack consume", not a post-state metric.
    // A degenerate pool (zero quote reserve) leaves severity unset rather than
    // forcing a divide-by-zero into Critical.
    if attack.severity.is_none() {
        let pool_quote_tvl = tx_reserves.pre.1;
        if pool_quote_tvl > 0 {
            let loss_ratio = (loss.victim_loss.max(0) as f64) / (pool_quote_tvl as f64);
            attack.severity = Some(Severity::from_loss_ratio(loss_ratio));
        }
    }

    // ReplayConfidence = 1 - (actual / counterfactual), clamped to [0, 1].
    // A counterfactual of zero means the victim wouldn't have gotten anything
    // even without the frontrun (malformed swap); treat that as no signal.
    let replay_confidence: f64 = if trace.counterfactual_victim_out > 0 {
        let ratio = trace.actual_victim_out as f64 / trace.counterfactual_victim_out as f64;
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

    // Per-step model fidelity (Tier 3.2). Emit only the steps where we have
    // a usable observation; missing parser data is silent rather than a
    // misleading zero.
    for (step, residual) in [
        (ReplayStep::Frontrun, loss.residual_bps_frontrun),
        (ReplayStep::Victim, loss.residual_bps_victim),
        (ReplayStep::Backrun, loss.residual_bps_backrun),
    ] {
        if let Some(residual_bps) = residual {
            amm_signals.push(Signal::InvariantResidual {
                step,
                residual_bps,
            });
        }
    }

    // Sandwich shape (Tier 3.5): the with-victim profit is what the attacker
    // actually netted; the without-victim profit is what they would have
    // netted if the victim had not traded. Emit unconditionally so the
    // ensemble can downweight arbitrage profiles where the victim was
    // incidental.
    amm_signals.push(Signal::CounterfactualAttackerProfit {
        with_victim: loss.attacker_profit_real,
        without_victim: loss.counterfactual_attacker_profit_no_victim,
    });

    // Post-state diff (Tier 3.1): if the caller supplied the backrun tx,
    // compare the chain's actual post-backrun vault balances to what our
    // replay predicts. Silent when the backrun tx is missing or its meta
    // doesn't carry the vault accounts — preserving the existing call
    // shape while adding the proof signal opportunistically.
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

    match attack.evidence.as_mut() {
        Some(ev) => ev.extend(amm_signals),
        None => attack.evidence = Some(DetectionEvidence::from_signals(amm_signals)),
    }
    attack.amm_replay = Some(trace);

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
    }

    #[async_trait]
    impl PoolStateLookup for MockLookup {
        async fn pool_config(&self, _pool: &str, _dex: DexType) -> Option<PoolConfig> {
            Some(self.config.clone())
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
        }
    }

    #[tokio::test]
    async fn enriches_fields_on_happy_path() {
        let mut attack = make_attack();
        let tx = make_frontrun_tx();
        let lookup = MockLookup {
            config: make_config(),
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
        };

        let result = enrich_attack(&mut attack, &tx, None, &lookup).await;
        assert_eq!(result, EnrichmentResult::UnsupportedDex);
        assert!(attack.victim_loss_lamports.is_none());
    }

    #[tokio::test]
    async fn reports_reserves_missing_when_vault_absent() {
        let mut attack = make_attack();
        let mut tx = make_frontrun_tx();
        tx.token_balance_changes.clear();
        let lookup = MockLookup {
            config: make_config(),
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
        };

        let result =
            enrich_attack(&mut attack, &frontrun_tx, Some(&backrun_tx), &lookup).await;
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
}
