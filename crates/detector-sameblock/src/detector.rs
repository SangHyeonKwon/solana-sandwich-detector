use std::collections::{HashMap, HashSet};

use swap_events::types::{DetectionEvidence, DetectionMethod, SandwichAttack, Signal, SwapEvent};

/// Detect same-block sandwich attacks from a list of swap events.
///
/// Groups swaps by pool, then finds triplets (frontrun, victim, backrun) where:
/// - frontrun and backrun have the same signer (attacker)
/// - frontrun and backrun are opposite directions (buy then sell, or vice versa)
/// - victim is between them in transaction order
/// - victim has a different signer
/// - victim trades in the same direction as frontrun
pub fn detect_sandwiches(slot: u64, swaps: &[SwapEvent]) -> Vec<SandwichAttack> {
    let mut results = Vec::new();

    // Group by pool
    let mut by_pool: HashMap<&str, Vec<&SwapEvent>> = HashMap::new();
    for swap in swaps {
        by_pool.entry(&swap.pool).or_default().push(swap);
    }

    for (_pool, mut pool_swaps) in by_pool {
        pool_swaps.sort_by_key(|s| s.tx_index);

        if pool_swaps.len() < 3 {
            continue;
        }

        // Track consumed swaps to prevent reuse
        let mut consumed: HashSet<usize> = HashSet::new();

        for i in 0..pool_swaps.len() {
            let frontrun = pool_swaps[i];

            if consumed.contains(&frontrun.tx_index) {
                continue;
            }

            for k in (i + 2)..pool_swaps.len() {
                let backrun = pool_swaps[k];

                if consumed.contains(&backrun.tx_index) {
                    continue;
                }

                // Same signer (attacker)
                if frontrun.signer != backrun.signer {
                    continue;
                }
                // Opposite directions
                if frontrun.direction == backrun.direction {
                    continue;
                }

                // Find victim(s) sandwiched between frontrun and backrun
                let mut found_victim = false;
                for &victim in pool_swaps.iter().take(k).skip(i + 1) {
                    if victim.signer == frontrun.signer {
                        continue;
                    }
                    if victim.direction != frontrun.direction {
                        continue;
                    }

                    let gross = backrun.amount_out as i64 - frontrun.amount_in as i64;
                    let cost = frontrun.fee.map(|f| f as i64).unwrap_or(0)
                        + backrun.fee.map(|f| f as i64).unwrap_or(0);
                    let net = gross - cost;
                    let front_gap = victim.tx_index.saturating_sub(frontrun.tx_index);
                    let back_gap = backrun.tx_index.saturating_sub(victim.tx_index);
                    let evidence = DetectionEvidence::from_signals(vec![
                        Signal::SameBlock,
                        Signal::OrderingTight {
                            front_gap,
                            back_gap,
                        },
                        Signal::NaiveProfit { gross, cost, net },
                    ]);
                    results.push(SandwichAttack {
                        slot,
                        attacker: frontrun.signer.clone(),
                        frontrun: frontrun.clone(),
                        victim: victim.clone(),
                        backrun: backrun.clone(),
                        pool: frontrun.pool.clone(),
                        dex: frontrun.dex,
                        estimated_attacker_profit: estimate_profit(frontrun, backrun),
                        victim_loss_lamports: None,
                        frontrun_slot: None,
                        backrun_slot: None,
                        detection_method: Some(DetectionMethod::SameBlock),
                        bundle_provenance: None,
                        confidence: None,
                        net_profit: Some(net),
                        attacker_profit: None,
                        price_impact_bps: None,
                        evidence: Some(evidence),
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
                    });
                    found_victim = true;
                }

                if found_victim {
                    consumed.insert(frontrun.tx_index);
                    consumed.insert(backrun.tx_index);
                    break;
                }
            }
        }
    }

    results
}

/// Simple v1 heuristic: attacker profit = what they got back minus what they spent.
fn estimate_profit(frontrun: &SwapEvent, backrun: &SwapEvent) -> Option<i64> {
    Some(backrun.amount_out as i64 - frontrun.amount_in as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_events::types::{DexType, SwapDirection};

    fn swap(sig: &str, signer: &str, pool: &str, dir: SwapDirection, idx: usize) -> SwapEvent {
        SwapEvent {
            signature: sig.to_string(),
            signer: signer.to_string(),
            dex: DexType::RaydiumV4,
            pool: pool.to_string(),
            direction: dir,
            token_mint: "TokenMint111".to_string(),
            amount_in: 1_000_000,
            amount_out: 900_000,
            tx_index: idx,
            slot: None,
            fee: None,
        }
    }

    #[test]
    fn basic_sandwich() {
        let swaps = vec![
            swap("s1", "attacker", "pool1", SwapDirection::Buy, 0),
            swap("s2", "victim", "pool1", SwapDirection::Buy, 1),
            swap("s3", "attacker", "pool1", SwapDirection::Sell, 2),
        ];
        let res = detect_sandwiches(100, &swaps);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].attacker, "attacker");
        assert_eq!(res[0].victim.signature, "s2");
    }

    #[test]
    fn no_sandwich_same_signer() {
        let swaps = vec![
            swap("s1", "trader", "pool1", SwapDirection::Buy, 0),
            swap("s2", "trader", "pool1", SwapDirection::Buy, 1),
            swap("s3", "trader", "pool1", SwapDirection::Sell, 2),
        ];
        assert!(detect_sandwiches(100, &swaps).is_empty());
    }

    #[test]
    fn no_sandwich_same_direction() {
        let swaps = vec![
            swap("s1", "atk", "pool1", SwapDirection::Buy, 0),
            swap("s2", "vic", "pool1", SwapDirection::Buy, 1),
            swap("s3", "atk", "pool1", SwapDirection::Buy, 2),
        ];
        assert!(detect_sandwiches(100, &swaps).is_empty());
    }

    #[test]
    fn multiple_victims() {
        let swaps = vec![
            swap("s1", "atk", "pool1", SwapDirection::Buy, 0),
            swap("s2", "vic1", "pool1", SwapDirection::Buy, 1),
            swap("s3", "vic2", "pool1", SwapDirection::Buy, 2),
            swap("s4", "atk", "pool1", SwapDirection::Sell, 3),
        ];
        assert_eq!(detect_sandwiches(100, &swaps).len(), 2);
    }

    #[test]
    fn different_pools_no_sandwich() {
        let swaps = vec![
            swap("s1", "atk", "pool1", SwapDirection::Buy, 0),
            swap("s2", "vic", "pool2", SwapDirection::Buy, 1),
            swap("s3", "atk", "pool1", SwapDirection::Sell, 2),
        ];
        assert!(detect_sandwiches(100, &swaps).is_empty());
    }

    #[test]
    fn reverse_sandwich_sell_first() {
        let swaps = vec![
            swap("s1", "atk", "pool1", SwapDirection::Sell, 0),
            swap("s2", "vic", "pool1", SwapDirection::Sell, 1),
            swap("s3", "atk", "pool1", SwapDirection::Buy, 2),
        ];
        let res = detect_sandwiches(100, &swaps);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].frontrun.direction, SwapDirection::Sell);
        assert_eq!(res[0].backrun.direction, SwapDirection::Buy);
    }

    #[test]
    fn backrun_not_reused() {
        // atk has two buy frontruns (s1, s3) but only one sell backrun (s5).
        // s5 should be consumed by s1's sandwich and not reused for s3.
        let swaps = vec![
            swap("s1", "atk", "pool1", SwapDirection::Buy, 0),
            swap("s2", "vic1", "pool1", SwapDirection::Buy, 1),
            swap("s3", "atk", "pool1", SwapDirection::Buy, 2),
            swap("s4", "vic2", "pool1", SwapDirection::Buy, 3),
            swap("s5", "atk", "pool1", SwapDirection::Sell, 4),
        ];
        let res = detect_sandwiches(100, &swaps);
        // s1 as frontrun, s5 as backrun → vic1 and vic2 as victims (2 sandwiches)
        // s3 cannot reuse s5 because it's consumed
        assert_eq!(res.len(), 2);
        assert!(res.iter().all(|s| s.frontrun.signature == "s1"));
    }

    #[test]
    fn evidence_structure_same_block() {
        use swap_events::types::Signal;

        let swaps = vec![
            swap("s1", "attacker", "pool1", SwapDirection::Buy, 3),
            swap("s2", "victim", "pool1", SwapDirection::Buy, 4),
            swap("s3", "attacker", "pool1", SwapDirection::Sell, 5),
        ];
        let res = detect_sandwiches(100, &swaps);
        assert_eq!(res.len(), 1);
        let ev = res[0].evidence.as_ref().expect("evidence attached");

        // Expect SameBlock + OrderingTight + NaiveProfit as passing.
        let kinds: Vec<&str> = ev
            .passing
            .iter()
            .map(|s| match s {
                Signal::SameBlock => "SameBlock",
                Signal::OrderingTight { .. } => "OrderingTight",
                Signal::NaiveProfit { .. } => "NaiveProfit",
                _ => "other",
            })
            .collect();
        assert!(kinds.contains(&"SameBlock"));
        assert!(kinds.contains(&"OrderingTight"));
        // NaiveProfit may be Pass or Fail depending on gross; test triplet has
        // amount_out < amount_in so net is negative → goes to failing, not passing.
        // Confirm tight ordering (gaps = 1 each).
        for s in &ev.passing {
            if let Signal::OrderingTight {
                front_gap,
                back_gap,
            } = s
            {
                assert_eq!(*front_gap, 1);
                assert_eq!(*back_gap, 1);
            }
        }
        // categories_fired must be at least 2 (Temporal + Structural).
        assert!(
            ev.categories_fired >= 2,
            "expected ≥2 categories, got {}",
            ev.categories_fired
        );
    }

    #[test]
    fn profit_calculation() {
        let mut front = swap("s1", "atk", "pool1", SwapDirection::Buy, 0);
        front.amount_in = 5_000_000_000;
        front.amount_out = 100_000;
        let victim = swap("s2", "vic", "pool1", SwapDirection::Buy, 1);
        let mut back = swap("s3", "atk", "pool1", SwapDirection::Sell, 2);
        back.amount_in = 100_000;
        back.amount_out = 5_200_000_000;

        let res = detect_sandwiches(100, &[front, victim, back]);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].estimated_attacker_profit, Some(200_000_000));
    }

    #[test]
    fn detects_wide_same_block_sandwich_with_intervening_swaps() {
        // Mainnet pattern observed in slot 285000037: a single attacker
        // frontrun at a low tx_index sandwiches victims spread across high
        // tx_indices with a far backrun. The sameblock detector must surface
        // these even though tx_index gaps are large; finalize_for_vigil()
        // then classifies the result as Wide Sandwich.
        use swap_events::types::AttackType;

        let mut swaps = vec![
            swap("front", "atk", "pool1", SwapDirection::Buy, 5),
            // Three unrelated traders in the same pool / same direction —
            // they look like victims to the sandwich heuristic.
            swap("noise1", "trader_a", "pool1", SwapDirection::Buy, 30),
            swap("victim", "vic", "pool1", SwapDirection::Buy, 60),
            swap("noise2", "trader_b", "pool1", SwapDirection::Buy, 100),
            swap("back", "atk", "pool1", SwapDirection::Sell, 200),
        ];
        // Detector requires sorted-by-tx_index input; mirror what production
        // produces and let the detector group internally.
        swaps.sort_by_key(|s| s.tx_index);

        let res = detect_sandwiches(100, &swaps);
        // 3 candidates emerge — anyone same-direction between front and back
        // is a potential victim. The downstream filter (FilteredWindowDetector)
        // uses evidence to reject implausible victims; sameblock just surfaces
        // candidates.
        assert_eq!(res.len(), 3, "should surface all 3 wide-spread victims");
        for s in &res {
            // Front gap > 1 across all three; backrun is at idx 200 so
            // back_gap is also large.
            assert!(s.victim.tx_index > s.frontrun.tx_index + 1);
            assert!(s.backrun.tx_index > s.victim.tx_index + 1);
            // compute_is_wide should flag every one of these.
            assert!(s.compute_is_wide(), "wide tx_index gaps must classify wide");
        }

        // Calling finalize_for_vigil sets attack_type to WideSandwich for
        // any detection where compute_is_wide() is true.
        let mut wide = res.into_iter().next().unwrap();
        wide.finalize_for_vigil();
        assert_eq!(wide.attack_type, Some(AttackType::WideSandwich));
        assert!(wide.is_wide_sandwich);
    }
}
