use std::collections::{HashMap, HashSet, VecDeque};

use swap_events::types::{DetectionEvidence, DetectionMethod, SandwichAttack, Signal, SwapEvent};

use crate::filters::{self, BundleLookup, FilterConfig, NoBundleLookup};
use crate::WindowDetector;

/// Swap event tagged with its slot, used in the per-pool ring buffer.
#[derive(Debug, Clone)]
struct TaggedSwap {
    slot: u64,
    swap: SwapEvent,
    /// Tx fee in lamports (if known).
    fee: u64,
}

/// Filtered cross-slot window detector.
///
/// Architecture:
///   - Per-pool ring buffer of swap events (window of W slots)
///   - On each new backrun candidate, scan the buffer for matching frontruns
///   - Apply 3 precision filters: bundle provenance, economic feasibility, victim plausibility
///   - Only emit candidates that pass all filters with sufficient confidence
///
/// This is the "v1 production" detector described in the algorithm spec.
pub struct FilteredWindowDetector {
    window_slots: usize,
    /// Per-pool ring buffer: pool_id -> deque of tagged swaps.
    buffers: HashMap<String, VecDeque<TaggedSwap>>,
    /// Track the latest slot seen, for eviction.
    latest_slot: u64,
    /// Already-emitted victim signatures (dedup).
    /// TODO: prune entries whose slot has left the window to bound memory in long-running mode.
    emitted: HashSet<String>,
    /// Filter configuration.
    config: FilterConfig,
    /// Bundle lookup (can be NoBundleLookup if Jito data unavailable).
    bundle_lookup: Box<dyn BundleLookup>,
    /// Known attacker wallets (for victim plausibility filter).
    known_attackers: HashSet<String>,
}

impl FilteredWindowDetector {
    pub fn new(window_slots: usize) -> Self {
        Self {
            window_slots,
            buffers: HashMap::new(),
            latest_slot: 0,
            emitted: HashSet::new(),
            config: FilterConfig::default(),
            bundle_lookup: Box::new(NoBundleLookup),
            known_attackers: HashSet::new(),
        }
    }

    pub fn with_config(mut self, config: FilterConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_bundle_lookup(mut self, lookup: Box<dyn BundleLookup>) -> Self {
        self.bundle_lookup = lookup;
        self
    }

    pub fn with_known_attackers(mut self, wallets: HashSet<String>) -> Self {
        self.known_attackers = wallets;
        self
    }

    /// Add a known attacker wallet at runtime (e.g., discovered from previous detections).
    pub fn add_known_attacker(&mut self, wallet: String) {
        self.known_attackers.insert(wallet);
    }

    /// Evict swap events from pools older than the window.
    fn evict_old(&mut self) {
        let cutoff = self
            .latest_slot
            .saturating_sub(self.window_slots.max(1) as u64 - 1);
        for buffer in self.buffers.values_mut() {
            while buffer.front().map(|s| s.slot < cutoff).unwrap_or(false) {
                buffer.pop_front();
            }
        }
        // Remove empty pools
        self.buffers.retain(|_, buf| !buf.is_empty());
    }

    /// Core detection: scan a pool's buffer for sandwich patterns, apply filters.
    fn detect_in_pool(&mut self, pool: &str) -> Vec<SandwichAttack> {
        let Some(buffer) = self.buffers.get(pool) else {
            return Vec::new();
        };

        let swaps: Vec<&TaggedSwap> = buffer.iter().collect();
        if swaps.len() < 2 {
            return Vec::new();
        }

        let mut results = Vec::new();

        // For each pair of swaps by the same signer with opposite directions
        // where the potential backrun is in a later slot (cross-slot only)
        for (i, front) in swaps.iter().enumerate() {
            for back in swaps.iter().skip(i + 1) {
                // Same signer (attacker)
                if front.swap.signer != back.swap.signer {
                    continue;
                }
                // Opposite directions
                if front.swap.direction == back.swap.direction {
                    continue;
                }
                // Must be cross-slot (same-slot handled by sameblock detector)
                if front.slot == back.slot {
                    continue;
                }

                // --- Filter 2: Economic feasibility ---
                let economic = filters::check_economic_feasibility(
                    &front.swap,
                    &back.swap,
                    front.fee,
                    back.fee,
                    &self.config,
                );

                // Check if front+back are co-bundled (skip econ check for known MEV bundles)
                let fb = self.bundle_lookup.bundle_for_tx(&front.swap.signature);
                let bb = self.bundle_lookup.bundle_for_tx(&back.swap.signature);
                let front_back_bundled = matches!((&fb, &bb), (Some(f), Some(b)) if f == b);

                if !economic.feasible && !front_back_bundled {
                    continue;
                }

                // Find victims between front and back
                for victim_tagged in &swaps {
                    // Temporal ordering: front < victim < back
                    if (victim_tagged.slot, victim_tagged.swap.tx_index)
                        <= (front.slot, front.swap.tx_index)
                    {
                        continue;
                    }
                    if (victim_tagged.slot, victim_tagged.swap.tx_index)
                        >= (back.slot, back.swap.tx_index)
                    {
                        continue;
                    }
                    // Different signer
                    if victim_tagged.swap.signer == front.swap.signer {
                        continue;
                    }
                    // Same direction as frontrun
                    if victim_tagged.swap.direction != front.swap.direction {
                        continue;
                    }
                    // Already emitted
                    if self.emitted.contains(&victim_tagged.swap.signature) {
                        continue;
                    }

                    // --- Filter 1 (refined): per-victim provenance ---
                    let victim_provenance = filters::classify_provenance(
                        &front.swap.signature,
                        &victim_tagged.swap.signature,
                        &back.swap.signature,
                        self.bundle_lookup.as_ref(),
                    );

                    // --- Filter 3: Victim plausibility ---
                    let victim_check = filters::check_victim_plausibility(
                        &front.swap,
                        &victim_tagged.swap,
                        &self.known_attackers,
                        &self.config,
                    );

                    if !victim_check.plausible {
                        continue;
                    }

                    // --- Confidence scoring ---
                    let confidence =
                        filters::compute_confidence(victim_provenance, &economic, &victim_check);

                    if confidence < self.config.min_confidence {
                        continue;
                    }

                    // Pick the most-informative bundle id for the evidence trace.
                    // For Atomic/Spanning, front and back share an id; for TipRace
                    // front has its own id; Organic has none. Using front's id
                    // (when present) covers all three non-organic cases.
                    let bundle_id = fb.clone();
                    let slot_distance = back.slot.saturating_sub(front.slot);
                    let evidence = DetectionEvidence::from_signals(vec![
                        Signal::CrossSlot { slot_distance },
                        Signal::Bundle {
                            provenance: victim_provenance,
                            bundle_id,
                        },
                        Signal::NaiveProfit {
                            gross: economic.gross_revenue,
                            cost: economic.estimated_cost,
                            net: economic.net_profit,
                        },
                        Signal::VictimSize {
                            ratio: victim_check.size_ratio,
                        },
                        Signal::KnownAttackerVictim {
                            is_known: victim_check.is_known_attacker,
                        },
                    ]);

                    let attack = SandwichAttack {
                        slot: victim_tagged.slot,
                        attacker: front.swap.signer.clone(),
                        frontrun: front.swap.clone(),
                        victim: victim_tagged.swap.clone(),
                        backrun: back.swap.clone(),
                        pool: front.swap.pool.clone(),
                        dex: front.swap.dex,
                        estimated_attacker_profit: Some(economic.gross_revenue),
                        victim_loss_lamports: None,
                        victim_loss_lamports_lower: None,
                        victim_loss_lamports_upper: None,
                        frontrun_slot: Some(front.slot),
                        backrun_slot: Some(back.slot),
                        detection_method: Some(DetectionMethod::CrossSlotWindow {
                            window_size: self.window_slots,
                        }),
                        bundle_provenance: Some(victim_provenance),
                        confidence: Some(confidence),
                        net_profit: Some(economic.net_profit),
                        attacker_profit: None,
                        price_impact_bps: None,
                        evidence: Some(evidence),
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
                    };

                    self.emitted.insert(victim_tagged.swap.signature.clone());
                    results.push(attack);
                }
            }
        }

        results
    }
}

impl WindowDetector for FilteredWindowDetector {
    fn ingest_slot(&mut self, slot: u64, swaps: Vec<SwapEvent>) -> Vec<SandwichAttack> {
        self.latest_slot = self.latest_slot.max(slot);

        // Track which pools got new data
        let mut affected_pools: HashSet<String> = HashSet::new();

        for swap in swaps {
            let pool = swap.pool.clone();
            let tagged = TaggedSwap {
                slot,
                fee: swap.fee.unwrap_or(5000),
                swap: SwapEvent {
                    slot: Some(slot),
                    ..swap
                },
            };
            self.buffers
                .entry(pool.clone())
                .or_default()
                .push_back(tagged);
            affected_pools.insert(pool);
        }

        self.evict_old();

        // Only scan pools that got new data
        let mut results = Vec::new();
        for pool in &affected_pools {
            results.extend(self.detect_in_pool(pool));
        }

        results
    }

    fn flush(&mut self) -> Vec<SandwichAttack> {
        let pools: Vec<String> = self.buffers.keys().cloned().collect();
        let mut results = Vec::new();
        for pool in &pools {
            results.extend(self.detect_in_pool(pool));
        }
        self.buffers.clear();
        results
    }

    fn window_size(&self) -> usize {
        self.window_slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_events::types::{DexType, SwapDirection};

    fn swap(sig: &str, signer: &str, pool: &str, dir: SwapDirection, idx: usize) -> SwapEvent {
        SwapEvent {
            signature: sig.into(),
            signer: signer.into(),
            dex: DexType::RaydiumV4,
            pool: pool.into(),
            direction: dir,
            token_mint: "Token".into(),
            amount_in: 1_000_000,
            amount_out: 900_000,
            tx_index: idx,
            slot: None,
            fee: None,
        }
    }

    #[test]
    fn filtered_detects_cross_slot() {
        let mut det = FilteredWindowDetector::new(4);

        det.ingest_slot(100, vec![swap("front", "atk", "p1", SwapDirection::Buy, 5)]);
        det.ingest_slot(
            101,
            vec![swap("victim", "vic", "p1", SwapDirection::Buy, 2)],
        );
        let results = det.ingest_slot(
            102,
            vec![{
                let mut s = swap("back", "atk", "p1", SwapDirection::Sell, 3);
                s.amount_out = 1_100_000; // profitable
                s
            }],
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].frontrun.signature, "front");
        assert_eq!(results[0].victim.signature, "victim");
        assert!(results[0].confidence.unwrap() > 0.0);
        assert!(results[0].net_profit.unwrap() > 0);
    }

    #[test]
    fn filtered_rejects_unprofitable() {
        let config = FilterConfig {
            min_net_profit: 0,
            ..Default::default()
        };
        let mut det = FilteredWindowDetector::new(4).with_config(config);

        det.ingest_slot(100, vec![swap("front", "atk", "p1", SwapDirection::Buy, 0)]);
        det.ingest_slot(
            101,
            vec![swap("victim", "vic", "p1", SwapDirection::Buy, 0)],
        );

        // Backrun gets LESS than frontrun spent — not profitable
        let results = det.ingest_slot(
            102,
            vec![{
                let mut s = swap("back", "atk", "p1", SwapDirection::Sell, 0);
                s.amount_out = 500_000; // loss
                s
            }],
        );

        assert!(
            results.is_empty(),
            "unprofitable candidates should be rejected"
        );
    }

    #[test]
    fn filtered_rejects_known_attacker_victim() {
        let attackers = HashSet::from(["atk_alt".to_string()]);
        let mut det = FilteredWindowDetector::new(4).with_known_attackers(attackers);

        det.ingest_slot(100, vec![swap("front", "atk", "p1", SwapDirection::Buy, 0)]);
        det.ingest_slot(
            101,
            vec![swap("victim", "atk_alt", "p1", SwapDirection::Buy, 0)],
        );
        let results = det.ingest_slot(
            102,
            vec![{
                let mut s = swap("back", "atk", "p1", SwapDirection::Sell, 0);
                s.amount_out = 1_100_000;
                s
            }],
        );

        assert!(
            results.is_empty(),
            "known attacker as victim should be rejected"
        );
    }

    #[test]
    fn filtered_skips_same_slot() {
        let mut det = FilteredWindowDetector::new(4);
        let results = det.ingest_slot(
            100,
            vec![
                swap("front", "atk", "p1", SwapDirection::Buy, 0),
                swap("victim", "vic", "p1", SwapDirection::Buy, 1),
                {
                    let mut s = swap("back", "atk", "p1", SwapDirection::Sell, 2);
                    s.amount_out = 1_100_000;
                    s
                },
            ],
        );
        assert!(
            results.is_empty(),
            "same-slot should be left to sameblock detector"
        );
    }

    #[test]
    fn filtered_with_bundle_provenance() {
        use crate::filters::MemoryBundleLookup;

        let mut tx_map = HashMap::new();
        tx_map.insert("front".into(), "bundle1".into());
        tx_map.insert("victim".into(), "bundle1".into());
        tx_map.insert("back".into(), "bundle1".into());
        let lookup = MemoryBundleLookup {
            tx_to_bundle: tx_map,
        };

        let mut det = FilteredWindowDetector::new(4).with_bundle_lookup(Box::new(lookup));

        det.ingest_slot(100, vec![swap("front", "atk", "p1", SwapDirection::Buy, 0)]);
        det.ingest_slot(
            101,
            vec![swap("victim", "vic", "p1", SwapDirection::Buy, 0)],
        );
        let results = det.ingest_slot(
            102,
            vec![{
                let mut s = swap("back", "atk", "p1", SwapDirection::Sell, 0);
                s.amount_out = 1_100_000;
                s
            }],
        );

        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].bundle_provenance,
            Some(swap_events::types::BundleProvenance::AtomicBundle)
        );
        // Atomic bundle should have high confidence
        assert!(results[0].confidence.unwrap() > 0.6);
    }

    #[test]
    fn evidence_structure_cross_slot() {
        use swap_events::types::Signal;

        let mut det = FilteredWindowDetector::new(4);
        det.ingest_slot(100, vec![swap("front", "atk", "p1", SwapDirection::Buy, 5)]);
        det.ingest_slot(
            101,
            vec![swap("victim", "vic", "p1", SwapDirection::Buy, 2)],
        );
        let results = det.ingest_slot(
            102,
            vec![{
                let mut s = swap("back", "atk", "p1", SwapDirection::Sell, 3);
                s.amount_out = 1_100_000; // profitable
                s
            }],
        );

        assert_eq!(results.len(), 1);
        let ev = results[0].evidence.as_ref().expect("evidence attached");

        // Cross-slot path should produce CrossSlot (temporal), NaiveProfit
        // (economic), VictimSize / KnownAttackerVictim (plausibility), and
        // Bundle (provenance = Organic → informational).
        let passing_kinds: Vec<&str> = ev
            .passing
            .iter()
            .map(|s| match s {
                Signal::CrossSlot { .. } => "CrossSlot",
                Signal::NaiveProfit { .. } => "NaiveProfit",
                Signal::VictimSize { .. } => "VictimSize",
                Signal::KnownAttackerVictim { .. } => "KnownAttackerVictim",
                Signal::Bundle { .. } => "Bundle",
                _ => "other",
            })
            .collect();
        assert!(passing_kinds.contains(&"CrossSlot"));
        assert!(passing_kinds.contains(&"NaiveProfit"));
        assert!(passing_kinds.contains(&"VictimSize"));
        // Temporal + Economic + Plausibility categories should all be counted.
        assert!(
            ev.categories_fired >= 3,
            "expected ≥3 categories, got {}",
            ev.categories_fired
        );

        // CrossSlot carries slot_distance = 102 - 100 = 2.
        for s in &ev.passing {
            if let Signal::CrossSlot { slot_distance } = s {
                assert_eq!(*slot_distance, 2);
            }
        }
    }

    #[test]
    fn per_pool_isolation() {
        let mut det = FilteredWindowDetector::new(4);

        det.ingest_slot(
            100,
            vec![swap("f1", "atk", "pool_A", SwapDirection::Buy, 0)],
        );
        det.ingest_slot(
            101,
            vec![swap("v1", "vic", "pool_B", SwapDirection::Buy, 0)],
        ); // wrong pool
        let results = det.ingest_slot(
            102,
            vec![{
                let mut s = swap("b1", "atk", "pool_A", SwapDirection::Sell, 0);
                s.amount_out = 1_100_000;
                s
            }],
        );

        assert!(
            results.is_empty(),
            "victim on different pool should not match"
        );
    }

    #[test]
    fn no_self_population_of_known_attackers() {
        // After detecting a sandwich, the attacker should NOT be auto-added
        // to known_attackers. A normal swap by the same signer in another pool
        // should still be eligible as a victim.
        let mut det = FilteredWindowDetector::new(4);

        // First sandwich: atk attacks in pool_A
        det.ingest_slot(
            100,
            vec![swap("f1", "atk", "pool_A", SwapDirection::Buy, 0)],
        );
        det.ingest_slot(
            101,
            vec![swap("v1", "vic", "pool_A", SwapDirection::Buy, 0)],
        );
        let r1 = det.ingest_slot(
            102,
            vec![{
                let mut s = swap("b1", "atk", "pool_A", SwapDirection::Sell, 0);
                s.amount_out = 1_100_000;
                s
            }],
        );
        assert_eq!(r1.len(), 1, "first sandwich should be detected");

        // Second sandwich in pool_B: atk is the VICTIM of a different attacker
        det.ingest_slot(
            103,
            vec![swap("f2", "atk2", "pool_B", SwapDirection::Buy, 0)],
        );
        det.ingest_slot(
            104,
            vec![swap("v2", "atk", "pool_B", SwapDirection::Buy, 0)],
        );
        let r2 = det.ingest_slot(
            105,
            vec![{
                let mut s = swap("b2", "atk2", "pool_B", SwapDirection::Sell, 0);
                s.amount_out = 1_100_000;
                s
            }],
        );
        assert_eq!(
            r2.len(),
            1,
            "atk as victim should not be rejected by self-population"
        );
    }

    #[test]
    fn deterministic_results() {
        // Running the same data through two fresh detectors must yield identical results
        let run = || {
            let mut det = FilteredWindowDetector::new(4);
            det.ingest_slot(100, vec![swap("f", "atk", "p1", SwapDirection::Buy, 0)]);
            det.ingest_slot(101, vec![swap("v", "vic", "p1", SwapDirection::Buy, 0)]);
            det.ingest_slot(
                102,
                vec![{
                    let mut s = swap("b", "atk", "p1", SwapDirection::Sell, 0);
                    s.amount_out = 1_100_000;
                    s
                }],
            )
        };

        let r1 = run();
        let r2 = run();
        assert_eq!(r1.len(), r2.len());
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.victim.signature, b.victim.signature);
            assert_eq!(a.confidence, b.confidence);
        }
    }

    #[test]
    fn filtered_window_eviction() {
        // Mirrors naive::tests::window_eviction — window=2 should keep exactly 2 slots
        let mut det = FilteredWindowDetector::new(2);

        det.ingest_slot(100, vec![swap("front", "atk", "p1", SwapDirection::Buy, 0)]);
        det.ingest_slot(
            101,
            vec![swap("victim", "vic", "p1", SwapDirection::Buy, 0)],
        );
        // Slot 102: window=2 means keep {101,102}, evict 100
        let results = det.ingest_slot(
            102,
            vec![{
                let mut s = swap("back", "atk", "p1", SwapDirection::Sell, 0);
                s.amount_out = 1_100_000;
                s
            }],
        );
        assert!(
            results.is_empty(),
            "frontrun at slot 100 should be evicted with window=2"
        );
    }

    #[test]
    fn bundled_front_back_skips_econ_check() {
        use crate::filters::MemoryBundleLookup;

        // Front and back are in the same bundle, but backrun is unprofitable
        let mut tx_map = HashMap::new();
        tx_map.insert("front".into(), "bundle1".into());
        tx_map.insert("back".into(), "bundle1".into());
        let lookup = MemoryBundleLookup {
            tx_to_bundle: tx_map,
        };

        let mut det = FilteredWindowDetector::new(4).with_bundle_lookup(Box::new(lookup));

        det.ingest_slot(100, vec![swap("front", "atk", "p1", SwapDirection::Buy, 0)]);
        det.ingest_slot(
            101,
            vec![swap("victim", "vic", "p1", SwapDirection::Buy, 0)],
        );
        let results = det.ingest_slot(
            102,
            vec![{
                let mut s = swap("back", "atk", "p1", SwapDirection::Sell, 0);
                s.amount_out = 500_000; // unprofitable
                s
            }],
        );

        // Should still detect because front+back are co-bundled (econ check bypassed)
        assert_eq!(
            results.len(),
            1,
            "co-bundled front+back should bypass economic check"
        );
    }
}
