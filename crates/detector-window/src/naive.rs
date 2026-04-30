use std::collections::{HashMap, HashSet, VecDeque};

use swap_events::types::{DetectionEvidence, DetectionMethod, SandwichAttack, Signal, SwapEvent};

use crate::WindowDetector;

/// Naive cross-slot window detector.
///
/// Uses a sliding window of N slots and same-signer heuristic:
/// - Groups swaps by (signer, pool) across the window
/// - Finds opposite-direction pairs (frontrun in slot A, backrun in slot B)
/// - Looks for victim swaps on the same pool between them
///
/// This is a baseline with high precision (same-signer constraint)
/// but limited recall (misses multi-wallet attackers).
pub struct NaiveWindowDetector {
    window_slots: usize,
    slot_buffer: VecDeque<(u64, Vec<SwapEvent>)>,
    /// Track already-emitted sandwiches by victim signature to avoid duplicates.
    emitted: HashSet<String>,
}

impl NaiveWindowDetector {
    pub fn new(window_slots: usize) -> Self {
        Self {
            window_slots,
            slot_buffer: VecDeque::new(),
            emitted: HashSet::new(),
        }
    }

    fn detect_in_window(&mut self) -> Vec<SandwichAttack> {
        // Flatten all swaps, tagging each with its slot
        let all_swaps: Vec<(u64, &SwapEvent)> = self
            .slot_buffer
            .iter()
            .flat_map(|(slot, swaps)| swaps.iter().map(move |s| (*slot, s)))
            .collect();

        // Group by (signer, pool) — the attacker identity key
        let mut groups: HashMap<(&str, &str), Vec<(u64, &SwapEvent)>> = HashMap::new();
        for (slot, swap) in &all_swaps {
            groups
                .entry((swap.signer.as_str(), swap.pool.as_str()))
                .or_default()
                .push((*slot, swap));
        }

        let mut results = Vec::new();

        for ((_signer, pool), attacker_swaps) in &groups {
            if attacker_swaps.len() < 2 {
                continue;
            }

            // Sort by (slot, tx_index) for temporal ordering
            let mut sorted = attacker_swaps.clone();
            sorted.sort_by_key(|(slot, swap)| (*slot, swap.tx_index));

            // Find opposite-direction pairs (potential frontrun/backrun)
            for (i, (front_slot, frontrun)) in sorted.iter().enumerate() {
                for (back_slot, backrun) in sorted.iter().skip(i + 1) {
                    // Must be opposite directions
                    if frontrun.direction == backrun.direction {
                        continue;
                    }

                    // Skip same-slot pairs (handled by sameblock detector)
                    if front_slot == back_slot {
                        continue;
                    }

                    // Find victims: swaps on the same pool, different signer,
                    // same direction as frontrun, temporally between front and back
                    let victims: Vec<(u64, &SwapEvent)> = all_swaps
                        .iter()
                        .filter(|(v_slot, v_swap)| {
                            v_swap.pool == *pool
                                && v_swap.signer != frontrun.signer
                                && v_swap.direction == frontrun.direction
                                && is_between(
                                    (*front_slot, frontrun.tx_index),
                                    (*v_slot, v_swap.tx_index),
                                    (*back_slot, backrun.tx_index),
                                )
                        })
                        .cloned()
                        .collect();

                    for (victim_slot, victim) in &victims {
                        // Skip if already emitted
                        if self.emitted.contains(&victim.signature) {
                            continue;
                        }

                        let gross = backrun.amount_out as i64 - frontrun.amount_in as i64;
                        let cost = frontrun.fee.map(|f| f as i64).unwrap_or(0)
                            + backrun.fee.map(|f| f as i64).unwrap_or(0);
                        let net = gross - cost;
                        let slot_distance = back_slot.saturating_sub(*front_slot);
                        let evidence = DetectionEvidence::from_signals(vec![
                            Signal::CrossSlot { slot_distance },
                            Signal::NaiveProfit { gross, cost, net },
                        ]);
                        let attack = SandwichAttack {
                            slot: *victim_slot,
                            attacker: frontrun.signer.clone(),
                            frontrun: (*frontrun).clone(),
                            victim: (*victim).clone(),
                            backrun: (*backrun).clone(),
                            pool: frontrun.pool.clone(),
                            dex: frontrun.dex,
                            estimated_attacker_profit: Some(gross),
                            victim_loss_lamports: None,
                            victim_loss_lamports_lower: None,
                            victim_loss_lamports_upper: None,
                            frontrun_slot: Some(*front_slot),
                            backrun_slot: Some(*back_slot),
                            detection_method: Some(DetectionMethod::CrossSlotWindow {
                                window_size: self.window_slots,
                            }),
                            bundle_provenance: None,
                            confidence: None,
                            net_profit: Some(net),
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

                        self.emitted.insert(victim.signature.clone());
                        results.push(attack);
                    }
                }
            }
        }

        results
    }
}

/// Check if victim is temporally between frontrun and backrun.
fn is_between(front: (u64, usize), victim: (u64, usize), back: (u64, usize)) -> bool {
    // Strict temporal ordering: front < victim < back
    (front.0, front.1) < (victim.0, victim.1) && (victim.0, victim.1) < (back.0, back.1)
}

impl WindowDetector for NaiveWindowDetector {
    fn ingest_slot(&mut self, slot: u64, swaps: Vec<SwapEvent>) -> Vec<SandwichAttack> {
        // Tag swaps with their slot
        let tagged: Vec<SwapEvent> = swaps
            .into_iter()
            .map(|mut s| {
                s.slot = Some(slot);
                s
            })
            .collect();

        self.slot_buffer.push_back((slot, tagged));

        // Evict old slots
        while self.slot_buffer.len() > self.window_slots {
            self.slot_buffer.pop_front();
        }

        self.detect_in_window()
    }

    fn flush(&mut self) -> Vec<SandwichAttack> {
        let results = self.detect_in_window();
        self.slot_buffer.clear();
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
    fn detects_cross_slot_sandwich() {
        let mut detector = NaiveWindowDetector::new(4);

        // Slot 100: attacker buys
        let results = detector.ingest_slot(
            100,
            vec![swap("front", "atk", "pool1", SwapDirection::Buy, 5)],
        );
        assert!(results.is_empty());

        // Slot 101: victim buys on same pool
        let results = detector.ingest_slot(
            101,
            vec![swap("victim", "vic", "pool1", SwapDirection::Buy, 2)],
        );
        assert!(results.is_empty());

        // Slot 102: attacker sells (completes the sandwich)
        let results = detector.ingest_slot(
            102,
            vec![swap("back", "atk", "pool1", SwapDirection::Sell, 3)],
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].frontrun.signature, "front");
        assert_eq!(results[0].victim.signature, "victim");
        assert_eq!(results[0].backrun.signature, "back");
        assert_eq!(results[0].frontrun_slot, Some(100));
        assert_eq!(results[0].backrun_slot, Some(102));
    }

    #[test]
    fn skips_same_slot_pairs() {
        let mut detector = NaiveWindowDetector::new(4);

        // All in same slot — should NOT be detected (that's sameblock's job)
        let results = detector.ingest_slot(
            100,
            vec![
                swap("front", "atk", "pool1", SwapDirection::Buy, 0),
                swap("victim", "vic", "pool1", SwapDirection::Buy, 1),
                swap("back", "atk", "pool1", SwapDirection::Sell, 2),
            ],
        );
        assert!(results.is_empty());
    }

    #[test]
    fn window_eviction() {
        let mut detector = NaiveWindowDetector::new(2);

        // Slot 100: frontrun
        detector.ingest_slot(
            100,
            vec![swap("front", "atk", "pool1", SwapDirection::Buy, 0)],
        );
        // Slot 101: victim
        detector.ingest_slot(
            101,
            vec![swap("victim", "vic", "pool1", SwapDirection::Buy, 0)],
        );
        // Slot 102: evicts slot 100 (window=2), backrun can't pair
        let results = detector.ingest_slot(
            102,
            vec![swap("back", "atk", "pool1", SwapDirection::Sell, 0)],
        );
        // frontrun was evicted, so no sandwich
        assert!(results.is_empty());
    }

    #[test]
    fn no_sandwich_different_pools() {
        let mut detector = NaiveWindowDetector::new(4);

        detector.ingest_slot(
            100,
            vec![swap("front", "atk", "pool1", SwapDirection::Buy, 0)],
        );
        detector.ingest_slot(
            101,
            vec![swap("victim", "vic", "pool2", SwapDirection::Buy, 0)],
        );
        let results = detector.ingest_slot(
            102,
            vec![swap("back", "atk", "pool1", SwapDirection::Sell, 0)],
        );
        // victim is on a different pool
        assert!(results.is_empty());
    }

    #[test]
    fn multiple_victims_cross_slot() {
        let mut detector = NaiveWindowDetector::new(4);

        detector.ingest_slot(
            100,
            vec![swap("front", "atk", "pool1", SwapDirection::Buy, 0)],
        );
        detector.ingest_slot(
            101,
            vec![
                swap("v1", "vic1", "pool1", SwapDirection::Buy, 0),
                swap("v2", "vic2", "pool1", SwapDirection::Buy, 1),
            ],
        );
        let results = detector.ingest_slot(
            102,
            vec![swap("back", "atk", "pool1", SwapDirection::Sell, 0)],
        );
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn deduplication() {
        let mut detector = NaiveWindowDetector::new(4);

        detector.ingest_slot(
            100,
            vec![swap("front", "atk", "pool1", SwapDirection::Buy, 0)],
        );
        detector.ingest_slot(
            101,
            vec![swap("victim", "vic", "pool1", SwapDirection::Buy, 0)],
        );

        // First detection
        let r1 = detector.ingest_slot(
            102,
            vec![swap("back", "atk", "pool1", SwapDirection::Sell, 0)],
        );
        assert_eq!(r1.len(), 1);

        // Ingesting another slot should not re-emit the same victim
        let r2 = detector.ingest_slot(103, vec![]);
        assert!(r2.is_empty());
    }
}
