use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use swap_events::types::SandwichAttack;

use crate::labels::LabeledExample;

/// Evaluation result for a detector run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResult {
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub true_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    /// Per-example details for debugging.
    pub details: Vec<ExampleResult>,
}

/// Result for a single labeled example.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleResult {
    pub label_id: String,
    pub expected: bool,
    pub detected: bool,
    pub match_type: MatchType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    TruePositive,
    FalsePositive,
    FalseNegative,
    TrueNegative,
}

/// Match detector output against labeled examples.
///
/// Matching strategy: a detector output matches a label if the victim tx
/// signature matches. The victim is the unique anchor because:
/// - A given victim is either sandwiched or not — no ambiguity
/// - The attacker may use fresh wallets per attack
/// - Pool + slot + victim_sig is a unique triplet
pub fn evaluate(labels: &[LabeledExample], detections: &[SandwichAttack]) -> EvalResult {
    // Build set of detected victim signatures for fast lookup
    let detected_victims: HashSet<&str> = detections
        .iter()
        .map(|d| d.victim.signature.as_str())
        .collect();

    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut r#fn = 0usize;
    let mut tn = 0usize;
    let mut details = Vec::new();

    // Check each label against detections
    for label in labels {
        let was_detected = detected_victims.contains(label.tx_signatures.victim.as_str());

        let (match_type, expected, detected) = match (label.is_sandwich, was_detected) {
            (true, true) => {
                tp += 1;
                (MatchType::TruePositive, true, true)
            }
            (true, false) => {
                r#fn += 1;
                (MatchType::FalseNegative, true, false)
            }
            (false, true) => {
                fp += 1;
                (MatchType::FalsePositive, false, true)
            }
            (false, false) => {
                tn += 1;
                (MatchType::TrueNegative, false, false)
            }
        };

        details.push(ExampleResult {
            label_id: label.id.clone(),
            expected,
            detected,
            match_type,
        });
    }

    // Also count detections that don't match any label as FP
    let labeled_victims: HashSet<&str> = labels
        .iter()
        .map(|l| l.tx_signatures.victim.as_str())
        .collect();

    let unlabeled_detections = detections
        .iter()
        .filter(|d| !labeled_victims.contains(d.victim.signature.as_str()))
        .count();
    fp += unlabeled_detections;

    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };

    let recall = if tp + r#fn > 0 {
        tp as f64 / (tp + r#fn) as f64
    } else {
        0.0
    };

    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    EvalResult {
        true_positives: tp,
        false_positives: fp,
        false_negatives: r#fn,
        true_negatives: tn,
        precision,
        recall,
        f1,
        details,
    }
}

impl std::fmt::Display for EvalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Evaluation Results")?;
        writeln!(
            f,
            "  TP: {}  FP: {}  FN: {}  TN: {}",
            self.true_positives, self.false_positives, self.false_negatives, self.true_negatives
        )?;
        writeln!(f, "  Precision: {:.1}%", self.precision * 100.0)?;
        writeln!(f, "  Recall:    {:.1}%", self.recall * 100.0)?;
        writeln!(f, "  F1:        {:.1}%", self.f1 * 100.0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::{LabelProvenance, SandwichTxSigs};
    use chrono::Utc;
    use swap_events::types::{DexType, SwapDirection, SwapEvent};

    fn make_label(id: &str, victim_sig: &str, is_sandwich: bool) -> LabeledExample {
        LabeledExample {
            id: id.into(),
            slot: 100,
            tx_signatures: SandwichTxSigs {
                frontrun: "front".into(),
                victim: victim_sig.into(),
                backrun: "back".into(),
            },
            pool: "pool".into(),
            is_sandwich,
            attacker_wallets: vec![],
            provenance: LabelProvenance::HandLabeled,
            notes: String::new(),
            labeled_at: Utc::now(),
            labeled_by: "test".into(),
        }
    }

    fn make_detection(victim_sig: &str) -> SandwichAttack {
        let swap = |sig: &str| SwapEvent {
            signature: sig.into(),
            signer: "atk".into(),
            dex: DexType::RaydiumV4,
            pool: "pool".into(),
            direction: SwapDirection::Buy,
            token_mint: "token".into(),
            amount_in: 100,
            amount_out: 90,
            tx_index: 0,
            slot: None,
            fee: None,
        };

        SandwichAttack {
            slot: 100,
            attacker: "atk".into(),
            frontrun: swap("front"),
            victim: swap(victim_sig),
            backrun: {
                let mut s = swap("back");
                s.direction = SwapDirection::Sell;
                s
            },
            pool: "pool".into(),
            dex: DexType::RaydiumV4,
            estimated_attacker_profit: Some(10),
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

    #[test]
    fn perfect_detection() {
        let labels = vec![make_label("l1", "victim1", true)];
        let detections = vec![make_detection("victim1")];
        let result = evaluate(&labels, &detections);
        assert_eq!(result.true_positives, 1);
        assert_eq!(result.false_positives, 0);
        assert_eq!(result.false_negatives, 0);
        assert!((result.precision - 1.0).abs() < f64::EPSILON);
        assert!((result.recall - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn missed_sandwich() {
        let labels = vec![make_label("l1", "victim1", true)];
        let detections = vec![];
        let result = evaluate(&labels, &detections);
        assert_eq!(result.true_positives, 0);
        assert_eq!(result.false_negatives, 1);
        assert!((result.recall - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn false_positive_detection() {
        let labels = vec![make_label("l1", "victim1", false)];
        let detections = vec![make_detection("victim1")];
        let result = evaluate(&labels, &detections);
        assert_eq!(result.false_positives, 1);
        assert_eq!(result.true_negatives, 0);
    }

    #[test]
    fn true_negative() {
        let labels = vec![make_label("l1", "victim1", false)];
        let detections = vec![];
        let result = evaluate(&labels, &detections);
        assert_eq!(result.true_negatives, 1);
    }

    #[test]
    fn mixed_results() {
        let labels = vec![
            make_label("l1", "v1", true),
            make_label("l2", "v2", true),
            make_label("l3", "v3", false),
        ];
        let detections = vec![
            make_detection("v1"), // TP
                                  // v2 missed -> FN
                                  // v3 not detected -> TN
        ];
        let result = evaluate(&labels, &detections);
        assert_eq!(result.true_positives, 1);
        assert_eq!(result.false_negatives, 1);
        assert_eq!(result.true_negatives, 1);
        assert_eq!(result.false_positives, 0);
        assert!((result.precision - 1.0).abs() < f64::EPSILON);
        assert!((result.recall - 0.5).abs() < f64::EPSILON);
    }
}
