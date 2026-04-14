use std::collections::{HashMap, HashSet};

use swap_events::types::{BundleProvenance, SwapEvent};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the precision filters.
#[derive(Debug, Clone)]
pub struct FilterConfig {
    /// Minimum net profit (lamports) to pass economic feasibility.
    /// Candidates with net < this are rejected.
    pub min_net_profit: i64,
    /// Minimum victim swap amount_in relative to frontrun amount_in.
    /// E.g. 0.01 = victim must be at least 1% of frontrun size.
    pub min_victim_ratio: f64,
    /// Minimum confidence score to emit a detection.
    /// Note: with NoBundleLookup, Organic provenance contributes a floor of 0.10.
    /// Setting this below 0.10 effectively disables confidence filtering.
    pub min_confidence: f64,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            min_net_profit: 0,
            min_victim_ratio: 0.01,
            min_confidence: 0.30,
        }
    }
}

// ---------------------------------------------------------------------------
// Filter 1: Jito Bundle Provenance
// ---------------------------------------------------------------------------

/// Trait for looking up which bundle a transaction belongs to.
/// Implementations can back this with cached Jito API data.
pub trait BundleLookup: Send + Sync {
    /// Return the bundle ID containing this tx signature, if any.
    fn bundle_for_tx(&self, tx_sig: &str) -> Option<String>;
}

/// No-op bundle lookup (when Jito data is unavailable).
pub struct NoBundleLookup;

impl BundleLookup for NoBundleLookup {
    fn bundle_for_tx(&self, _tx_sig: &str) -> Option<String> {
        None
    }
}

/// In-memory bundle lookup backed by a pre-fetched map.
pub struct MemoryBundleLookup {
    /// tx_signature -> bundle_id
    pub tx_to_bundle: HashMap<String, String>,
}

impl BundleLookup for MemoryBundleLookup {
    fn bundle_for_tx(&self, tx_sig: &str) -> Option<String> {
        self.tx_to_bundle.get(tx_sig).cloned()
    }
}

/// Classify a (frontrun, victim, backrun) triplet by bundle provenance.
pub fn classify_provenance(
    frontrun_sig: &str,
    victim_sig: &str,
    backrun_sig: &str,
    lookup: &dyn BundleLookup,
) -> BundleProvenance {
    let front_bundle = lookup.bundle_for_tx(frontrun_sig);
    let victim_bundle = lookup.bundle_for_tx(victim_sig);
    let back_bundle = lookup.bundle_for_tx(backrun_sig);

    match (&front_bundle, &victim_bundle, &back_bundle) {
        // All three in the same bundle
        (Some(fb), Some(vb), Some(bb)) if fb == vb && vb == bb => {
            BundleProvenance::AtomicBundle
        }
        // Front and back in the same bundle, victim separate
        (Some(fb), _, Some(bb)) if fb == bb => {
            BundleProvenance::SpanningBundle
        }
        // All in bundles but different ones
        (Some(_), _, Some(_)) => {
            BundleProvenance::TipRace
        }
        // Any tx not in a bundle
        _ => BundleProvenance::Organic,
    }
}

// ---------------------------------------------------------------------------
// Filter 2: Economic Feasibility
// ---------------------------------------------------------------------------

/// Economic feasibility check result.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EconomicResult {
    /// Gross revenue: backrun.amount_out - frontrun.amount_in
    pub gross_revenue: i64,
    /// Estimated cost: frontrun fee + backrun fee (+ tip if known)
    pub estimated_cost: i64,
    /// Net profit: gross_revenue - estimated_cost
    pub net_profit: i64,
    /// Whether this passes the feasibility threshold.
    pub feasible: bool,
}

/// Check if a sandwich candidate is economically feasible.
///
/// Revenue = backrun.amount_out - frontrun.amount_in (same token, simplified).
/// Cost = sum of tx fees (conservative lower bound; tip not always available).
///
/// For multi-hop or cross-token cases, this is approximate. Exact calculation
/// requires pool state replay (v2).
pub fn check_economic_feasibility(
    frontrun: &SwapEvent,
    backrun: &SwapEvent,
    frontrun_fee: u64,
    backrun_fee: u64,
    config: &FilterConfig,
) -> EconomicResult {
    let gross_revenue = backrun.amount_out as i64 - frontrun.amount_in as i64;
    let estimated_cost = (frontrun_fee + backrun_fee) as i64;
    let net_profit = gross_revenue - estimated_cost;
    let feasible = net_profit >= config.min_net_profit;

    EconomicResult {
        gross_revenue,
        estimated_cost,
        net_profit,
        feasible,
    }
}

// ---------------------------------------------------------------------------
// Filter 3: Victim Plausibility
// ---------------------------------------------------------------------------

/// Victim plausibility check result.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct VictimResult {
    /// Ratio of victim swap size to frontrun swap size.
    pub size_ratio: f64,
    /// Whether victim is in the known attacker wallet set.
    pub is_known_attacker: bool,
    /// Whether this victim passes plausibility checks.
    pub plausible: bool,
}

/// Check if a victim candidate is plausible.
///
/// Conditions:
/// (a) Victim swap size must be meaningful relative to frontrun
///     (if victim is 0.01x the frontrun, any "loss" is noise).
/// (b) Victim must not be a known attacker wallet.
pub fn check_victim_plausibility(
    frontrun: &SwapEvent,
    victim: &SwapEvent,
    known_attacker_wallets: &HashSet<String>,
    config: &FilterConfig,
) -> VictimResult {
    // (a) Size ratio: victim.amount_in / frontrun.amount_in
    let size_ratio = if frontrun.amount_in > 0 {
        victim.amount_in as f64 / frontrun.amount_in as f64
    } else {
        0.0
    };

    // (b) Not a known attacker
    let is_known_attacker = known_attacker_wallets.contains(&victim.signer);

    let plausible = size_ratio >= config.min_victim_ratio && !is_known_attacker;

    VictimResult {
        size_ratio,
        is_known_attacker,
        plausible,
    }
}

// ---------------------------------------------------------------------------
// Confidence scoring
// ---------------------------------------------------------------------------

/// Compute composite confidence score from all filter results.
///
/// Weights:
///   provenance: 50% (bundle relationship is strongest signal)
///   economic:   30% (net profit confirms intent)
///   victim:     20% (plausibility is a sanity check)
pub fn compute_confidence(
    provenance: BundleProvenance,
    economic: &EconomicResult,
    victim: &VictimResult,
) -> f64 {
    let prov_score = provenance.confidence_weight();

    let econ_score = if economic.feasible {
        // Scale by profit magnitude (diminishing returns)
        let profit_factor = (economic.net_profit.max(0) as f64).ln_1p() / 25.0;
        (0.5 + profit_factor).min(1.0)
    } else {
        0.0
    };

    let victim_score = if victim.plausible {
        // Scale by size ratio (bigger victim = more confidence)
        (victim.size_ratio.min(10.0) / 10.0 * 0.5 + 0.5).min(1.0)
    } else {
        0.0
    };

    prov_score * 0.50 + econ_score * 0.30 + victim_score * 0.20
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_atomic() {
        let mut map = HashMap::new();
        map.insert("f".into(), "b1".into());
        map.insert("v".into(), "b1".into());
        map.insert("b".into(), "b1".into());
        let lookup = MemoryBundleLookup { tx_to_bundle: map };
        assert_eq!(classify_provenance("f", "v", "b", &lookup), BundleProvenance::AtomicBundle);
    }

    #[test]
    fn provenance_spanning() {
        let mut map = HashMap::new();
        map.insert("f".into(), "b1".into());
        map.insert("b".into(), "b1".into());
        // victim not in any bundle
        let lookup = MemoryBundleLookup { tx_to_bundle: map };
        assert_eq!(classify_provenance("f", "v", "b", &lookup), BundleProvenance::SpanningBundle);
    }

    #[test]
    fn provenance_tip_race() {
        let mut map = HashMap::new();
        map.insert("f".into(), "b1".into());
        map.insert("v".into(), "b2".into());
        map.insert("b".into(), "b3".into());
        let lookup = MemoryBundleLookup { tx_to_bundle: map };
        assert_eq!(classify_provenance("f", "v", "b", &lookup), BundleProvenance::TipRace);
    }

    #[test]
    fn provenance_organic() {
        let lookup = NoBundleLookup;
        assert_eq!(classify_provenance("f", "v", "b", &lookup), BundleProvenance::Organic);
    }

    #[test]
    fn economic_feasible() {
        use swap_events::types::{DexType, SwapDirection};
        let front = SwapEvent {
            signature: "f".into(), signer: "atk".into(), dex: DexType::RaydiumV4,
            pool: "p".into(), direction: SwapDirection::Buy, token_mint: "t".into(),
            amount_in: 5_000_000_000, amount_out: 1_000_000, tx_index: 0, slot: None, fee: None,
        };
        let back = SwapEvent {
            signature: "b".into(), signer: "atk".into(), dex: DexType::RaydiumV4,
            pool: "p".into(), direction: SwapDirection::Sell, token_mint: "t".into(),
            amount_in: 1_000_000, amount_out: 5_200_000_000, tx_index: 2, slot: None, fee: None,
        };
        let config = FilterConfig::default();
        let result = check_economic_feasibility(&front, &back, 5000, 5000, &config);
        assert!(result.feasible);
        assert_eq!(result.net_profit, 200_000_000 - 10_000);
    }

    #[test]
    fn economic_not_feasible() {
        use swap_events::types::{DexType, SwapDirection};
        let front = SwapEvent {
            signature: "f".into(), signer: "atk".into(), dex: DexType::RaydiumV4,
            pool: "p".into(), direction: SwapDirection::Buy, token_mint: "t".into(),
            amount_in: 5_000_000_000, amount_out: 100, tx_index: 0, slot: None, fee: None,
        };
        let back = SwapEvent {
            signature: "b".into(), signer: "atk".into(), dex: DexType::RaydiumV4,
            pool: "p".into(), direction: SwapDirection::Sell, token_mint: "t".into(),
            amount_in: 100, amount_out: 4_900_000_000, tx_index: 2, slot: None, fee: None,
        };
        let config = FilterConfig::default();
        let result = check_economic_feasibility(&front, &back, 5000, 5000, &config);
        assert!(!result.feasible); // lost 100M lamports
    }

    #[test]
    fn victim_plausible() {
        use swap_events::types::{DexType, SwapDirection};
        let front = SwapEvent {
            signature: "f".into(), signer: "atk".into(), dex: DexType::RaydiumV4,
            pool: "p".into(), direction: SwapDirection::Buy, token_mint: "t".into(),
            amount_in: 1_000_000, amount_out: 100, tx_index: 0, slot: None, fee: None,
        };
        let victim = SwapEvent {
            signature: "v".into(), signer: "vic".into(), dex: DexType::RaydiumV4,
            pool: "p".into(), direction: SwapDirection::Buy, token_mint: "t".into(),
            amount_in: 500_000, amount_out: 50, tx_index: 1, slot: None, fee: None,
        };
        let config = FilterConfig::default();
        let result = check_victim_plausibility(&front, &victim, &HashSet::new(), &config);
        assert!(result.plausible);
        assert!((result.size_ratio - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn victim_is_attacker() {
        use swap_events::types::{DexType, SwapDirection};
        let front = SwapEvent {
            signature: "f".into(), signer: "atk".into(), dex: DexType::RaydiumV4,
            pool: "p".into(), direction: SwapDirection::Buy, token_mint: "t".into(),
            amount_in: 1_000_000, amount_out: 100, tx_index: 0, slot: None, fee: None,
        };
        let victim = SwapEvent {
            signature: "v".into(), signer: "atk_alt".into(), dex: DexType::RaydiumV4,
            pool: "p".into(), direction: SwapDirection::Buy, token_mint: "t".into(),
            amount_in: 500_000, amount_out: 50, tx_index: 1, slot: None, fee: None,
        };
        let known = HashSet::from(["atk_alt".to_string()]);
        let config = FilterConfig::default();
        let result = check_victim_plausibility(&front, &victim, &known, &config);
        assert!(!result.plausible);
    }

    #[test]
    fn victim_too_small() {
        use swap_events::types::{DexType, SwapDirection};
        let front = SwapEvent {
            signature: "f".into(), signer: "atk".into(), dex: DexType::RaydiumV4,
            pool: "p".into(), direction: SwapDirection::Buy, token_mint: "t".into(),
            amount_in: 10_000_000_000, amount_out: 100, tx_index: 0, slot: None, fee: None,
        };
        let victim = SwapEvent {
            signature: "v".into(), signer: "vic".into(), dex: DexType::RaydiumV4,
            pool: "p".into(), direction: SwapDirection::Buy, token_mint: "t".into(),
            amount_in: 1_000, amount_out: 1, tx_index: 1, slot: None, fee: None, // 0.00001% of frontrun
        };
        let config = FilterConfig { min_victim_ratio: 0.01, ..Default::default() };
        let result = check_victim_plausibility(&front, &victim, &HashSet::new(), &config);
        assert!(!result.plausible);
    }

    #[test]
    fn confidence_scoring() {
        let econ = EconomicResult {
            gross_revenue: 200_000_000,
            estimated_cost: 10_000,
            net_profit: 199_990_000,
            feasible: true,
        };
        let victim = VictimResult {
            size_ratio: 0.5,
            is_known_attacker: false,
            plausible: true,
        };

        let conf = compute_confidence(BundleProvenance::AtomicBundle, &econ, &victim);
        assert!(conf > 0.8, "atomic bundle + profitable should be high confidence: {}", conf);

        let conf_organic = compute_confidence(BundleProvenance::Organic, &econ, &victim);
        assert!(conf_organic < conf, "organic should be lower than atomic");
    }
}
