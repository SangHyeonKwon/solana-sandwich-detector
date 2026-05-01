//! Aggregate economic metrics over a batch of detected (and ideally enriched)
//! [`SandwichAttack`]s.
//!
//! This is the module that produces the headline numbers for a run: how much
//! did victims lose, how much did attackers extract, which wallets dominate,
//! and — crucially — the *reclassification rate*: the share of sandwiches that
//! the naive rule-based profit estimate flags as profitable but AMM-correct
//! replay shows to be losing money. That reclassification is the signal that
//! makes pool-state enrichment a real contribution rather than a re-labelling.
//!
//! Input: any slice of `SandwichAttack`. Fields populated by pool-state
//! enrichment (`victim_loss_lamports`, `attacker_profit`) are folded in
//! when present and skipped when `None`, so this module also works on a
//! pre-enrichment run to compare with/without numbers.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use swap_events::types::{DexType, SandwichAttack};

/// One lamport expressed in SOL — used for pretty-printing only.
const LAMPORTS_PER_SOL: f64 = 1_000_000_000.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsReport {
    pub total_attacks: usize,
    pub unique_attackers: usize,
    pub unique_victims: usize,
    pub unique_pools: usize,

    /// Count of attacks where pool-state enrichment successfully filled
    /// `victim_loss_lamports`. Denominator for coverage metrics.
    pub enriched_count: usize,

    /// Sum of `victim_loss_lamports` over enriched attacks. Quote-token
    /// smallest unit (lamports for SOL-quoted pools). Mixes units across
    /// pools with different quote tokens — consumers that care should
    /// group by quote mint first.
    pub total_victim_loss: i64,
    /// Sum of `attacker_profit` over enriched attacks.
    pub total_attacker_profit_real: i64,
    /// Sum of `estimated_attacker_profit` (the naive, pre-AMM-replay number).
    pub total_attacker_profit_naive: i64,

    /// Reclassification: enriched attacks where the naive estimate was
    /// strictly positive but the AMM-correct number is non-positive. These
    /// are the cases where a baseline detector would over-report extraction.
    pub naive_profitable_real_unprofitable: usize,
    /// Enriched attacks where both naive and real profit are strictly positive.
    pub consistently_profitable: usize,

    /// Per-DEX breakdown. BTreeMap so serialized output is deterministic.
    pub by_dex: BTreeMap<String, DexStats>,

    /// Top attackers by total extracted value (sum of positive
    /// `attacker_profit`). Length bounded by the `top_n` argument.
    pub top_attackers: Vec<AttackerStats>,

    /// Percentiles over `victim_loss_lamports`, enriched attacks only.
    pub victim_loss_percentiles: LossPercentiles,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DexStats {
    pub count: usize,
    pub total_victim_loss: i64,
    pub total_attacker_profit_real: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerStats {
    pub wallet: String,
    pub sandwich_count: usize,
    /// Sum of positive `attacker_profit`. Losses are floored at 0 per
    /// attack so a single bad sandwich doesn't erase a profitable streak.
    pub total_extracted: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LossPercentiles {
    pub p50: i64,
    pub p90: i64,
    pub p99: i64,
    pub max: i64,
}

/// Aggregate a batch of sandwich detections into an economics report.
///
/// `top_n` caps the `top_attackers` list. Pass `usize::MAX` for unbounded.
pub fn aggregate(attacks: &[SandwichAttack], top_n: usize) -> EconomicsReport {
    let mut unique_attackers: HashSet<&str> = HashSet::new();
    let mut unique_victims: HashSet<&str> = HashSet::new();
    let mut unique_pools: HashSet<&str> = HashSet::new();

    let mut total_victim_loss: i64 = 0;
    let mut total_attacker_profit_real: i64 = 0;
    let mut total_attacker_profit_naive: i64 = 0;
    let mut enriched_count = 0usize;

    let mut naive_profitable_real_unprofitable = 0usize;
    let mut consistently_profitable = 0usize;

    let mut by_dex: BTreeMap<String, DexStats> = BTreeMap::new();
    let mut per_attacker: HashMap<String, AttackerStats> = HashMap::new();
    let mut victim_losses: Vec<i64> = Vec::new();

    for a in attacks {
        unique_attackers.insert(a.attacker.as_str());
        unique_victims.insert(a.victim.signer.as_str());
        unique_pools.insert(a.pool.as_str());

        let dex_stats = by_dex.entry(dex_label(a.dex).to_string()).or_default();
        dex_stats.count += 1;

        total_attacker_profit_naive =
            total_attacker_profit_naive.saturating_add(a.estimated_attacker_profit.unwrap_or(0));

        if let (Some(loss), Some(real)) = (a.victim_loss_lamports, a.attacker_profit) {
            enriched_count += 1;
            total_victim_loss = total_victim_loss.saturating_add(loss);
            total_attacker_profit_real = total_attacker_profit_real.saturating_add(real);
            dex_stats.total_victim_loss = dex_stats.total_victim_loss.saturating_add(loss);
            dex_stats.total_attacker_profit_real =
                dex_stats.total_attacker_profit_real.saturating_add(real);
            victim_losses.push(loss);

            let naive = a.estimated_attacker_profit.unwrap_or(0);
            match (naive > 0, real > 0) {
                (true, false) => naive_profitable_real_unprofitable += 1,
                (true, true) => consistently_profitable += 1,
                _ => {}
            }

            let entry = per_attacker
                .entry(a.attacker.clone())
                .or_insert_with(|| AttackerStats {
                    wallet: a.attacker.clone(),
                    sandwich_count: 0,
                    total_extracted: 0,
                });
            entry.sandwich_count += 1;
            if real > 0 {
                entry.total_extracted = entry.total_extracted.saturating_add(real);
            }
        }
    }

    let mut top_attackers: Vec<AttackerStats> = per_attacker.into_values().collect();
    top_attackers.sort_by(|a, b| {
        b.total_extracted
            .cmp(&a.total_extracted)
            .then_with(|| a.wallet.cmp(&b.wallet))
    });
    if top_attackers.len() > top_n {
        top_attackers.truncate(top_n);
    }

    EconomicsReport {
        total_attacks: attacks.len(),
        unique_attackers: unique_attackers.len(),
        unique_victims: unique_victims.len(),
        unique_pools: unique_pools.len(),
        enriched_count,
        total_victim_loss,
        total_attacker_profit_real,
        total_attacker_profit_naive,
        naive_profitable_real_unprofitable,
        consistently_profitable,
        by_dex,
        top_attackers,
        victim_loss_percentiles: percentiles(&mut victim_losses),
    }
}

fn percentiles(values: &mut [i64]) -> LossPercentiles {
    if values.is_empty() {
        return LossPercentiles::default();
    }
    values.sort_unstable();
    let n = values.len();
    let pick = |q: f64| -> i64 {
        // Nearest-rank percentile on a sorted slice.
        let idx = ((q * n as f64).ceil() as usize)
            .saturating_sub(1)
            .min(n - 1);
        values[idx]
    };
    LossPercentiles {
        p50: pick(0.50),
        p90: pick(0.90),
        p99: pick(0.99),
        max: *values.last().unwrap(),
    }
}

fn dex_label(dex: DexType) -> &'static str {
    match dex {
        DexType::RaydiumV4 => "raydium_v4",
        DexType::RaydiumCpmm => "raydium_cpmm",
        DexType::RaydiumClmm => "raydium_clmm",
        DexType::OrcaWhirlpool => "orca_whirlpool",
        DexType::JupiterV6 => "jupiter_v6",
        DexType::MeteoraDlmm => "meteora_dlmm",
        DexType::PumpFun => "pump_fun",
        DexType::Phoenix => "phoenix",
    }
}

impl std::fmt::Display for EconomicsReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Economics Report")?;
        writeln!(
            f,
            "  attacks={}  attackers={}  victims={}  pools={}",
            self.total_attacks, self.unique_attackers, self.unique_victims, self.unique_pools
        )?;
        writeln!(
            f,
            "  enriched={}/{} ({:.1}%)",
            self.enriched_count,
            self.total_attacks,
            if self.total_attacks == 0 {
                0.0
            } else {
                100.0 * self.enriched_count as f64 / self.total_attacks as f64
            }
        )?;
        writeln!(
            f,
            "  total victim loss  = {} ({:.4} SOL)",
            self.total_victim_loss,
            self.total_victim_loss as f64 / LAMPORTS_PER_SOL
        )?;
        writeln!(
            f,
            "  attacker profit (real)  = {} ({:.4} SOL)",
            self.total_attacker_profit_real,
            self.total_attacker_profit_real as f64 / LAMPORTS_PER_SOL
        )?;
        writeln!(
            f,
            "  attacker profit (naive) = {} ({:.4} SOL)",
            self.total_attacker_profit_naive,
            self.total_attacker_profit_naive as f64 / LAMPORTS_PER_SOL
        )?;
        let reclass_denom = self.consistently_profitable + self.naive_profitable_real_unprofitable;
        if reclass_denom > 0 {
            writeln!(
                f,
                "  reclassification: {}/{} ({:.1}%) naive-profitable were actually losing",
                self.naive_profitable_real_unprofitable,
                reclass_denom,
                100.0 * self.naive_profitable_real_unprofitable as f64 / reclass_denom as f64
            )?;
        }
        writeln!(
            f,
            "  victim loss percentiles: p50={}  p90={}  p99={}  max={}",
            self.victim_loss_percentiles.p50,
            self.victim_loss_percentiles.p90,
            self.victim_loss_percentiles.p99,
            self.victim_loss_percentiles.max,
        )?;
        if !self.by_dex.is_empty() {
            writeln!(f, "  by DEX:")?;
            for (dex, s) in &self.by_dex {
                writeln!(
                    f,
                    "    {:<16} count={}  victim_loss={}  profit_real={}",
                    dex, s.count, s.total_victim_loss, s.total_attacker_profit_real,
                )?;
            }
        }
        if !self.top_attackers.is_empty() {
            writeln!(f, "  top attackers:")?;
            for (i, a) in self.top_attackers.iter().enumerate() {
                writeln!(
                    f,
                    "    {:>2}. {}  attacks={}  extracted={}",
                    i + 1,
                    a.wallet,
                    a.sandwich_count,
                    a.total_extracted,
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_events::types::{DexType, SwapDirection, SwapEvent};

    fn swap(sig: &str, signer: &str, dir: SwapDirection) -> SwapEvent {
        SwapEvent {
            signature: sig.into(),
            signer: signer.into(),
            dex: DexType::RaydiumV4,
            pool: "pool1".into(),
            direction: dir,
            token_mint: "MINT".into(),
            amount_in: 1000,
            amount_out: 900,
            tx_index: 0,
            slot: None,
            fee: None,
        }
    }

    fn attack(
        attacker: &str,
        victim: &str,
        pool: &str,
        dex: DexType,
        naive: Option<i64>,
        real: Option<i64>,
        loss: Option<i64>,
    ) -> SandwichAttack {
        SandwichAttack {
            slot: 1,
            attacker: attacker.into(),
            frontrun: swap("f", attacker, SwapDirection::Buy),
            victim: swap("v", victim, SwapDirection::Buy),
            backrun: swap("b", attacker, SwapDirection::Sell),
            pool: pool.into(),
            dex,
            estimated_attacker_profit: naive,
            victim_loss_lamports: loss,
            victim_loss_lamports_lower: None,
            victim_loss_lamports_upper: None,
            attacker_profit: real,
            price_impact_bps: None,
            frontrun_slot: None,
            backrun_slot: None,
            detection_method: None,
            bundle_provenance: None,
            confidence: None,
            net_profit: None,
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

    #[test]
    fn empty_input_returns_zeros() {
        let r = aggregate(&[], 10);
        assert_eq!(r.total_attacks, 0);
        assert_eq!(r.enriched_count, 0);
        assert_eq!(r.total_victim_loss, 0);
        assert!(r.top_attackers.is_empty());
    }

    #[test]
    fn aggregates_sums_and_uniques() {
        let attacks = vec![
            attack(
                "atk1",
                "vic1",
                "poolA",
                DexType::RaydiumV4,
                Some(100),
                Some(80),
                Some(120),
            ),
            attack(
                "atk1",
                "vic2",
                "poolA",
                DexType::RaydiumV4,
                Some(50),
                Some(40),
                Some(60),
            ),
            attack(
                "atk2",
                "vic1",
                "poolB",
                DexType::RaydiumCpmm,
                Some(200),
                Some(150),
                Some(220),
            ),
        ];
        let r = aggregate(&attacks, 10);

        assert_eq!(r.total_attacks, 3);
        assert_eq!(r.unique_attackers, 2);
        assert_eq!(r.unique_victims, 2);
        assert_eq!(r.unique_pools, 2);
        assert_eq!(r.enriched_count, 3);
        assert_eq!(r.total_victim_loss, 400);
        assert_eq!(r.total_attacker_profit_real, 270);
        assert_eq!(r.total_attacker_profit_naive, 350);
        assert_eq!(r.by_dex["raydium_v4"].count, 2);
        assert_eq!(r.by_dex["raydium_cpmm"].count, 1);
        assert_eq!(r.by_dex["raydium_v4"].total_victim_loss, 180);
    }

    #[test]
    fn reclassifies_naive_profitable_but_real_losing() {
        let attacks = vec![
            // Naive +, real + -> consistently profitable
            attack(
                "atk1",
                "vic1",
                "p",
                DexType::RaydiumV4,
                Some(100),
                Some(50),
                Some(80),
            ),
            // Naive +, real - -> reclassified
            attack(
                "atk2",
                "vic2",
                "p",
                DexType::RaydiumV4,
                Some(100),
                Some(-10),
                Some(80),
            ),
            // Naive +, real - (another one)
            attack(
                "atk3",
                "vic3",
                "p",
                DexType::RaydiumV4,
                Some(50),
                Some(-5),
                Some(40),
            ),
        ];
        let r = aggregate(&attacks, 10);
        assert_eq!(r.consistently_profitable, 1);
        assert_eq!(r.naive_profitable_real_unprofitable, 2);
    }

    #[test]
    fn top_attackers_ranked_by_extracted_and_capped() {
        let attacks = vec![
            attack(
                "A",
                "v1",
                "p",
                DexType::RaydiumV4,
                Some(0),
                Some(100),
                Some(1),
            ),
            attack(
                "B",
                "v2",
                "p",
                DexType::RaydiumV4,
                Some(0),
                Some(300),
                Some(1),
            ),
            attack(
                "C",
                "v3",
                "p",
                DexType::RaydiumV4,
                Some(0),
                Some(200),
                Some(1),
            ),
        ];
        let r = aggregate(&attacks, 2);
        assert_eq!(r.top_attackers.len(), 2);
        assert_eq!(r.top_attackers[0].wallet, "B");
        assert_eq!(r.top_attackers[1].wallet, "C");
    }

    #[test]
    fn loss_percentiles_computed() {
        let mut attacks = Vec::new();
        for i in 1..=100 {
            attacks.push(attack(
                "a",
                &format!("v{}", i),
                "p",
                DexType::RaydiumV4,
                Some(0),
                Some(1),
                Some(i as i64),
            ));
        }
        let r = aggregate(&attacks, 10);
        // With 100 values 1..=100 and nearest-rank, p50 -> ceil(50) = 50
        assert_eq!(r.victim_loss_percentiles.p50, 50);
        assert_eq!(r.victim_loss_percentiles.p90, 90);
        assert_eq!(r.victim_loss_percentiles.p99, 99);
        assert_eq!(r.victim_loss_percentiles.max, 100);
    }

    #[test]
    fn skips_unenriched_but_still_counts_attack() {
        let attacks = vec![attack(
            "a",
            "v",
            "p",
            DexType::RaydiumV4,
            Some(100),
            None,
            None,
        )];
        let r = aggregate(&attacks, 10);
        assert_eq!(r.total_attacks, 1);
        assert_eq!(r.enriched_count, 0);
        assert_eq!(r.total_victim_loss, 0);
        assert_eq!(r.total_attacker_profit_real, 0);
        assert_eq!(r.total_attacker_profit_naive, 100);
    }
}
