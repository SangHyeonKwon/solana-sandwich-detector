//! Differential property test: `FilteredWindowDetector ⊆ NaiveWindowDetector`.
//!
//! `NaiveWindowDetector` emits every cross-slot triplet that satisfies the
//! sandwich shape (same-signer endpoints, opposite directions, victim
//! sandwiched in tx-order). `FilteredWindowDetector` runs the same
//! candidate-generation step and then layers three precision filters on
//! top: economic feasibility, victim plausibility, and a confidence
//! threshold derived from bundle provenance.
//!
//! The contract between the two is a *set inclusion*: any triplet
//! Filtered emits must also have been a candidate Naive emits. A
//! regression that promotes a candidate Filtered shouldn't have seen —
//! e.g. a filter-side bug that skips the temporal-ordering guard, or
//! that constructs a victim from a different code path — would break
//! this inclusion silently.
//!
//! The property is verified by feeding both detectors the same randomly
//! generated stream of swap events across a small slot window and
//! comparing emitted victim-signature sets.
//!
//! Notes on the strategy:
//!   - Signatures are derived from `(slot, tx_index)` so duplicates are
//!     impossible by construction; otherwise dedup by signature would
//!     mask a bug.
//!   - Wallet and pool universes are kept small (5 wallets, 3 pools) so
//!     a 10-slot stream has a real chance of producing sandwich shapes;
//!     a uniform 2^256 keyspace would generate noise that never triggers
//!     any candidate.
//!   - Window sizes 2..=5 cover the production setting (typically 5).

use std::collections::HashSet;

use detector_window::{FilteredWindowDetector, NaiveWindowDetector, WindowDetector};
use proptest::prelude::*;
use swap_events::types::{DexType, SwapDirection, SwapEvent};

const WALLETS: &[&str] = &["W1", "W2", "W3", "W4", "W5"];
const POOLS: &[&str] = &["P1", "P2", "P3"];

fn arb_swap_stub() -> impl Strategy<Value = (usize, usize, SwapDirection, u64, u64)> {
    (
        0usize..WALLETS.len(),
        0usize..POOLS.len(),
        prop_oneof![Just(SwapDirection::Buy), Just(SwapDirection::Sell)],
        // amount_in: 0.001 SOL to 100 SOL in lamports.
        1_000_000u64..=100_000_000_000u64,
        // amount_out as a percent of amount_in (50% .. 150%). Keeps
        // economic feasibility checks in the realistic band so the
        // filtered detector occasionally emits — without this the
        // subset relation holds trivially because filtered emits zero.
        50u64..=150,
    )
}

fn arb_slot_block() -> impl Strategy<Value = Vec<(usize, usize, SwapDirection, u64, u64)>> {
    prop::collection::vec(arb_swap_stub(), 0..=6)
}

/// Build a single block of `SwapEvent`s from the per-swap stubs,
/// assigning sequential `tx_index` and `(slot, tx_index)`-derived
/// signatures.
fn build_block(slot: u64, stubs: Vec<(usize, usize, SwapDirection, u64, u64)>) -> Vec<SwapEvent> {
    stubs
        .into_iter()
        .enumerate()
        .map(|(idx, (w, p, dir, amount_in, out_pct))| {
            let amount_out =
                (amount_in as u128 * out_pct as u128 / 100).min(u64::MAX as u128) as u64;
            SwapEvent {
                signature: format!("sig_{slot}_{idx}"),
                signer: WALLETS[w].to_string(),
                dex: DexType::RaydiumV4,
                pool: POOLS[p].to_string(),
                direction: dir,
                token_mint: "MINT".into(),
                amount_in,
                amount_out,
                tx_index: idx,
                slot: Some(slot),
                fee: Some(5_000),
            }
        })
        .collect()
}

fn run_naive(window: usize, blocks: &[Vec<SwapEvent>]) -> HashSet<String> {
    let mut det = NaiveWindowDetector::new(window);
    let mut emitted = HashSet::new();
    for (i, block) in blocks.iter().enumerate() {
        let slot = 100 + i as u64;
        for d in det.ingest_slot(slot, block.clone()) {
            emitted.insert(d.victim.signature);
        }
    }
    for d in det.flush() {
        emitted.insert(d.victim.signature);
    }
    emitted
}

fn run_filtered(window: usize, blocks: &[Vec<SwapEvent>]) -> HashSet<String> {
    let mut det = FilteredWindowDetector::new(window);
    let mut emitted = HashSet::new();
    for (i, block) in blocks.iter().enumerate() {
        let slot = 100 + i as u64;
        for d in det.ingest_slot(slot, block.clone()) {
            emitted.insert(d.victim.signature);
        }
    }
    for d in det.flush() {
        emitted.insert(d.victim.signature);
    }
    emitted
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Core property: the set of victim signatures Filtered emits must
    /// be a subset of Naive's. Filtered's filters can only *reject*
    /// Naive candidates; they must never invent a new triplet.
    #[test]
    fn filtered_emissions_are_subset_of_naive(
        blocks in prop::collection::vec(arb_slot_block(), 1..=8),
        window in 2usize..=5,
    ) {
        let blocks: Vec<Vec<SwapEvent>> = blocks
            .into_iter()
            .enumerate()
            .map(|(i, stubs)| build_block(100 + i as u64, stubs))
            .collect();

        let naive = run_naive(window, &blocks);
        let filtered = run_filtered(window, &blocks);

        let extras: Vec<&String> = filtered.difference(&naive).collect();
        prop_assert!(
            extras.is_empty(),
            "filtered emitted {} signature(s) naive missed: {:?}",
            extras.len(),
            extras,
        );
    }

    /// Determinism: re-running the same input through a fresh detector
    /// instance must yield the same emission set. A hash-iteration order
    /// or non-deterministic tie-break that leaks here would make CI
    /// flaky and Vigil's BE see ghost rows on retries.
    #[test]
    fn filtered_is_deterministic(
        blocks in prop::collection::vec(arb_slot_block(), 1..=6),
        window in 2usize..=5,
    ) {
        let blocks: Vec<Vec<SwapEvent>> = blocks
            .into_iter()
            .enumerate()
            .map(|(i, stubs)| build_block(100 + i as u64, stubs))
            .collect();

        let a = run_filtered(window, &blocks);
        let b = run_filtered(window, &blocks);
        prop_assert_eq!(a, b);
    }

    /// Naive determinism — same property, but for the baseline. Catches
    /// the (less likely) case where Filtered is deterministic only because
    /// Naive is, and a refactor breaks Naive's iteration order.
    #[test]
    fn naive_is_deterministic(
        blocks in prop::collection::vec(arb_slot_block(), 1..=6),
        window in 2usize..=5,
    ) {
        let blocks: Vec<Vec<SwapEvent>> = blocks
            .into_iter()
            .enumerate()
            .map(|(i, stubs)| build_block(100 + i as u64, stubs))
            .collect();

        let a = run_naive(window, &blocks);
        let b = run_naive(window, &blocks);
        prop_assert_eq!(a, b);
    }
}
