//! Adversarial corpus: false-positive-shaped scenarios the detector
//! must reject.
//!
//! Each test below is a hand-crafted block whose swap pattern *looks*
//! sandwich-shaped to a naive heuristic but isn't an attack. The detector
//! is required to emit zero detections; a regression that flips any case
//! to a positive emission breaks the suite and surfaces which guard
//! relaxed.
//!
//! Adversarial cases differ from `detector-sameblock` unit tests in two
//! ways:
//!   - they're framed as scenarios (round-trip arb, cross-pool arb,
//!     multi-bot dense block) rather than per-guard regressions;
//!   - they exercise the swap-event layer the same way the production
//!     pipeline does, so any future change that adds swap-derivation
//!     ambiguity will surface here.
//!
//! When a *real* mainnet false positive shows up, mirror it as a fixture
//! plus a `must_not_detect` manifest under `tests/adversarial/<name>/`
//! and extend this runner. For now the cases are synthetic — they
//! parameterize on the smallest set of fields the detector keys on
//! (signer, direction, pool, tx_index) so future detector tweaks can't
//! accidentally pass through a guard relaxation.

use sandwich_detector::{
    authority_hop::{index_by_wallet_pair, AuthorityHop, AuthorityType},
    detector,
    types::{DexType, SwapDirection, SwapEvent},
};

fn swap(sig: &str, signer: &str, pool: &str, dir: SwapDirection, tx_index: usize) -> SwapEvent {
    SwapEvent {
        signature: sig.into(),
        signer: signer.into(),
        dex: DexType::RaydiumV4,
        pool: pool.into(),
        direction: dir,
        token_mint: "MINT".into(),
        amount_in: 1_000_000,
        amount_out: 900_000,
        tx_index,
        slot: Some(100),
        fee: Some(5_000),
    }
}

fn assert_no_detections(label: &str, swaps: Vec<SwapEvent>) {
    let detections = detector::detect_sandwiches(100, &swaps);
    assert!(
        detections.is_empty(),
        "{label}: expected no detections, got {} ({:?})",
        detections.len(),
        detections
            .iter()
            .map(|d| (
                d.frontrun.signature.clone(),
                d.victim.signature.clone(),
                d.backrun.signature.clone(),
            ))
            .collect::<Vec<_>>()
    );
}

/// Single-attacker round-trip arbitrage with an unrelated trader in the
/// middle, *all in the same direction*. Looks like a sandwich shape if
/// you only check signer-equality at the endpoints — but the opposite-
/// direction guard rejects it. Mirrors the most common mainnet false-
/// positive shape: an arb bot that buys, holds, then buys again later in
/// the slot while a retail trader also buys between them.
#[test]
fn round_trip_same_direction_arb_is_not_a_sandwich() {
    let swaps = vec![
        swap("arb_open", "ARB_BOT", "POOL_X", SwapDirection::Buy, 0),
        swap("retail", "RETAIL_USER", "POOL_X", SwapDirection::Buy, 1),
        // Same wallet, same direction — opposite-direction guard rejects.
        swap("arb_top_up", "ARB_BOT", "POOL_X", SwapDirection::Buy, 2),
    ];
    assert_no_detections("round_trip_same_direction_arb", swaps);
}

/// Cross-pool arbitrage: bot buys in pool X, sells in pool Y, with an
/// unrelated retail buy in pool X between them. The two attacker swaps
/// are in different pools, so by-pool grouping must keep them apart. A
/// detector that mistakenly flattens pools would emit one false
/// positive.
#[test]
fn cross_pool_arbitrage_is_not_a_sandwich() {
    let swaps = vec![
        swap("arb_buy_x", "ARB_BOT", "POOL_X", SwapDirection::Buy, 0),
        swap("retail", "RETAIL_USER", "POOL_X", SwapDirection::Buy, 1),
        // Same bot but different pool — cross-pool guard rejects.
        swap("arb_sell_y", "ARB_BOT", "POOL_Y", SwapDirection::Sell, 2),
    ];
    assert_no_detections("cross_pool_arbitrage", swaps);
}

/// Three retail buyers in a row, all different wallets — a momentum
/// cascade, not a sandwich. The detector requires the frontrun and
/// backrun to share a signer; with three distinct signers no triplet
/// satisfies that. Any future heuristic that generalizes attacker
/// identity beyond `signer == signer` must keep this case quiet.
#[test]
fn momentum_cluster_three_buyers_is_not_a_sandwich() {
    let swaps = vec![
        swap("buyer_a", "WALLET_A", "POOL_X", SwapDirection::Buy, 0),
        swap("buyer_b", "WALLET_B", "POOL_X", SwapDirection::Buy, 1),
        swap("buyer_c", "WALLET_C", "POOL_X", SwapDirection::Buy, 2),
    ];
    assert_no_detections("momentum_cluster_three_buyers", swaps);
}

/// Single-attacker self-rotation: A buys, A buys, A sells. Frontrun /
/// backrun share signer and have opposite directions, but every middle
/// "victim" candidate is also signed by A — same-signer victim guard
/// rejects. Synthetic version of an internal LP/inventory rebalance.
#[test]
fn single_attacker_self_rotation_has_no_victim() {
    let swaps = vec![
        swap("a_buy_1", "ATTACKER", "POOL_X", SwapDirection::Buy, 0),
        // Sole "candidate victim" is the attacker themselves.
        swap("a_buy_2", "ATTACKER", "POOL_X", SwapDirection::Buy, 1),
        swap("a_sell", "ATTACKER", "POOL_X", SwapDirection::Sell, 2),
    ];
    assert_no_detections("single_attacker_self_rotation", swaps);
}

/// JIT-LP-like scenario: an LP provider's mint and burn wrap a single
/// retail swap. Only one swap event lands in the detector's input
/// (mints/burns aren't swaps), so no triplet is possible. Rejecting
/// this synthetic case ensures a future "treat LP delta as a swap"
/// experiment doesn't accidentally shape JIT activity into sandwich
/// triplets.
#[test]
fn jit_lp_provider_swap_alone_is_not_a_sandwich() {
    // The JIT LP mint and burn are non-swap events; only the retail
    // swap reaches the detector. With <3 swaps in the pool no detection
    // is possible, by sandwich definition.
    let swaps = vec![swap(
        "retail",
        "RETAIL_USER",
        "POOL_X",
        SwapDirection::Buy,
        1,
    )];
    assert_no_detections("jit_lp_provider_swap_alone", swaps);
}

// ---------------------------------------------------------------------
// Authority-Hop variants — same shape as above but exercising the
// detect_authority_hop_sandwiches path. The Authority-Hop detector keys
// on (frontrun_signer, backrun_signer) wallet pairs that appear in a
// hop index; these scenarios make sure the detector stays quiet when
// the index doesn't actually link the two wallets.
// ---------------------------------------------------------------------

fn assert_no_authority_hop_detections(label: &str, swaps: Vec<SwapEvent>, hops: Vec<AuthorityHop>) {
    let idx = index_by_wallet_pair(hops);
    let detections = detector::detect_authority_hop_sandwiches(100, &swaps, &idx);
    assert!(
        detections.is_empty(),
        "{label}: expected no authority-hop detections, got {}",
        detections.len(),
    );
}

/// Wallet-mismatch sandwich shape with no SetAuthority observed. The
/// wallets simply happen to share a pool in the same slot — there's no
/// custody chain. detector must stay quiet.
#[test]
fn wallet_mismatch_without_hop_is_not_an_authority_hop() {
    let swaps = vec![
        swap("front", "WALLET_A", "POOL_X", SwapDirection::Buy, 0),
        swap("victim", "VICTIM", "POOL_X", SwapDirection::Buy, 1),
        swap("back", "WALLET_B", "POOL_X", SwapDirection::Sell, 2),
    ];
    assert_no_authority_hop_detections("wallet_mismatch_without_hop", swaps, vec![]);
}

/// Mint authority change A → B between two unrelated swaps. The
/// instruction does land in the slot but it doesn't move trading
/// capability — `MintTokens` authority controls minting, not the SPL
/// account's owner. index_by_wallet_pair must not index it, so the
/// detector can't promote the unrelated triplet into AuthorityHop.
#[test]
fn mint_authority_change_does_not_link_unrelated_swaps() {
    let swaps = vec![
        swap("front", "WALLET_A", "POOL_X", SwapDirection::Buy, 0),
        swap("victim", "VICTIM", "POOL_X", SwapDirection::Buy, 1),
        swap("back", "WALLET_B", "POOL_X", SwapDirection::Sell, 3),
    ];
    let hops = vec![AuthorityHop {
        account: "MINT_X".into(),
        authority_type: AuthorityType::MintTokens, // not AccountOwner
        from: "WALLET_A".into(),
        to: Some("WALLET_B".into()),
        tx_signature: "tx_mint".into(),
        slot: 100,
        tx_index: 2,
    }];
    assert_no_authority_hop_detections("mint_authority_change", swaps, hops);
}

/// Close-account authority change A → B between unrelated swaps. Same
/// principle as the mint variant — `CloseAccount` authority controls
/// rent reclamation, not trading. Must not link.
#[test]
fn close_authority_change_does_not_link_unrelated_swaps() {
    let swaps = vec![
        swap("front", "WALLET_A", "POOL_X", SwapDirection::Buy, 0),
        swap("victim", "VICTIM", "POOL_X", SwapDirection::Buy, 1),
        swap("back", "WALLET_B", "POOL_X", SwapDirection::Sell, 3),
    ];
    let hops = vec![AuthorityHop {
        account: "ACCT".into(),
        authority_type: AuthorityType::CloseAccount,
        from: "WALLET_A".into(),
        to: Some("WALLET_B".into()),
        tx_signature: "tx_close".into(),
        slot: 100,
        tx_index: 2,
    }];
    assert_no_authority_hop_detections("close_authority_change", swaps, hops);
}

/// Multi-bot dense block: two unrelated bots open positions in the same
/// pool but neither closes within the slot. Looks like four-tx activity
/// in one pool but the backruns are missing — every triplet candidate
/// fails the opposite-direction guard at the third leg.
#[test]
fn dense_open_only_block_has_no_closing_legs() {
    let swaps = vec![
        swap("bot_a_open", "BOT_A", "POOL_X", SwapDirection::Buy, 0),
        swap("retail_1", "RETAIL_1", "POOL_X", SwapDirection::Buy, 1),
        swap("bot_b_open", "BOT_B", "POOL_X", SwapDirection::Buy, 2),
        swap("retail_2", "RETAIL_2", "POOL_X", SwapDirection::Buy, 3),
    ];
    assert_no_detections("dense_open_only_block", swaps);
}
