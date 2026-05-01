//! Authority-Hop sandwich heuristic.
//!
//! Some sandwich operators rotate token-account ownership between the frontrun
//! and the backrun: a frontrun signed by wallet A is followed by an SPL Token
//! `SetAuthority` that transfers the trading account to wallet B, after which
//! B issues the backrun. The two wallets look unrelated to a naïve detector
//! (different signers), so the same-block / window heuristics drop the
//! triplet. The `SetAuthority` itself, observable in the tx's inner
//! instructions, is the audit-quality link: this module finds those events
//! and projects them into [`Signal::AuthorityChain`] evidence so a downstream
//! pass can promote rejected candidates into [`AttackType::AuthorityHop`]
//! detections.
//!
//! Two layers:
//!   - Parsing/indexing — [`scan_block`] and [`index_by_wallet_pair`] turn
//!     the inner-instruction stream into an `(A, B) -> Vec<AuthorityHop>` map.
//!   - Detection — [`detect_authority_hop_sandwiches`] is the analogue of
//!     `detector_sameblock::detect_sandwiches` for the wallet-mismatch
//!     branch: it looks for sandwich-shaped triplets the sameblock detector
//!     dropped (different frontrun/backrun signers) and promotes the ones
//!     whose `(A, B)` pair has a temporally-bracketed hop in the index.
//!
//! [`Signal::AuthorityChain`]: swap_events::types::Signal::AuthorityChain
//! [`AttackType::AuthorityHop`]: swap_events::types::AttackType::AuthorityHop

use std::collections::{HashMap, HashSet};

use swap_events::types::{
    BlockData, DetectionEvidence, DetectionMethod, InstructionData, SandwichAttack, Signal,
    SwapEvent, TransactionData,
};

/// Canonical SPL Token program (Token v1).
pub const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// SPL Token-2022 — the newer extension-aware variant. Same instruction
/// taxonomy for SetAuthority so it parses identically.
pub const SPL_TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// Discriminator byte for `SetAuthority` (variant index 6 of the SPL Token
/// instruction enum).
const SET_AUTHORITY_DISCRIMINATOR: u8 = 6;

/// SPL Token `AuthorityType` byte values. Only [`AuthorityType::AccountOwner`]
/// is meaningful for sandwich linkage — the other variants change mint-side
/// rights (mint, freeze, close) and don't move trading capability between
/// wallets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityType {
    MintTokens = 0,
    FreezeAccount = 1,
    AccountOwner = 2,
    CloseAccount = 3,
}

impl AuthorityType {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::MintTokens),
            1 => Some(Self::FreezeAccount),
            2 => Some(Self::AccountOwner),
            3 => Some(Self::CloseAccount),
            _ => None,
        }
    }
}

/// One observed `SetAuthority` event extracted from a transaction.
///
/// `from` is the prior authority (the signing wallet of the SetAuthority);
/// `to` is the new authority encoded in the instruction data, or `None` when
/// the SetAuthority cleared the authority entirely (no replacement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityHop {
    pub account: String,
    pub authority_type: AuthorityType,
    pub from: String,
    /// New authority. `None` when the SetAuthority cleared the slot —
    /// not useful for sandwich linkage, but kept for forensic completeness.
    pub to: Option<String>,
    pub tx_signature: String,
    pub slot: u64,
    pub tx_index: usize,
}

impl AuthorityHop {
    /// Project this hop into a [`Signal::AuthorityChain`] suitable for an
    /// emission's evidence list. Returns `None` for hops that can't link two
    /// wallets — non-`AccountOwner` changes, or cleared-authority events with
    /// `to = None`.
    pub fn into_chain_signal(self) -> Option<Signal> {
        if self.authority_type != AuthorityType::AccountOwner {
            return None;
        }
        Some(Signal::AuthorityChain {
            from: self.from,
            to: self.to?,
            authority_tx: self.tx_signature,
        })
    }
}

/// Scan a single transaction (top-level + inner instructions) for SetAuthority
/// events. The detector calls this for every tx in the victim window and
/// indexes the results by `(from, to)` for cheap lookup.
pub fn scan_transaction(tx: &TransactionData, slot: u64) -> Vec<AuthorityHop> {
    let mut hops = Vec::new();
    for ix in &tx.instructions {
        if let Some(hop) = parse_set_authority(ix, tx, slot) {
            hops.push(hop);
        }
    }
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            if let Some(hop) = parse_set_authority(ix, tx, slot) {
                hops.push(hop);
            }
        }
    }
    hops
}

/// Convenience: scan every tx in a block. Skips failed txs since their state
/// changes were rolled back — a SetAuthority in a failed tx didn't actually
/// transfer anything.
pub fn scan_block(block: &BlockData) -> Vec<AuthorityHop> {
    let mut hops = Vec::new();
    for tx in &block.transactions {
        if !tx.success {
            continue;
        }
        hops.extend(scan_transaction(tx, block.slot));
    }
    hops
}

/// Index hops by `(from, to)` so a candidate sandwich `(frontrun_signer A,
/// backrun_signer B)` can be checked in O(1). Multiple hops may share the
/// same wallet pair (e.g. an operator rotates several accounts at once); the
/// detector picks the first by tx_index when constructing evidence.
///
/// Only `AuthorityType::AccountOwner` hops are indexed — mint, freeze, and
/// close authority changes don't transfer trading capability between
/// wallets, so they can't link a sandwich. Filtering at index time keeps
/// detector code simple and prevents an irrelevant authority change from
/// accidentally fusing two unrelated swaps into a false-positive triplet.
pub fn index_by_wallet_pair(
    hops: Vec<AuthorityHop>,
) -> HashMap<(String, String), Vec<AuthorityHop>> {
    let mut idx: HashMap<(String, String), Vec<AuthorityHop>> = HashMap::new();
    for hop in hops {
        if hop.authority_type != AuthorityType::AccountOwner {
            continue;
        }
        if let Some(to) = hop.to.clone() {
            idx.entry((hop.from.clone(), to)).or_default().push(hop);
        }
    }
    idx
}

/// Authority-Hop sandwich detector pass.
///
/// Companion to `detector_sameblock::detect_sandwiches` — the sameblock
/// detector drops candidates whose frontrun and backrun signers don't match.
/// This function is the inverse: it scans for triplets where the signers
/// *differ* but a SetAuthority(AccountOwner) hop in `hop_index` ties them
/// together. The two passes are disjoint by construction (one requires
/// `front == back`, the other `front != back`), so callers can union the
/// results without dedup.
///
/// Same-slot only. Cross-slot Authority-Hop would need a window-aware
/// variant; the same-slot case is the pattern observed in mainnet today.
///
/// Returned attacks have:
///   - `attack_type = None` — set by [`SandwichAttack::finalize_for_vigil`]
///     to `AttackType::AuthorityHop` because the evidence carries an
///     `AuthorityChain` signal.
///   - `detection_method = SameBlock` — the trip landed in one slot. The
///     authority-hop classification lives on `attack_type`, not on the
///     detection method.
///
/// Tightness guards (precision over recall):
///   - The linking hop must sit *between* the frontrun and backrun in
///     tx-index order. A SetAuthority before the frontrun or after the
///     backrun couldn't have enabled the rotation.
///   - The victim must be signed by neither attacker wallet — A→B operators
///     occasionally rotate through more than two wallets in the same slot,
///     and we don't want a sibling rotation to count as a victim.
pub fn detect_authority_hop_sandwiches(
    slot: u64,
    swaps: &[SwapEvent],
    hop_index: &HashMap<(String, String), Vec<AuthorityHop>>,
) -> Vec<SandwichAttack> {
    let mut results = Vec::new();

    let mut by_pool: HashMap<&str, Vec<&SwapEvent>> = HashMap::new();
    for swap in swaps {
        by_pool.entry(&swap.pool).or_default().push(swap);
    }

    for (_pool, mut pool_swaps) in by_pool {
        pool_swaps.sort_by_key(|s| s.tx_index);

        if pool_swaps.len() < 3 {
            continue;
        }

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

                // Inverse of sameblock: the wallets must differ.
                if frontrun.signer == backrun.signer {
                    continue;
                }
                if frontrun.direction == backrun.direction {
                    continue;
                }

                // Look up the wallet pair. Pick the earliest hop strictly
                // between the frontrun and backrun — that's the rotation
                // event that actually enabled the swap.
                let key = (frontrun.signer.clone(), backrun.signer.clone());
                let Some(hops) = hop_index.get(&key) else {
                    continue;
                };
                let Some(linking_hop) = hops
                    .iter()
                    .filter(|h| h.tx_index > frontrun.tx_index && h.tx_index < backrun.tx_index)
                    .min_by_key(|h| h.tx_index)
                else {
                    continue;
                };

                let mut found_victim = false;
                for &victim in pool_swaps.iter().take(k).skip(i + 1) {
                    // Both attacker wallets are excluded — we don't want a
                    // sibling rotation in the same triplet to count as a
                    // victim.
                    if victim.signer == frontrun.signer || victim.signer == backrun.signer {
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
                        Signal::AuthorityChain {
                            from: frontrun.signer.clone(),
                            to: backrun.signer.clone(),
                            authority_tx: linking_hop.tx_signature.clone(),
                        },
                    ]);
                    results.push(SandwichAttack {
                        slot,
                        // attacker = frontrun signer (the wallet that opened
                        // the position). The receipt's AuthorityChain signal
                        // exposes the backrun signer too.
                        attacker: frontrun.signer.clone(),
                        frontrun: frontrun.clone(),
                        victim: victim.clone(),
                        backrun: backrun.clone(),
                        pool: frontrun.pool.clone(),
                        dex: frontrun.dex,
                        estimated_attacker_profit: Some(gross),
                        victim_loss_lamports: None,
                        victim_loss_lamports_lower: None,
                        victim_loss_lamports_upper: None,
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
                        whirlpool_replay: None,
                        dlmm_replay: None,
                        attack_signature: None,
                        timestamp_ms: None,
                        // Left None so finalize_for_vigil reads the
                        // AuthorityChain signal and sets AttackType::AuthorityHop.
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

/// Decode a single instruction. Returns `None` for anything that isn't a
/// SetAuthority on SPL Token / Token-2022, or for instructions whose layout
/// is malformed (truncated data / accounts).
fn parse_set_authority(
    ix: &InstructionData,
    tx: &TransactionData,
    slot: u64,
) -> Option<AuthorityHop> {
    if ix.program_id != SPL_TOKEN_PROGRAM_ID && ix.program_id != SPL_TOKEN_2022_PROGRAM_ID {
        return None;
    }
    // SetAuthority always carries at least [discriminator, authority_type,
    // option_tag] = 3 bytes; clear-authority is 3 bytes, set-to-pubkey is 35.
    if ix.data.len() < 3 {
        return None;
    }
    if ix.data[0] != SET_AUTHORITY_DISCRIMINATOR {
        return None;
    }
    let authority_type = AuthorityType::from_u8(ix.data[1])?;
    let to = match ix.data[2] {
        0 => None,
        1 => {
            if ix.data.len() < 35 {
                return None;
            }
            let bytes: [u8; 32] = ix.data[3..35].try_into().ok()?;
            Some(bs58::encode(bytes).into_string())
        }
        // Anything else is a malformed Option<Pubkey> — bail rather than
        // misinterpret raw bytes as a pubkey.
        _ => return None,
    };
    if ix.accounts.len() < 2 {
        return None;
    }
    Some(AuthorityHop {
        account: ix.accounts[0].clone(),
        authority_type,
        from: ix.accounts[1].clone(),
        to,
        tx_signature: tx.signature.clone(),
        slot,
        tx_index: tx.tx_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_events::types::{InnerInstructionGroup, InstructionData, TransactionData};

    fn tx_with_instructions(
        sig: &str,
        signer: &str,
        tx_index: usize,
        instructions: Vec<InstructionData>,
        inner: Vec<InnerInstructionGroup>,
    ) -> TransactionData {
        TransactionData {
            signature: sig.into(),
            signer: signer.into(),
            success: true,
            tx_index,
            account_keys: vec![],
            instructions,
            inner_instructions: inner,
            token_balance_changes: vec![],
            sol_balance_changes: vec![],
            fee: 5000,
            log_messages: vec![],
        }
    }

    fn set_authority_data(authority_type: u8, new_authority: Option<[u8; 32]>) -> Vec<u8> {
        let mut data = vec![SET_AUTHORITY_DISCRIMINATOR, authority_type];
        match new_authority {
            None => data.push(0),
            Some(pk) => {
                data.push(1);
                data.extend_from_slice(&pk);
            }
        }
        data
    }

    fn b58_dummy(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn parses_account_owner_setauthority_in_top_level() {
        let new_authority = b58_dummy(0xAB);
        let new_auth_str = bs58::encode(new_authority).into_string();
        let ix = InstructionData {
            program_id: SPL_TOKEN_PROGRAM_ID.into(),
            accounts: vec!["TOKEN_ACCT".into(), "WALLET_A".into()],
            data: set_authority_data(2, Some(new_authority)),
        };
        let tx = tx_with_instructions("sig1", "WALLET_A", 7, vec![ix], vec![]);

        let hops = scan_transaction(&tx, 100);
        assert_eq!(hops.len(), 1);
        let h = &hops[0];
        assert_eq!(h.account, "TOKEN_ACCT");
        assert_eq!(h.authority_type, AuthorityType::AccountOwner);
        assert_eq!(h.from, "WALLET_A");
        assert_eq!(h.to.as_deref(), Some(new_auth_str.as_str()));
        assert_eq!(h.tx_signature, "sig1");
        assert_eq!(h.slot, 100);
        assert_eq!(h.tx_index, 7);
    }

    #[test]
    fn parses_setauthority_in_inner_instructions() {
        let new_authority = b58_dummy(0xCD);
        let inner_ix = InstructionData {
            program_id: SPL_TOKEN_2022_PROGRAM_ID.into(),
            accounts: vec!["MINT_X".into(), "WALLET_A".into()],
            data: set_authority_data(2, Some(new_authority)),
        };
        let group = InnerInstructionGroup {
            index: 0,
            instructions: vec![inner_ix],
        };
        // Top-level instruction is unrelated (e.g. a Raydium swap); the
        // SetAuthority lives nested in CPI.
        let outer = InstructionData {
            program_id: "RaydiumProgram".into(),
            accounts: vec![],
            data: vec![9, 0, 0, 0],
        };
        let tx = tx_with_instructions("sig2", "WALLET_A", 3, vec![outer], vec![group]);

        let hops = scan_transaction(&tx, 200);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].account, "MINT_X");
    }

    #[test]
    fn skips_non_setauthority_instructions() {
        let ix = InstructionData {
            program_id: SPL_TOKEN_PROGRAM_ID.into(),
            // Discriminator 3 = Transfer, not SetAuthority — should be ignored.
            accounts: vec!["A".into(), "B".into(), "C".into()],
            data: vec![3, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let tx = tx_with_instructions("sig", "signer", 0, vec![ix], vec![]);
        assert!(scan_transaction(&tx, 1).is_empty());
    }

    #[test]
    fn skips_non_token_program() {
        let ix = InstructionData {
            program_id: "RandomProgram111".into(),
            accounts: vec!["A".into(), "B".into()],
            data: vec![SET_AUTHORITY_DISCRIMINATOR, 2, 0],
        };
        let tx = tx_with_instructions("sig", "signer", 0, vec![ix], vec![]);
        assert!(scan_transaction(&tx, 1).is_empty());
    }

    #[test]
    fn handles_cleared_authority_with_to_none() {
        let ix = InstructionData {
            program_id: SPL_TOKEN_PROGRAM_ID.into(),
            accounts: vec!["TOKEN_ACCT".into(), "WALLET_A".into()],
            // Option tag = 0 → cleared (None new authority)
            data: vec![SET_AUTHORITY_DISCRIMINATOR, 2, 0],
        };
        let tx = tx_with_instructions("sig", "WALLET_A", 0, vec![ix], vec![]);
        let hops = scan_transaction(&tx, 1);
        assert_eq!(hops.len(), 1);
        assert!(hops[0].to.is_none());
        // A cleared-authority event can't form a sandwich linkage signal.
        assert!(hops[0].clone().into_chain_signal().is_none());
    }

    #[test]
    fn rejects_truncated_data() {
        let ix_short = InstructionData {
            program_id: SPL_TOKEN_PROGRAM_ID.into(),
            accounts: vec!["A".into(), "B".into()],
            data: vec![SET_AUTHORITY_DISCRIMINATOR],
        };
        let ix_truncated_pubkey = InstructionData {
            program_id: SPL_TOKEN_PROGRAM_ID.into(),
            accounts: vec!["A".into(), "B".into()],
            // Option tag = 1 (Some) but only 10 bytes of pubkey instead of 32.
            data: {
                let mut d = vec![SET_AUTHORITY_DISCRIMINATOR, 2, 1];
                d.extend_from_slice(&[0; 10]);
                d
            },
        };
        let tx = tx_with_instructions(
            "sig",
            "signer",
            0,
            vec![ix_short, ix_truncated_pubkey],
            vec![],
        );
        assert!(scan_transaction(&tx, 1).is_empty());
    }

    #[test]
    fn into_chain_signal_only_for_account_owner() {
        let new_authority = b58_dummy(1);
        // MintTokens authority change — not relevant for sandwich linkage.
        let mint_hop = AuthorityHop {
            account: "MINT".into(),
            authority_type: AuthorityType::MintTokens,
            from: "OLD".into(),
            to: Some(bs58::encode(new_authority).into_string()),
            tx_signature: "tx".into(),
            slot: 1,
            tx_index: 0,
        };
        assert!(mint_hop.into_chain_signal().is_none());

        // AccountOwner with both endpoints → produces the chain signal.
        let owner_hop = AuthorityHop {
            account: "ACCT".into(),
            authority_type: AuthorityType::AccountOwner,
            from: "WALLET_A".into(),
            to: Some("WALLET_B".into()),
            tx_signature: "txhop".into(),
            slot: 1,
            tx_index: 0,
        };
        match owner_hop.into_chain_signal() {
            Some(Signal::AuthorityChain {
                from,
                to,
                authority_tx,
            }) => {
                assert_eq!(from, "WALLET_A");
                assert_eq!(to, "WALLET_B");
                assert_eq!(authority_tx, "txhop");
            }
            other => panic!("expected AuthorityChain signal, got {:?}", other),
        }
    }

    #[test]
    fn index_by_wallet_pair_groups_by_endpoints() {
        // Two hops A → B in different txs, and one A → C unrelated. Should
        // produce two index buckets.
        let hops = vec![
            AuthorityHop {
                account: "ACCT1".into(),
                authority_type: AuthorityType::AccountOwner,
                from: "A".into(),
                to: Some("B".into()),
                tx_signature: "tx1".into(),
                slot: 1,
                tx_index: 0,
            },
            AuthorityHop {
                account: "ACCT2".into(),
                authority_type: AuthorityType::AccountOwner,
                from: "A".into(),
                to: Some("B".into()),
                tx_signature: "tx2".into(),
                slot: 1,
                tx_index: 1,
            },
            AuthorityHop {
                account: "ACCT3".into(),
                authority_type: AuthorityType::AccountOwner,
                from: "A".into(),
                to: Some("C".into()),
                tx_signature: "tx3".into(),
                slot: 1,
                tx_index: 2,
            },
            // Cleared-authority hop — should be skipped (no `to` to key by).
            AuthorityHop {
                account: "ACCT4".into(),
                authority_type: AuthorityType::AccountOwner,
                from: "A".into(),
                to: None,
                tx_signature: "tx4".into(),
                slot: 1,
                tx_index: 3,
            },
        ];

        let idx = index_by_wallet_pair(hops);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx[&("A".into(), "B".into())].len(), 2);
        assert_eq!(idx[&("A".into(), "C".into())].len(), 1);
    }

    // -----------------------------------------------------------------
    // detect_authority_hop_sandwiches: the detection pass that promotes
    // wallet-mismatched candidates the sameblock detector would have
    // dropped. These tests exercise the contract a CLI integration relies
    // on — a hop in the index between front and back lifts a sandwich
    // out, evidence carries AuthorityChain so finalize classifies it as
    // AttackType::AuthorityHop.
    // -----------------------------------------------------------------

    use swap_events::types::{AttackType, DexType, SwapDirection, SwapEvent};

    fn swap(sig: &str, signer: &str, dir: SwapDirection, idx: usize) -> SwapEvent {
        SwapEvent {
            signature: sig.into(),
            signer: signer.into(),
            dex: DexType::RaydiumV4,
            pool: "POOL".into(),
            direction: dir,
            token_mint: "MINT".into(),
            amount_in: 1_000_000,
            amount_out: 900_000,
            tx_index: idx,
            slot: Some(10),
            fee: Some(5_000),
        }
    }

    fn make_hop(from: &str, to: &str, tx_sig: &str, tx_index: usize) -> AuthorityHop {
        AuthorityHop {
            account: format!("ACCT_{from}_{to}"),
            authority_type: AuthorityType::AccountOwner,
            from: from.into(),
            to: Some(to.into()),
            tx_signature: tx_sig.into(),
            slot: 10,
            tx_index,
        }
    }

    #[test]
    fn detects_authority_hop_sandwich_with_linking_hop() {
        // Frontrun by A at idx 0, hop A→B at idx 1, backrun by B at idx 3,
        // victim by V at idx 2. The sameblock detector would drop this
        // because front.signer != back.signer; the authority-hop pass
        // should surface it.
        let swaps = vec![
            swap("front", "WALLET_A", SwapDirection::Buy, 0),
            swap("victim", "VICTIM", SwapDirection::Buy, 2),
            swap("back", "WALLET_B", SwapDirection::Sell, 3),
        ];
        let hops = vec![make_hop("WALLET_A", "WALLET_B", "tx_hop", 1)];
        let idx = index_by_wallet_pair(hops);

        let res = detect_authority_hop_sandwiches(10, &swaps, &idx);
        assert_eq!(res.len(), 1);
        let s = &res[0];
        assert_eq!(s.frontrun.signer, "WALLET_A");
        assert_eq!(s.backrun.signer, "WALLET_B");
        assert_eq!(s.victim.signer, "VICTIM");
        assert_eq!(s.attacker, "WALLET_A");
        assert!(matches!(
            s.detection_method,
            Some(DetectionMethod::SameBlock)
        ));

        // Evidence must include the AuthorityChain signal — that's what
        // finalize_for_vigil reads to set AttackType::AuthorityHop.
        let ev = s.evidence.as_ref().expect("evidence attached");
        let chain = ev
            .passing
            .iter()
            .find(|sig| matches!(sig, Signal::AuthorityChain { .. }));
        assert!(chain.is_some(), "AuthorityChain signal must be in passing");
        if let Some(Signal::AuthorityChain {
            from,
            to,
            authority_tx,
        }) = chain
        {
            assert_eq!(from, "WALLET_A");
            assert_eq!(to, "WALLET_B");
            assert_eq!(authority_tx, "tx_hop");
        }

        // End-to-end classification: finalize promotes to AuthorityHop.
        let mut s = s.clone();
        s.finalize_for_vigil();
        assert_eq!(s.attack_type, Some(AttackType::AuthorityHop));
    }

    #[test]
    fn skips_when_wallet_pair_not_in_hop_index() {
        // Same triplet shape, but no hop in the index → no detection.
        let swaps = vec![
            swap("front", "WALLET_A", SwapDirection::Buy, 0),
            swap("victim", "VICTIM", SwapDirection::Buy, 2),
            swap("back", "WALLET_B", SwapDirection::Sell, 3),
        ];
        let idx = index_by_wallet_pair(vec![]);

        let res = detect_authority_hop_sandwiches(10, &swaps, &idx);
        assert!(res.is_empty());
    }

    #[test]
    fn skips_when_hop_outside_front_back_window() {
        // Hop at idx 5 lies *after* the backrun (idx 3) — can't have
        // enabled the rotation. Detector must reject.
        let swaps = vec![
            swap("front", "WALLET_A", SwapDirection::Buy, 0),
            swap("victim", "VICTIM", SwapDirection::Buy, 2),
            swap("back", "WALLET_B", SwapDirection::Sell, 3),
        ];
        let hops = vec![make_hop("WALLET_A", "WALLET_B", "tx_hop", 5)];
        let idx = index_by_wallet_pair(hops);

        let res = detect_authority_hop_sandwiches(10, &swaps, &idx);
        assert!(res.is_empty());

        // Same hop, but at idx 0 (before frontrun) — also rejected.
        let hops = vec![make_hop("WALLET_A", "WALLET_B", "tx_hop", 0)];
        let idx = index_by_wallet_pair(hops);
        // Need to bump frontrun off idx 0 so the hop is strictly before it.
        let swaps = vec![
            swap("front", "WALLET_A", SwapDirection::Buy, 1),
            swap("victim", "VICTIM", SwapDirection::Buy, 2),
            swap("back", "WALLET_B", SwapDirection::Sell, 3),
        ];
        let res = detect_authority_hop_sandwiches(10, &swaps, &idx);
        assert!(res.is_empty());
    }

    #[test]
    fn does_not_emit_when_signers_match() {
        // Same wallet for front and back — that's the sameblock detector's
        // territory, not authority-hop's. Even with a self-hop in the index
        // the authority-hop pass must stay out.
        let swaps = vec![
            swap("front", "WALLET_A", SwapDirection::Buy, 0),
            swap("victim", "VICTIM", SwapDirection::Buy, 2),
            swap("back", "WALLET_A", SwapDirection::Sell, 3),
        ];
        let hops = vec![make_hop("WALLET_A", "WALLET_A", "tx_hop", 1)];
        let idx = index_by_wallet_pair(hops);

        let res = detect_authority_hop_sandwiches(10, &swaps, &idx);
        assert!(
            res.is_empty(),
            "matching signers belong to sameblock detector"
        );
    }

    #[test]
    fn excludes_attacker_wallets_from_victim_role() {
        // A→B hop. Three "candidate victims" sit between front and back:
        // one is signed by A (sibling rotation), one by B, one by V. Only
        // V is a real victim; the A and B txs must be rejected.
        let swaps = vec![
            swap("front", "WALLET_A", SwapDirection::Buy, 0),
            swap("sibling_a", "WALLET_A", SwapDirection::Buy, 1),
            swap("victim", "VICTIM", SwapDirection::Buy, 2),
            swap("sibling_b", "WALLET_B", SwapDirection::Buy, 3),
            swap("back", "WALLET_B", SwapDirection::Sell, 5),
        ];
        let hops = vec![make_hop("WALLET_A", "WALLET_B", "tx_hop", 4)];
        let idx = index_by_wallet_pair(hops);

        let res = detect_authority_hop_sandwiches(10, &swaps, &idx);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].victim.signature, "victim");
    }

    #[test]
    fn picks_earliest_linking_hop_when_multiple() {
        // Two A→B hops in the window, at idx 1 and idx 2. The detector
        // should reference the *earliest* — that's the temporally-causal
        // one for a backrun at idx 3.
        let swaps = vec![
            swap("front", "WALLET_A", SwapDirection::Buy, 0),
            swap("victim", "VICTIM", SwapDirection::Buy, 2),
            swap("back", "WALLET_B", SwapDirection::Sell, 4),
        ];
        let hops = vec![
            make_hop("WALLET_A", "WALLET_B", "tx_late", 3),
            make_hop("WALLET_A", "WALLET_B", "tx_early", 1),
        ];
        let idx = index_by_wallet_pair(hops);

        let res = detect_authority_hop_sandwiches(10, &swaps, &idx);
        assert_eq!(res.len(), 1);
        let chain = res[0]
            .evidence
            .as_ref()
            .unwrap()
            .passing
            .iter()
            .find_map(|s| match s {
                Signal::AuthorityChain { authority_tx, .. } => Some(authority_tx.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(chain, "tx_early");
    }

    #[test]
    fn cross_pool_matches_are_not_emitted() {
        // Front in pool_A, back in pool_B with a valid hop between A and B
        // wallets. Sandwiches require same-pool — must reject.
        let mut front = swap("front", "WALLET_A", SwapDirection::Buy, 0);
        front.pool = "pool_A".into();
        let victim = swap("victim", "VICTIM", SwapDirection::Buy, 2);
        // victim sits in pool_A; back in pool_B.
        let mut victim = victim;
        victim.pool = "pool_A".into();
        let mut back = swap("back", "WALLET_B", SwapDirection::Sell, 3);
        back.pool = "pool_B".into();
        let swaps = vec![front, victim, back];
        let hops = vec![make_hop("WALLET_A", "WALLET_B", "tx_hop", 1)];
        let idx = index_by_wallet_pair(hops);

        let res = detect_authority_hop_sandwiches(10, &swaps, &idx);
        assert!(res.is_empty());
    }

    #[test]
    fn scan_block_skips_failed_transactions() {
        let new_authority = b58_dummy(0xEE);
        let ix = InstructionData {
            program_id: SPL_TOKEN_PROGRAM_ID.into(),
            accounts: vec!["ACCT".into(), "WALLET_A".into()],
            data: set_authority_data(2, Some(new_authority)),
        };
        // Two txs with the same SetAuthority — one succeeded, one failed.
        let mut tx_ok = tx_with_instructions("ok", "WALLET_A", 0, vec![ix.clone()], vec![]);
        tx_ok.success = true;
        let mut tx_fail = tx_with_instructions("fail", "WALLET_A", 1, vec![ix], vec![]);
        tx_fail.success = false;

        let block = BlockData {
            slot: 42,
            block_time: None,
            transactions: vec![tx_ok, tx_fail],
        };

        let hops = scan_block(&block);
        assert_eq!(hops.len(), 1, "failed tx must be skipped");
        assert_eq!(hops[0].tx_signature, "ok");
    }
}
