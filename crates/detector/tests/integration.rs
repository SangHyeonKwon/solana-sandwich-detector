use sandwich_detector::{
    authority_hop::{index_by_wallet_pair, scan_block, SPL_TOKEN_PROGRAM_ID},
    detector, dex, parser,
    types::*,
};

/// Build a minimal TransactionData for testing.
#[allow(clippy::too_many_arguments)]
fn make_tx(
    signature: &str,
    signer: &str,
    tx_index: usize,
    program_id: &str,
    instruction_data: Vec<u8>,
    instruction_accounts: Vec<&str>,
    token_changes: Vec<TokenBalanceChange>,
    sol_changes: Vec<SolBalanceChange>,
    fee: u64,
) -> TransactionData {
    TransactionData {
        signature: signature.to_string(),
        signer: signer.to_string(),
        success: true,
        tx_index,
        account_keys: vec![signer.to_string()],
        instructions: vec![InstructionData {
            program_id: program_id.to_string(),
            accounts: instruction_accounts.iter().map(|s| s.to_string()).collect(),
            data: instruction_data,
        }],
        inner_instructions: Vec::new(),
        token_balance_changes: token_changes,
        sol_balance_changes: sol_changes,
        fee,
        log_messages: Vec::new(),
    }
}

/// End-to-end test: Raydium V4 sandwich with wrapped SOL (token balance changes).
#[test]
fn raydium_sandwich_token_balances() {
    let pool = "PoolABC123";
    let raydium = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
    // Raydium swap discriminator = 9
    let swap_data = vec![9u8];

    let attacker = "AttackerWallet111";
    let victim = "VictimWallet222";
    let wsol = "So11111111111111111111111111111111111111112";
    let token = "TokenMintXYZ";

    // Attacker buys: spent 5 WSOL, got 1000 tokens
    let tx0 = make_tx(
        "sig_front",
        attacker,
        0,
        raydium,
        swap_data.clone(),
        vec![raydium, pool, "auth", "open_orders"],
        vec![
            TokenBalanceChange {
                mint: wsol.into(),
                account: "atk_wsol_acc".into(),
                owner: attacker.into(),
                pre_amount: 5_000_000_000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: token.into(),
                account: "atk_token_acc".into(),
                owner: attacker.into(),
                pre_amount: 0,
                post_amount: 1_000_000,
            },
        ],
        vec![],
        5000,
    );

    // Victim buys: spent 2 WSOL, got 380 tokens (worse rate due to frontrun)
    let tx1 = make_tx(
        "sig_victim",
        victim,
        1,
        raydium,
        swap_data.clone(),
        vec![raydium, pool, "auth", "open_orders"],
        vec![
            TokenBalanceChange {
                mint: wsol.into(),
                account: "vic_wsol_acc".into(),
                owner: victim.into(),
                pre_amount: 2_000_000_000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: token.into(),
                account: "vic_token_acc".into(),
                owner: victim.into(),
                pre_amount: 0,
                post_amount: 380_000,
            },
        ],
        vec![],
        5000,
    );

    // Attacker sells: spent 1000 tokens, got 5.2 WSOL
    let tx2 = make_tx(
        "sig_back",
        attacker,
        2,
        raydium,
        swap_data.clone(),
        vec![raydium, pool, "auth", "open_orders"],
        vec![
            TokenBalanceChange {
                mint: token.into(),
                account: "atk_token_acc".into(),
                owner: attacker.into(),
                pre_amount: 1_000_000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: wsol.into(),
                account: "atk_wsol_acc".into(),
                owner: attacker.into(),
                pre_amount: 0,
                post_amount: 5_200_000_000,
            },
        ],
        vec![],
        5000,
    );

    let block = BlockData {
        slot: 300_000_000,
        block_time: Some(1_700_000_000),
        transactions: vec![tx0, tx1, tx2],
    };

    let parsers = dex::all_parsers();
    let swaps: Vec<SwapEvent> = block
        .transactions
        .iter()
        .flat_map(|tx| dex::extract_swaps(tx, &parsers))
        .collect();

    assert_eq!(swaps.len(), 3, "Expected 3 swaps, got {}", swaps.len());

    let sandwiches = detector::detect_sandwiches(block.slot, &swaps);
    assert_eq!(sandwiches.len(), 1);

    let s = &sandwiches[0];
    assert_eq!(s.attacker, attacker);
    assert_eq!(s.frontrun.signature, "sig_front");
    assert_eq!(s.victim.signature, "sig_victim");
    assert_eq!(s.backrun.signature, "sig_back");
    assert_eq!(s.dex, DexType::RaydiumV4);
    assert_eq!(s.pool, pool);
    assert_eq!(s.frontrun.direction, SwapDirection::Buy);
    assert_eq!(s.backrun.direction, SwapDirection::Sell);
    // Profit = backrun.amount_out (5.2 SOL) - frontrun.amount_in (5 SOL) = 0.2 SOL
    assert_eq!(s.estimated_attacker_profit, Some(200_000_000));
}

/// End-to-end test: SOL swap (unwrapped SOL, no WSOL token balance change).
#[test]
fn sol_native_swap_detection() {
    let pool = "PoolDEF456";
    let raydium = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
    let swap_data = vec![9u8];
    let token = "TokenMintABC";
    let signer = "Trader111";

    // Signer spent native SOL (not WSOL), got tokens
    let tx = make_tx(
        "sig_sol_buy",
        signer,
        0,
        raydium,
        swap_data,
        vec![raydium, pool, "auth", "open_orders"],
        vec![
            // Only token increase — no WSOL change
            TokenBalanceChange {
                mint: token.into(),
                account: "trader_token_acc".into(),
                owner: signer.into(),
                pre_amount: 0,
                post_amount: 500_000,
            },
        ],
        vec![
            // SOL decreased (including fee)
            SolBalanceChange {
                account: signer.into(),
                pre_lamports: 10_000_000_000,
                post_lamports: 4_995_000,
            },
        ],
        5000,
    );

    let parsers = dex::all_parsers();
    let swaps: Vec<SwapEvent> = dex::extract_swaps(&tx, &parsers);

    assert_eq!(swaps.len(), 1);
    assert_eq!(swaps[0].direction, SwapDirection::Buy);
    assert_eq!(swaps[0].token_mint, token);
    // amount_in = -(sol_delta + fee) = -(4_995_000 - 10_000_000_000 + 5000)
    assert_eq!(swaps[0].amount_in, 10_000_000_000 - 4_995_000 - 5000);
}

/// No sandwich when pool can't be resolved (C1 fix verification).
#[test]
fn no_swap_when_pool_unresolvable() {
    let raydium = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
    let signer = "Trader";
    let wsol = "So11111111111111111111111111111111111111112";
    let token = "Token";

    // Instruction has no data (so discriminator check fails) → pool unresolvable
    let tx = make_tx(
        "sig_no_pool",
        signer,
        0,
        raydium,
        vec![],
        vec![raydium],
        vec![
            TokenBalanceChange {
                mint: wsol.into(),
                account: "trader_wsol_acc".into(),
                owner: signer.into(),
                pre_amount: 1000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: token.into(),
                account: "trader_token_acc".into(),
                owner: signer.into(),
                pre_amount: 0,
                post_amount: 500,
            },
        ],
        vec![],
        5000,
    );

    let parsers = dex::all_parsers();
    let swaps = dex::extract_swaps(&tx, &parsers);
    assert!(
        swaps.is_empty(),
        "Should return no swaps when pool can't be resolved"
    );
}

/// End-to-end test against a real mainnet block (slot 285000037).
/// This block has known sandwich attacks from multiple bots.
#[test]
fn mainnet_slot_285000037() {
    let json = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/slot_285000037.json"
    ))
    .expect("fixture file not found — run the fetch script first");

    let block: solana_transaction_status::UiConfirmedBlock =
        serde_json::from_str(&json).expect("failed to parse fixture JSON");

    let block_data = parser::parse_block(285000037, block).expect("parse_block failed");

    assert!(
        block_data.transactions.len() > 100,
        "expected many transactions, got {}",
        block_data.transactions.len()
    );

    let parsers = dex::all_parsers();
    let swaps: Vec<SwapEvent> = block_data
        .transactions
        .iter()
        .flat_map(|tx| dex::extract_swaps(tx, &parsers))
        .collect();

    assert!(swaps.len() > 10, "expected many swaps, got {}", swaps.len());

    let sandwiches = detector::detect_sandwiches(285000037, &swaps);

    assert!(
        !sandwiches.is_empty(),
        "expected at least 1 sandwich in this block"
    );

    // Verify basic invariants on every detected sandwich
    for s in &sandwiches {
        assert_eq!(s.slot, 285000037);
        assert_eq!(s.frontrun.signer, s.backrun.signer, "attacker mismatch");
        assert_eq!(s.frontrun.signer, s.attacker);
        assert_ne!(s.victim.signer, s.attacker, "victim == attacker");
        assert_ne!(
            s.frontrun.direction, s.backrun.direction,
            "frontrun/backrun same direction"
        );
        assert_eq!(
            s.victim.direction, s.frontrun.direction,
            "victim should match frontrun direction"
        );
        assert!(
            s.frontrun.tx_index < s.victim.tx_index,
            "frontrun must come before victim"
        );
        assert!(
            s.victim.tx_index < s.backrun.tx_index,
            "victim must come before backrun"
        );
    }

    eprintln!(
        "slot 285000037: {} txs, {} swaps, {} sandwiches",
        block_data.transactions.len(),
        swaps.len(),
        sandwiches.len()
    );
}

/// Fixture-based enrichment test: pick a Raydium V4 sandwich from the mainnet
/// block, synthesize a `PoolConfig` from the frontrun tx's vault balances, and
/// verify that pool-state enrichment produces a non-zero victim loss.
///
/// We build the `PoolConfig` ourselves instead of fetching from RPC — the real
/// vault addresses and fee rate aren't hard-coded in the fixture, and we don't
/// want network calls in tests. The two token accounts in the frontrun that
/// are NOT owned by the attacker are, by construction, the pool's vaults.
#[tokio::test]
async fn enrichment_produces_victim_loss_on_fixture() {
    use async_trait::async_trait;
    use pool_state::{enrich_attack, EnrichmentResult, PoolConfig, PoolStateLookup};
    use std::collections::HashMap;

    let json = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/slot_285000037.json"
    ))
    .expect("fixture file not found — run the fetch script first");
    let block: solana_transaction_status::UiConfirmedBlock =
        serde_json::from_str(&json).expect("failed to parse fixture JSON");
    let block_data = parser::parse_block(285000037, block).expect("parse_block failed");

    let parsers = dex::all_parsers();
    let swaps: Vec<SwapEvent> = block_data
        .transactions
        .iter()
        .flat_map(|tx| dex::extract_swaps(tx, &parsers))
        .collect();
    let sandwiches = detector::detect_sandwiches(285000037, &swaps);

    // Signature -> TransactionData lookup for frontrun tx meta
    let tx_by_sig: HashMap<_, _> = block_data
        .transactions
        .iter()
        .map(|tx| (tx.signature.clone(), tx.clone()))
        .collect();

    // Build a mock lookup that synthesizes a PoolConfig from whatever vault
    // accounts appear in each pool's frontrun tx. Keyed by pool so tests don't
    // cross-contaminate across sandwiches.
    struct FixtureLookup {
        configs: HashMap<String, PoolConfig>,
    }
    #[async_trait]
    impl PoolStateLookup for FixtureLookup {
        async fn pool_config(
            &self,
            pool: &str,
            _dex: swap_events::types::DexType,
        ) -> Option<PoolConfig> {
            self.configs.get(pool).cloned()
        }
    }

    let mut configs: HashMap<String, PoolConfig> = HashMap::new();
    let mut attempted = 0;
    let mut enriched_ok = 0;
    let mut any_loss_positive = false;

    for attack in &sandwiches {
        if attack.dex != DexType::RaydiumV4 {
            continue;
        }
        let Some(frontrun_tx) = tx_by_sig.get(&attack.frontrun.signature) else {
            continue;
        };
        // Vault token accounts = the ones NOT owned by the attacker. We expect
        // exactly two mints for a Raydium V4 pool (base + quote).
        let vault_changes: Vec<_> = frontrun_tx
            .token_balance_changes
            .iter()
            .filter(|b| b.owner != attack.attacker)
            .collect();
        let mut by_mint: HashMap<String, &TokenBalanceChange> = HashMap::new();
        for c in &vault_changes {
            by_mint.entry(c.mint.clone()).or_insert(c);
        }
        if by_mint.len() != 2 {
            continue;
        }
        let mut vaults_iter = by_mint.values();
        let v1 = vaults_iter.next().unwrap();
        let v2 = vaults_iter.next().unwrap();
        // Direction doesn't matter — whichever we pick as base, the counterfactual
        // math is symmetric; we just need consistent labeling.
        let config = PoolConfig {
            kind: pool_state::AmmKind::RaydiumV4,
            pool: attack.pool.clone(),
            vault_base: v1.account.clone(),
            vault_quote: v2.account.clone(),
            base_mint: v1.mint.clone(),
            quote_mint: v2.mint.clone(),
            fee_num: 25,
            fee_den: 10_000,
        };
        configs.insert(attack.pool.clone(), config);
    }

    let lookup = FixtureLookup { configs };

    for attack in sandwiches.clone() {
        if attack.dex != DexType::RaydiumV4 {
            continue;
        }
        let Some(frontrun_tx) = tx_by_sig.get(&attack.frontrun.signature) else {
            continue;
        };
        attempted += 1;
        let mut attack = attack;
        let res = enrich_attack(&mut attack, frontrun_tx, &lookup).await;
        if res == EnrichmentResult::Enriched {
            enriched_ok += 1;
            if attack.victim_loss_lamports.unwrap_or(0) > 0 {
                any_loss_positive = true;
            }
            // Invariants on a successful enrichment
            assert!(
                attack.price_impact_bps.is_some(),
                "price_impact_bps should be filled"
            );
            assert!(
                attack.attacker_profit.is_some(),
                "attacker_profit should be filled"
            );
            assert!(
                attack.amm_replay.is_some(),
                "amm_replay trace should be attached after enrichment"
            );
            let ev = attack
                .evidence
                .as_ref()
                .expect("evidence should be present after enrichment");
            assert!(
                ev.categories_fired >= 2,
                "enriched attack should fire in ≥2 ensemble categories (Economic + at least one other); got {}",
                ev.categories_fired
            );
        }
    }

    eprintln!(
        "enrichment: {}/{} Raydium V4 sandwiches enriched, any_loss_positive={}",
        enriched_ok, attempted, any_loss_positive
    );

    assert!(
        attempted > 0,
        "fixture should contain at least 1 Raydium V4 sandwich to test against"
    );
    assert!(
        enriched_ok > 0,
        "at least one Raydium V4 sandwich should enrich successfully"
    );
    assert!(
        any_loss_positive,
        "at least one successful enrichment should report a positive victim loss"
    );
}

/// End-to-end Authority-Hop integration: build a 4-tx block where the
/// frontrun and backrun are signed by different wallets but linked via an
/// SPL Token `SetAuthority(AccountOwner)` between them. The CLI flow
/// (extract_swaps → scan_block → detect_authority_hop_sandwiches →
/// finalize_for_vigil) must surface the triplet and classify it as
/// `AttackType::AuthorityHop`. This is the contract the CLI's
/// `process_slot` integration depends on.
#[test]
fn authority_hop_end_to_end_classifies_as_authority_hop() {
    let pool = "PoolHopXYZ";
    let raydium = "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8";
    let swap_data = vec![9u8];

    let wallet_a = "WalletA1111111111111111111111111111111111111";
    let wallet_b = "WalletB2222222222222222222222222222222222222";
    let victim_wallet = "VictimWallet33333333333333333333333333333";
    let wsol = "So11111111111111111111111111111111111111112";
    let token = "TokenMintHOP";
    // 32-byte pubkey for SetAuthority "Some(new_authority)" payload — content
    // doesn't have to decode to wallet_b; the detector keys on
    // (instruction.accounts[1], parsed_to) which is what scan_transaction
    // returns. Keep it deterministic for reproducibility.
    let new_auth_bytes: [u8; 32] = [0xAB; 32];
    let new_auth_b58 = bs58::encode(new_auth_bytes).into_string();

    // tx 0 — Wallet A frontrun (Buy)
    let tx0 = make_tx(
        "sig_hop_front",
        wallet_a,
        0,
        raydium,
        swap_data.clone(),
        vec![raydium, pool, "auth", "open_orders"],
        vec![
            TokenBalanceChange {
                mint: wsol.into(),
                account: "a_wsol_acc".into(),
                owner: wallet_a.into(),
                pre_amount: 5_000_000_000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: token.into(),
                account: "a_token_acc".into(),
                owner: wallet_a.into(),
                pre_amount: 0,
                post_amount: 1_000_000,
            },
        ],
        vec![],
        5_000,
    );

    // tx 1 — SPL Token SetAuthority(AccountOwner): A → new_auth_b58.
    // Detector keys the index by (signer_at_accounts[1], new_authority),
    // so this is what links wallet_a → new_auth_b58. Use new_auth_b58 as
    // the backrun wallet so the index lookup matches downstream.
    let mut set_auth_data = vec![6u8, 2u8, 1u8];
    set_auth_data.extend_from_slice(&new_auth_bytes);
    let tx1 = make_tx(
        "sig_hop_setauth",
        wallet_a,
        1,
        SPL_TOKEN_PROGRAM_ID,
        set_auth_data,
        vec!["a_token_acc", wallet_a],
        vec![],
        vec![],
        5_000,
    );

    // tx 2 — victim swap (Buy, same direction as A)
    let tx2 = make_tx(
        "sig_hop_victim",
        victim_wallet,
        2,
        raydium,
        swap_data.clone(),
        vec![raydium, pool, "auth", "open_orders"],
        vec![
            TokenBalanceChange {
                mint: wsol.into(),
                account: "v_wsol_acc".into(),
                owner: victim_wallet.into(),
                pre_amount: 2_000_000_000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: token.into(),
                account: "v_token_acc".into(),
                owner: victim_wallet.into(),
                pre_amount: 0,
                post_amount: 380_000,
            },
        ],
        vec![],
        5_000,
    );

    // tx 3 — backrun signed by new_auth_b58 (the wallet that received
    // ownership in tx1). Sells the position A opened.
    let tx3 = make_tx(
        "sig_hop_back",
        &new_auth_b58,
        3,
        raydium,
        swap_data,
        vec![raydium, pool, "auth", "open_orders"],
        vec![
            TokenBalanceChange {
                mint: token.into(),
                account: "a_token_acc".into(), // same account, new owner
                owner: new_auth_b58.clone(),
                pre_amount: 1_000_000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: wsol.into(),
                account: "b_wsol_acc".into(),
                owner: new_auth_b58.clone(),
                pre_amount: 0,
                post_amount: 5_200_000_000,
            },
        ],
        vec![],
        5_000,
    );
    // Sanity: never accidentally collide with wallet_a or wallet_b literals.
    let _ = wallet_b;

    let block = BlockData {
        slot: 999_999,
        block_time: Some(1_700_000_000),
        transactions: vec![tx0, tx1, tx2, tx3],
    };

    // Sameblock pass — must NOT detect (signers differ).
    let parsers = dex::all_parsers();
    let swaps: Vec<SwapEvent> = block
        .transactions
        .iter()
        .flat_map(|tx| dex::extract_swaps(tx, &parsers))
        .collect();
    assert_eq!(swaps.len(), 3, "expect 3 swap events (tx1 has no swap)");
    let sameblock = detector::detect_sandwiches(block.slot, &swaps);
    assert!(
        sameblock.is_empty(),
        "sameblock detector must drop wallet-mismatch candidates",
    );

    // Authority-Hop pass — must surface the triplet.
    let hops = scan_block(&block);
    assert!(
        hops.iter().any(|h| h.from == wallet_a),
        "scan_block should find the SetAuthority hop"
    );
    let hop_index = index_by_wallet_pair(hops);
    let hop_attacks = detector::detect_authority_hop_sandwiches(block.slot, &swaps, &hop_index);
    assert_eq!(hop_attacks.len(), 1, "exactly one authority-hop sandwich");

    let mut s = hop_attacks.into_iter().next().unwrap();
    assert_eq!(s.frontrun.signature, "sig_hop_front");
    assert_eq!(s.victim.signature, "sig_hop_victim");
    assert_eq!(s.backrun.signature, "sig_hop_back");
    assert_eq!(s.attacker, wallet_a);
    assert_ne!(s.frontrun.signer, s.backrun.signer);

    // finalize_for_vigil reads the AuthorityChain signal in evidence and
    // promotes the row to AttackType::AuthorityHop — that's the
    // CLI-visible contract Vigil's BE keys on.
    s.finalize_for_vigil();
    assert_eq!(s.attack_type, Some(AttackType::AuthorityHop));
    let receipt = s.receipts.first().expect("receipt projected");
    assert_eq!(receipt.mev_type, AttackType::AuthorityHop);
}
