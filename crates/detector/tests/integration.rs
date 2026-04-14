use sandwich_detector::{detector, dex, parser, types::*};

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
                owner: attacker.into(),
                pre_amount: 5_000_000_000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: token.into(),
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
                owner: victim.into(),
                pre_amount: 2_000_000_000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: token.into(),
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
                owner: attacker.into(),
                pre_amount: 1_000_000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: wsol.into(),
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
                owner: signer.into(),
                pre_amount: 1000,
                post_amount: 0,
            },
            TokenBalanceChange {
                mint: token.into(),
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
