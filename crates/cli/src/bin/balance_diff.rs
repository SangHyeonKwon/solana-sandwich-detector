//! `balance-diff` — re-validate a sandwich victim's recorded
//! `amount_out` against on-chain truth via standard `getTransaction`.
//!
//! Reads `SandwichAttack` JSONL from stdin (the same shape
//! `sandwich-detect` emits), fetches the victim transaction via
//! `getTransaction`, re-derives `amount_out` from its
//! `pre_token_balances` / `post_token_balances` using the same
//! detector heuristic, and emits a per-attack
//! [`BalanceDiffReport`] on stdout.
//!
//! ## Why this works on historical corpora
//!
//! Unlike `archival-diff` (which would need a slot-aware archival
//! account fetcher Solana RPC doesn't expose — `getAccountInfo`
//! has no historical-slot parameter on any major provider),
//! `getTransaction` is fully archival on Helius / Triton / QuickNode.
//! That means this binary can validate parser correctness on a
//! months-old mainnet sandwich corpus with the standard public RPC.
//!
//! ## What it validates
//!
//! A non-zero diff between the recorded and re-observed `amount_out`
//! points to a parser-stable failure mode: account-key drift between
//! block snapshot and tx fetch (e.g. lookup-table updates),
//! token-balance representation differences, RPC-side serialisation
//! inconsistencies. **Replay-math bugs do not show up here** — they
//! live in `archival-diff`'s reserves / sqrt_price comparison.
//!
//! ## Output shape
//!
//! One JSONL line per input record. Successful diffs:
//!
//! ```json
//! { "attack_signature": "<sig>", "victim_signature": "<sig>",
//!   "diff": { "recorded_amount_out": 500, "observed_amount_out": 500, "diff_bps": 0 } }
//! ```
//!
//! Skipped records carry a `skipped` reason (`cross_check_failed`)
//! plus an `eprintln!` describing the underlying cause so the caller
//! can audit coverage.

use std::io::{self, BufRead, Write};

use anyhow::{Context, Result};
use clap::Parser;
use pool_state::{cross_check_victim_balance, BalanceDiffReport};
use sandwich_detector::types::SandwichAttack;
use serde::Serialize;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;

#[derive(Parser)]
#[command(name = "balance-diff")]
#[command(about = "Cross-check sandwich victim recorded amount_out against on-chain truth")]
struct Cli {
    /// RPC endpoint URL. Standard `getTransaction` is sufficient — no
    /// archival-account-fetcher provider needed.
    #[arg(long, env = "RPC_URL")]
    rpc: String,
}

/// Output record. Mutually exclusive: `diff` is set on success,
/// `skipped` names the bail reason. Both never `Some` simultaneously.
#[derive(Serialize)]
struct DiffRecord {
    attack_signature: String,
    victim_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<BalanceDiffReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skipped: Option<&'static str>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client =
        RpcClient::new_with_commitment(cli.rpc.clone(), CommitmentConfig::confirmed());

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    let mut total = 0usize;
    let mut emitted = 0usize;
    let mut skipped = 0usize;

    for line in stdin.lock().lines() {
        let line = line.context("read stdin line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Header / heartbeat lines from `sandwich-detect`'s JSONL stream
        // aren't sandwich attacks — skip them silently. Same string-check
        // gate `archival-diff` uses; full deserialise of every line as
        // `SandwichAttack` would fail loudly on those.
        if trimmed.contains("\"_header\"") || trimmed.contains("\"_heartbeat\"") {
            continue;
        }

        total += 1;
        let attack: SandwichAttack = match serde_json::from_str(trimmed) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("skip: failed to parse line as SandwichAttack: {e}");
                continue;
            }
        };

        let record = process_attack(&attack, &client).await;
        if record.diff.is_some() {
            emitted += 1;
        } else {
            skipped += 1;
        }
        writeln!(stdout, "{}", serde_json::to_string(&record)?)?;
    }

    eprintln!("balance-diff: {total} processed, {emitted} diffs emitted, {skipped} skipped");
    Ok(())
}

async fn process_attack(attack: &SandwichAttack, client: &RpcClient) -> DiffRecord {
    let attack_signature = attack
        .attack_signature
        .clone()
        .unwrap_or_else(|| attack.victim.signature.clone());
    let victim_signature = attack.victim.signature.clone();
    match cross_check_victim_balance(attack, client).await {
        Some(diff) => DiffRecord {
            attack_signature,
            victim_signature,
            diff: Some(diff),
            skipped: None,
        },
        None => {
            // `cross_check_victim_balance` collapses sig-parse / fetch /
            // observation failures into a single `None`. Surface a
            // single-reason skip plus the victim sig on stderr so the
            // operator can re-run individual attacks for diagnosis.
            eprintln!(
                "skip: cross-check failed for victim sig {} (signature parse, RPC fetch, or observation)",
                victim_signature,
            );
            DiffRecord {
                attack_signature,
                victim_signature,
                diff: None,
                skipped: Some("cross_check_failed"),
            }
        }
    }
}
