//! `archival-diff` — compare emitted Whirlpool sandwich replays against
//! chain-observed post-state.
//!
//! Reads `SandwichAttack` JSONL from stdin (the same shape `sandwich-detect`
//! emits, plus the `whirlpool_replay` trace populated by enrichment), fetches
//! the pool account at `attack.slot + slot_offset` via the configured
//! [`AccountFetcher`], and emits a per-attack diff record on stdout.
//!
//! ## Status: placeholder fetcher
//!
//! No major Solana RPC provider exposes a `getAccountInfo`-at-historical-
//! slot method (Helius/Triton/QuickNode all serve latest-confirmed for
//! account state — `minContextSlot` is a freshness floor, not a pin;
//! `getAccountInfoAtSlot` does not exist). Real account-state archival
//! requires either ledger replay (Old Faithful + Anza Jetstreamer) or a
//! Geyser plugin capturing state in real time. Until one of those is
//! wired up, this binary's [`LatestAccountFetcher`] is a placeholder and
//! the slot argument has no effect.
//!
//! For end-to-end victim accounting validation that *does* work on
//! historical sandwich corpora today, see the sister binary
//! `balance-diff`. It validates `victim.amount_out` against on-chain
//! truth via standard `getTransaction` (fully archival on every major
//! provider) — the parser side rather than the replay side, but the
//! more practical of the two for mainnet parity work right now.
//!
//! ## Output shape
//!
//! One JSONL line per input record. Successful diffs:
//!
//! ```json
//! { "attack_signature": "<victim_sig>", "slot": 1234567, "fetched_at_slot": 1234568,
//!   "diff": { "sqrt_price_diff_bps": 100, "liquidity_diff_bps": 0, "tick_diff": 1 } }
//! ```
//!
//! Skipped records carry a `skipped` reason (`non_whirlpool`,
//! `missing_trace`, `fetch_failed`) so the caller can audit coverage
//! without re-running.

use std::io::{self, BufRead, Write};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use pool_state::{
    diff_attack_against_archival, AccountFetcher, LatestAccountFetcher, WhirlpoolDiffReport,
};
use sandwich_detector::types::{DexType, SandwichAttack};
use serde::Serialize;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;

#[derive(Parser)]
#[command(name = "archival-diff")]
#[command(about = "Compare Whirlpool sandwich replay traces against chain post-state")]
struct Cli {
    /// RPC endpoint URL. Used as the archival fetch target unless
    /// `--archival-rpc` is set.
    #[arg(long, env = "RPC_URL")]
    rpc: String,

    /// Optional dedicated archival endpoint. When provided, dynamic-state
    /// fetches go here while the default `--rpc` handles control traffic.
    /// Useful when the archival provider is metered separately or has
    /// different latency characteristics.
    #[arg(long, env = "ARCHIVAL_RPC_URL")]
    archival_rpc: Option<String>,

    /// Slot offset added to `attack.slot` for the archival fetch. Most
    /// providers serve "state at slot N" meaning "after N-1 was applied
    /// but before N", so the post-sandwich state lives at `slot + 1`.
    #[arg(long, default_value = "1")]
    slot_offset: u64,
}

/// Output record. Mutually exclusive: `diff` is set on success, `skipped`
/// names the bail reason. Both never `Some` simultaneously.
#[derive(Serialize)]
struct DiffRecord {
    attack_signature: String,
    slot: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    fetched_at_slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<WhirlpoolDiffReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skipped: Option<&'static str>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Pick the URL to actually hit for dynamic-state fetches. If
    // archival_rpc is set, route there; otherwise fall back to --rpc.
    let archival_url = cli.archival_rpc.as_deref().unwrap_or(&cli.rpc);
    let archival_client = Arc::new(RpcClient::new_with_commitment(
        archival_url.to_string(),
        CommitmentConfig::confirmed(),
    ));
    let fetcher: Arc<dyn AccountFetcher> = Arc::new(LatestAccountFetcher::new(archival_client));

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
        // aren't sandwich attacks — skip them silently. They carry a
        // distinguishing `_header` / `_heartbeat` discriminator so a
        // cheap string check is enough; full deserialise of every
        // line as `SandwichAttack` would fail loudly on those.
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

        let record = process_attack(&attack, fetcher.as_ref(), cli.slot_offset).await;
        if record.diff.is_some() {
            emitted += 1;
        } else {
            skipped += 1;
        }
        writeln!(stdout, "{}", serde_json::to_string(&record)?)?;
    }

    eprintln!("archival-diff: {total} processed, {emitted} diffs emitted, {skipped} skipped",);
    Ok(())
}

async fn process_attack(
    attack: &SandwichAttack,
    fetcher: &dyn AccountFetcher,
    slot_offset: u64,
) -> DiffRecord {
    // Pick the most stable identifier the attack carries. Vigil's
    // `attack_signature` is set post-`finalize_for_vigil`; for raw
    // detector output we fall back to the victim's tx signature.
    let attack_signature = attack
        .attack_signature
        .clone()
        .unwrap_or_else(|| attack.victim.signature.clone());
    let base = DiffRecord {
        attack_signature,
        slot: attack.slot,
        fetched_at_slot: None,
        diff: None,
        skipped: None,
    };

    if attack.dex != DexType::OrcaWhirlpool {
        return DiffRecord {
            skipped: Some("non_whirlpool"),
            ..base
        };
    }
    if attack.whirlpool_replay.is_none() {
        return DiffRecord {
            skipped: Some("missing_trace"),
            ..base
        };
    }

    let fetched_at_slot = attack.slot.saturating_add(slot_offset);
    match diff_attack_against_archival(attack, fetcher, slot_offset).await {
        Some(diff) => DiffRecord {
            fetched_at_slot: Some(fetched_at_slot),
            diff: Some(diff),
            ..base
        },
        // The library function returns `None` for any of: dex mismatch
        // (already checked above), missing trace (already checked), or
        // fetch failure / parse failure. Only the last is reachable
        // here, so attribute it accordingly.
        None => DiffRecord {
            fetched_at_slot: Some(fetched_at_slot),
            skipped: Some("fetch_failed"),
            ..base
        },
    }
}
