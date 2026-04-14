//! Example: embed sandwich-detector in a downstream service.
//!
//! This simulates how a product like Vigil would import and use the library.
//! Run: `cargo run --example stream_detector -- --rpc $RPC_URL`

use sandwich_detector::{
    detector,
    dex::{self, DexParser},
    source::{rpc::RpcBlockSource, BlockSource},
    types::SandwichAttack,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rpc_url = std::env::args()
        .nth(2)
        .or_else(|| std::env::var("RPC_URL").ok())
        .expect("usage: stream_detector --rpc <RPC_URL>");

    let source = RpcBlockSource::new(&rpc_url);
    let parsers = dex::all_parsers();
    let mut slot = source.get_latest_slot().await?;

    eprintln!("streaming from slot {slot}");

    loop {
        let current = source.get_latest_slot().await?;
        if current <= slot {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }

        for s in (slot + 1)..=current {
            let attacks = process_block(&source, &parsers, s).await;
            for attack in &attacks {
                // ---- This is where Vigil would persist / alert / score ----
                handle_attack(attack);
            }
        }
        slot = current;
    }
}

async fn process_block(
    source: &RpcBlockSource,
    parsers: &[Box<dyn DexParser>],
    slot: u64,
) -> Vec<SandwichAttack> {
    let block = match source.get_block(slot).await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let swaps: Vec<_> = block
        .transactions
        .iter()
        .flat_map(|tx| dex::extract_swaps(tx, parsers))
        .collect();

    detector::detect_sandwiches(slot, &swaps)
}

fn handle_attack(attack: &SandwichAttack) {
    // Downstream consumer decides what to do:
    // - insert into DB
    // - send WebSocket push to dashboard
    // - fire Slack/Discord alert
    // - compute confidence score
    // - etc.
    eprintln!(
        "[slot {}] {} sandwiched {} on {} (profit: {:?})",
        attack.slot,
        &attack.attacker[..8],
        &attack.victim.signature[..8],
        attack.dex,
        attack.estimated_attacker_profit,
    );

    // JSON line to stdout (same format as CLI)
    println!("{}", serde_json::to_string(attack).unwrap());
}
