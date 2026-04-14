use anyhow::Result;
use serde::{Deserialize, Serialize};
use swap_events::{
    dex::{self, DexParser},
    source::{rpc::RpcBlockSource, BlockSource},
    types::SwapEvent,
};

/// A sampled slot with pre-computed statistics for labeling prioritization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampledSlot {
    pub slot: u64,
    pub tx_count: usize,
    pub swap_count: usize,
    pub sameblock_candidates: usize,
    pub has_block: bool,
}

/// Output of the sampling process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleSet {
    pub start_slot: u64,
    pub end_slot: u64,
    pub requested: usize,
    pub sampled: Vec<SampledSlot>,
}

/// Sample random slots from a range, pre-analyzing each for sandwich candidates.
pub async fn sample_slots(
    rpc_url: &str,
    start_slot: u64,
    end_slot: u64,
    count: usize,
) -> Result<SampleSet> {
    use std::collections::HashSet;

    let source = RpcBlockSource::new(rpc_url);
    let parsers = dex::all_parsers();

    // Generate random slot numbers
    let range_size = end_slot - start_slot + 1;
    let mut selected: HashSet<u64> = HashSet::new();
    let mut rng_state: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    while selected.len() < count && selected.len() < range_size as usize {
        // Simple xorshift PRNG (no external dep needed)
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        let slot = start_slot + (rng_state % range_size);
        selected.insert(slot);
    }

    let mut slots: Vec<u64> = selected.into_iter().collect();
    slots.sort();

    let mut sampled = Vec::new();

    for (i, &slot) in slots.iter().enumerate() {
        tracing::info!("[{}/{}] Analyzing slot {}...", i + 1, slots.len(), slot);

        match analyze_slot(&source, &parsers, slot).await {
            Ok(info) => sampled.push(info),
            Err(e) => {
                tracing::warn!("Slot {}: {}", slot, e);
                sampled.push(SampledSlot {
                    slot,
                    tx_count: 0,
                    swap_count: 0,
                    sameblock_candidates: 0,
                    has_block: false,
                });
            }
        }
    }

    Ok(SampleSet {
        start_slot,
        end_slot,
        requested: count,
        sampled,
    })
}

async fn analyze_slot(
    source: &RpcBlockSource,
    parsers: &[Box<dyn DexParser>],
    slot: u64,
) -> Result<SampledSlot> {
    let block = source.get_block(slot).await?;
    let tx_count = block.transactions.len();

    let swaps: Vec<SwapEvent> = block
        .transactions
        .iter()
        .flat_map(|tx| dex::extract_swaps(tx, parsers))
        .collect();

    let swap_count = swaps.len();
    let sandwiches = detector_sameblock::detect_sandwiches(slot, &swaps);

    Ok(SampledSlot {
        slot,
        tx_count,
        swap_count,
        sameblock_candidates: sandwiches.len(),
        has_block: true,
    })
}
