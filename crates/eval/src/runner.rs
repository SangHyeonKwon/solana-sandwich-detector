use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use anyhow::Result;
use futures::stream::{self, StreamExt};
use swap_events::{
    dex::{self, DexParser},
    source::{rpc::RpcBlockSource, BlockSource},
    types::{SandwichAttack, SwapEvent},
};

use crate::jito::JitoBundleClient;
use crate::labels::LabelDataset;
use detector_window::{FilteredWindowDetector, MemoryBundleLookup, WindowDetector};

fn block_fetch_concurrency() -> usize {
    std::env::var("BLOCK_FETCH_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
}

fn jito_fetch_concurrency() -> usize {
    std::env::var("JITO_FETCH_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
}

/// Run the same-block detector on all slots referenced in the label dataset.
pub async fn run_sameblock_on_labels(
    dataset: &LabelDataset,
    rpc_url: &str,
) -> Result<Vec<SandwichAttack>> {
    let source = Arc::new(RpcBlockSource::new(rpc_url));
    let parsers = Arc::new(dex::all_parsers());

    // Collect unique slots from labels
    let slots: Vec<u64> = dataset
        .labels
        .iter()
        .map(|l| l.slot)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    tracing::info!(
        "Fetching {} unique slots (concurrency={})",
        slots.len(),
        block_fetch_concurrency()
    );

    let results: Vec<_> = stream::iter(slots)
        .map(|slot| {
            let source = Arc::clone(&source);
            let parsers = Arc::clone(&parsers);
            async move { (slot, run_slot(&source, &parsers, slot).await) }
        })
        .buffer_unordered(block_fetch_concurrency())
        .collect()
        .await;

    let mut all_attacks = Vec::new();
    for (slot, result) in results {
        match result {
            Ok(attacks) => all_attacks.extend(attacks),
            Err(e) => tracing::warn!("Slot {}: {}", slot, e),
        }
    }

    Ok(all_attacks)
}

/// Run the cross-slot window detector on all slots referenced in the label dataset.
///
/// For each labeled slot S, fetches blocks in range [S - window_slots, S + window_slots].
/// Also fetches Jito bundle data for the entire range and injects it via MemoryBundleLookup.
pub async fn run_window_on_labels(
    dataset: &LabelDataset,
    rpc_url: &str,
    window_slots: usize,
) -> Result<Vec<SandwichAttack>> {
    let source = RpcBlockSource::new(rpc_url);
    let parsers = dex::all_parsers();

    // Collect unique labeled slots and expand to fetch range
    let labeled_slots: HashSet<u64> = dataset.labels.iter().map(|l| l.slot).collect();
    let mut slots_to_fetch: HashSet<u64> = HashSet::new();
    for &slot in &labeled_slots {
        let start = slot.saturating_sub(window_slots as u64);
        let end = slot + window_slots as u64;
        for s in start..=end {
            slots_to_fetch.insert(s);
        }
    }

    let min_slot = *slots_to_fetch.iter().min().unwrap_or(&0);
    let max_slot = *slots_to_fetch.iter().max().unwrap_or(&0);

    tracing::info!(
        "Fetching {} slots (range {}..={}) for {} labeled slots with window={}",
        slots_to_fetch.len(),
        min_slot,
        max_slot,
        labeled_slots.len(),
        window_slots,
    );

    // Fetch Jito bundle data for the range (parallel by slot)
    let jito_client = Arc::new(JitoBundleClient::new());
    let jito_slots: Vec<u64> = slots_to_fetch.iter().copied().collect();
    tracing::info!(
        "Fetching Jito bundles for {} slots (concurrency={})",
        jito_slots.len(),
        jito_fetch_concurrency(),
    );

    let jito_results: Vec<_> = stream::iter(jito_slots)
        .map(|slot| {
            let client = Arc::clone(&jito_client);
            async move { client.get_bundles_for_slot(slot).await }
        })
        .buffer_unordered(jito_fetch_concurrency())
        .collect()
        .await;

    let mut tx_to_bundle: HashMap<String, String> = HashMap::new();
    let mut bundle_count = 0usize;
    let mut jito_successes = 0usize;
    let mut jito_failures = 0usize;
    for result in jito_results {
        match result {
            Ok(bundles) => {
                for bundle in &bundles {
                    for tx_sig in &bundle.transactions {
                        tx_to_bundle.insert(tx_sig.clone(), bundle.bundle_id.clone());
                    }
                }
                bundle_count += bundles.len();
                jito_successes += 1;
            }
            Err(e) => {
                tracing::warn!("Jito fetch failed: {}", e);
                jito_failures += 1;
            }
        }
    }
    if jito_successes == 0 && jito_failures > 0 {
        tracing::error!(
            "All {} Jito API requests failed — bundle provenance will be unavailable",
            jito_failures,
        );
    } else if jito_failures > jito_successes {
        tracing::warn!(
            "{}/{} Jito requests failed — bundle data is partial",
            jito_failures,
            jito_failures + jito_successes,
        );
    }
    tracing::info!(
        "Fetched {} Jito bundles ({} slots ok, {} failed)",
        bundle_count,
        jito_successes,
        jito_failures,
    );
    let lookup = MemoryBundleLookup { tx_to_bundle };

    // Create detector with bundle lookup
    let mut detector =
        FilteredWindowDetector::new(window_slots).with_bundle_lookup(Box::new(lookup));

    // Fetch blocks in parallel, extract swaps
    let source = Arc::new(source);
    let parsers = Arc::new(parsers);
    let slots_vec: Vec<u64> = slots_to_fetch.into_iter().collect();
    tracing::info!(
        "Fetching {} blocks (concurrency={})",
        slots_vec.len(),
        block_fetch_concurrency(),
    );

    let block_results: Vec<_> = stream::iter(slots_vec)
        .map(|slot| {
            let source = Arc::clone(&source);
            let parsers = Arc::clone(&parsers);
            async move {
                let result = source.get_block(slot).await.map(|block| {
                    let swaps: Vec<SwapEvent> = block
                        .transactions
                        .iter()
                        .flat_map(|tx| dex::extract_swaps(tx, &parsers))
                        .collect();
                    swaps
                });
                (slot, result)
            }
        })
        .buffer_unordered(block_fetch_concurrency())
        .collect()
        .await;

    let mut slot_swaps: BTreeMap<u64, Vec<SwapEvent>> = BTreeMap::new();
    let mut fetched_slots: HashSet<u64> = HashSet::new();
    let mut block_fail_count = 0usize;
    for (slot, result) in block_results {
        match result {
            Ok(swaps) => {
                fetched_slots.insert(slot);
                if !swaps.is_empty() {
                    slot_swaps.insert(slot, swaps);
                }
            }
            Err(e) => {
                tracing::warn!("Slot {}: {}", slot, e);
                block_fail_count += 1;
            }
        }
    }

    // CRIT 2: Check which labeled slots failed to fetch
    let missing_labeled: Vec<u64> = labeled_slots
        .iter()
        .filter(|s| !fetched_slots.contains(s))
        .copied()
        .collect();
    if !missing_labeled.is_empty() {
        tracing::error!(
            "{} labeled slot(s) failed to fetch — results will undercount: {:?}",
            missing_labeled.len(),
            missing_labeled,
        );
    }

    // MID 6: Summary log
    tracing::info!(
        "Fetched {} blocks: {} with swaps, {} empty, {} failed",
        fetched_slots.len() + block_fail_count,
        slot_swaps.len(),
        fetched_slots.len() - slot_swaps.len(),
        block_fail_count,
    );

    // Ingest slots in order
    let mut all_attacks = Vec::new();
    for (slot, swaps) in slot_swaps {
        let attacks = detector.ingest_slot(slot, swaps);
        all_attacks.extend(attacks);
    }

    // Flush remaining buffered detections
    all_attacks.extend(detector.flush());

    // Deduplicate by victim signature
    let mut seen = HashSet::new();
    all_attacks.retain(|a| seen.insert(a.victim.signature.clone()));

    tracing::info!("Window detector produced {} detections", all_attacks.len());
    Ok(all_attacks)
}

/// Run the detector on a single slot and return all detected sandwiches.
async fn run_slot(
    source: &RpcBlockSource,
    parsers: &[Box<dyn DexParser>],
    slot: u64,
) -> Result<Vec<SandwichAttack>> {
    let block = source.get_block(slot).await?;

    let swaps: Vec<SwapEvent> = block
        .transactions
        .iter()
        .flat_map(|tx| dex::extract_swaps(tx, parsers))
        .collect();

    let attacks = detector_sameblock::detect_sandwiches(slot, &swaps);
    Ok(attacks)
}
