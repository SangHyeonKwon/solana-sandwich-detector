//! Jupiter V6 route extraction for enrichment dispatch.
//!
//! Jupiter V6 (`JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4`) is a
//! routing aggregator, not an AMM. A Jupiter swap CPIs into one or more
//! underlying DEX programs (Raydium V4 / CPMM / CLMM, Whirlpool, DLMM,
//! Pump.fun, Phoenix), and the resulting sandwich-attack math is a
//! sandwich on those underlying pools — not on Jupiter itself.
//!
//! This module is the route-extraction half of the Jupiter enrichment
//! pipeline: scan the tx's `inner_instructions` for known DEX swap
//! CPIs, classify the route as single-hop / multi-hop / no-DEX-cpi,
//! and surface the `(DexType, pool)` for the single-hop case so the
//! enrichment dispatch can pivot to the underlying DEX's existing
//! replay path.
//!
//! Pool-position-in-accounts knowledge is duplicated from
//! `swap_events::dex::jupiter::find_underlying_pool` — kept in lockstep
//! by the same offset comments. The call sites have different
//! semantics (detection grouping vs enrichment dispatch) so a shared
//! helper would couple two different concerns; the cost of the
//! duplication is one offset table that has to be updated in both
//! places when a new DEX joins.
//!
//! ## Multi-hop scope
//!
//! v1 single-hop only. Multi-hop attacks (Jupiter routes a swap
//! through ≥2 underlying pools, e.g. SOL→USDC→TOKEN through Raydium
//! V4 + Whirlpool) need per-leg replay + cross-leg attacker-profit
//! reconciliation — out of scope for the first cut. They surface as
//! [`RouteInfo::MultiHop`] and the dispatch maps them to a recognisable
//! metric bucket rather than enriching with wrong numbers.

use swap_events::types::{DexType, TransactionData};

/// Outcome of scanning a Jupiter V6 swap's `inner_instructions` for
/// the underlying DEX dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteInfo {
    /// Exactly one distinct underlying `(dex, pool)` was identified —
    /// the enrichment layer can dispatch to that DEX's existing
    /// replay path with this pool override.
    SingleHop { dex: DexType, pool: String },
    /// Two or more distinct underlying pools / DEXes — Jupiter routed
    /// through a chain (or a split + recombine). Out of scope for
    /// v1 enrichment.
    MultiHop {
        /// Count of *distinct* `(dex, pool)` tuples seen in the
        /// inner instructions. Useful telemetry for sizing a future
        /// multi-hop replay implementation; not used by the current
        /// dispatch beyond ≥2 ⇒ short-circuit.
        distinct_count: usize,
    },
    /// No CPI to a known DEX — either Jupiter dispatched to a DEX
    /// we don't yet recognise, or the tx isn't actually a Jupiter
    /// swap (parser false positive / instruction reorder). Caller
    /// treats this like `ReservesMissing`.
    NoDexCpi,
}

/// Scan a Jupiter V6 tx's `inner_instructions` for underlying DEX
/// CPIs and classify the route. See [`RouteInfo`] for the variants.
///
/// The classification dedups by `(dex, pool)` — a Jupiter swap that
/// CPIs to the same Raydium V4 pool twice (e.g. for compute-budget
/// reasons) registers as single-hop, not multi-hop. Distinct pools
/// even within the same DEX program (e.g. two different Whirlpool
/// pools on the route) count as separate hops.
pub fn extract_route(tx: &TransactionData) -> RouteInfo {
    let mut hops: Vec<(DexType, String)> = Vec::new();
    for group in &tx.inner_instructions {
        for ix in &group.instructions {
            let Some(hop) = identify_dex_swap(&ix.program_id, &ix.data, &ix.accounts) else {
                continue;
            };
            // Dedup by (dex, pool) — same pool re-touched within one
            // route is still single-hop.
            if !hops.contains(&hop) {
                hops.push(hop);
            }
        }
    }
    match hops.len() {
        0 => RouteInfo::NoDexCpi,
        1 => {
            let (dex, pool) = hops.into_iter().next().expect("len == 1");
            RouteInfo::SingleHop { dex, pool }
        }
        n => RouteInfo::MultiHop { distinct_count: n },
    }
}

/// Recognise a single inner instruction as a swap on a known DEX
/// and return `(dex_type, pool_address)`. Mirrors the per-DEX
/// program-id + pool-position table in
/// `swap_events::dex::jupiter::find_underlying_pool`. None for any
/// non-DEX instruction.
fn identify_dex_swap(
    program_id: &str,
    data: &[u8],
    accounts: &[String],
) -> Option<(DexType, String)> {
    use swap_events::dex::jupiter::JUPITER_V6_PROGRAM_ID;
    use swap_events::dex::meteora::METEORA_DLMM_PROGRAM_ID;
    use swap_events::dex::orca::ORCA_WHIRLPOOL_PROGRAM_ID;
    use swap_events::dex::phoenix::PHOENIX_PROGRAM_ID;
    use swap_events::dex::pumpfun::PUMPFUN_PROGRAM_ID;
    use swap_events::dex::raydium::RAYDIUM_V4_PROGRAM_ID;
    use swap_events::dex::raydium_clmm::RAYDIUM_CLMM_PROGRAM_ID;
    use swap_events::dex::raydium_cpmm::RAYDIUM_CPMM_PROGRAM_ID;

    // Skip Jupiter's own self-CPIs — those are routing-internal and
    // don't represent an underlying-pool hop.
    if program_id == JUPITER_V6_PROGRAM_ID {
        return None;
    }

    // Raydium V4 swap (discriminator 9), pool at accounts[1].
    if program_id == RAYDIUM_V4_PROGRAM_ID && data.first() == Some(&9) && accounts.len() > 1 {
        return Some((DexType::RaydiumV4, accounts[1].clone()));
    }

    // Raydium CLMM, pool at accounts[1]. Anchor disc ≥ 8 bytes
    // catches the swap variants without enumerating each.
    if program_id == RAYDIUM_CLMM_PROGRAM_ID && data.len() >= 8 && accounts.len() > 1 {
        return Some((DexType::RaydiumClmm, accounts[1].clone()));
    }

    // Raydium CPMM, pool at accounts[2].
    if program_id == RAYDIUM_CPMM_PROGRAM_ID && data.len() >= 8 && accounts.len() > 2 {
        return Some((DexType::RaydiumCpmm, accounts[2].clone()));
    }

    // Whirlpool swap discriminator (`global:swap`'s sha256[..8]),
    // pool at accounts[2]. Filtering by discriminator avoids
    // matching `init_pool` / liquidity admin instructions.
    if program_id == ORCA_WHIRLPOOL_PROGRAM_ID && data.len() >= 8 {
        const WHIRLPOOL_SWAP_DISC: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];
        if data[..8] == WHIRLPOOL_SWAP_DISC && accounts.len() > 2 {
            return Some((DexType::OrcaWhirlpool, accounts[2].clone()));
        }
    }

    // Meteora DLMM, lb_pair at accounts[0].
    if program_id == METEORA_DLMM_PROGRAM_ID && !accounts.is_empty() {
        return Some((DexType::MeteoraDlmm, accounts[0].clone()));
    }

    // Pump.fun, bonding curve at accounts[2].
    if program_id == PUMPFUN_PROGRAM_ID && data.len() >= 8 && accounts.len() > 2 {
        return Some((DexType::PumpFun, accounts[2].clone()));
    }

    // Phoenix, market at accounts[0].
    if program_id == PHOENIX_PROGRAM_ID && !accounts.is_empty() {
        return Some((DexType::Phoenix, accounts[0].clone()));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_events::types::{InnerInstructionGroup, InstructionData};

    fn make_ix(program_id: &str, data: Vec<u8>, accounts: Vec<&str>) -> InstructionData {
        InstructionData {
            program_id: program_id.to_string(),
            accounts: accounts.into_iter().map(String::from).collect(),
            data,
        }
    }

    fn make_tx(inner_groups: Vec<Vec<InstructionData>>) -> TransactionData {
        TransactionData {
            signature: "sig".into(),
            signer: "signer".into(),
            success: true,
            tx_index: 0,
            account_keys: vec![],
            instructions: vec![],
            inner_instructions: inner_groups
                .into_iter()
                .enumerate()
                .map(|(idx, instructions)| InnerInstructionGroup {
                    index: idx as u8,
                    instructions,
                })
                .collect(),
            token_balance_changes: vec![],
            sol_balance_changes: vec![],
            fee: 5000,
            log_messages: vec![],
        }
    }

    #[test]
    fn single_raydium_v4_cpi_classifies_as_single_hop() {
        use swap_events::dex::raydium::RAYDIUM_V4_PROGRAM_ID;
        let tx = make_tx(vec![vec![make_ix(
            RAYDIUM_V4_PROGRAM_ID,
            vec![9, 0, 0, 0],
            vec!["x", "POOL_V4", "y"],
        )]]);
        assert_eq!(
            extract_route(&tx),
            RouteInfo::SingleHop {
                dex: DexType::RaydiumV4,
                pool: "POOL_V4".to_string(),
            }
        );
    }

    #[test]
    fn single_whirlpool_cpi_classifies_as_single_hop() {
        use swap_events::dex::orca::ORCA_WHIRLPOOL_PROGRAM_ID;
        const WHIRLPOOL_SWAP_DISC: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];
        let tx = make_tx(vec![vec![make_ix(
            ORCA_WHIRLPOOL_PROGRAM_ID,
            WHIRLPOOL_SWAP_DISC.to_vec(),
            vec!["x", "y", "POOL_WP", "z"],
        )]]);
        assert_eq!(
            extract_route(&tx),
            RouteInfo::SingleHop {
                dex: DexType::OrcaWhirlpool,
                pool: "POOL_WP".to_string(),
            }
        );
    }

    #[test]
    fn multiple_distinct_dex_cpis_classify_as_multi_hop() {
        // Jupiter route SOL → USDC → TOKEN through Raydium V4 + Whirlpool.
        use swap_events::dex::orca::ORCA_WHIRLPOOL_PROGRAM_ID;
        use swap_events::dex::raydium::RAYDIUM_V4_PROGRAM_ID;
        const WHIRLPOOL_SWAP_DISC: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];
        let tx = make_tx(vec![vec![
            make_ix(
                RAYDIUM_V4_PROGRAM_ID,
                vec![9, 0, 0, 0],
                vec!["x", "POOL_V4", "y"],
            ),
            make_ix(
                ORCA_WHIRLPOOL_PROGRAM_ID,
                WHIRLPOOL_SWAP_DISC.to_vec(),
                vec!["x", "y", "POOL_WP", "z"],
            ),
        ]]);
        assert_eq!(extract_route(&tx), RouteInfo::MultiHop { distinct_count: 2 });
    }

    #[test]
    fn duplicate_cpi_to_same_pool_dedups_to_single_hop() {
        // A Jupiter route may CPI to the same pool twice for compute-
        // budget reasons. Same `(dex, pool)` ⇒ still single-hop.
        use swap_events::dex::raydium::RAYDIUM_V4_PROGRAM_ID;
        let ix = make_ix(
            RAYDIUM_V4_PROGRAM_ID,
            vec![9, 0, 0, 0],
            vec!["x", "POOL_V4", "y"],
        );
        let tx = make_tx(vec![vec![ix.clone(), ix]]);
        assert_eq!(
            extract_route(&tx),
            RouteInfo::SingleHop {
                dex: DexType::RaydiumV4,
                pool: "POOL_V4".to_string(),
            }
        );
    }

    #[test]
    fn two_distinct_pools_on_same_dex_classify_as_multi_hop() {
        // Jupiter route through two different Whirlpool pools — same DEX
        // program, distinct pool addresses ⇒ multi-hop, not single.
        use swap_events::dex::orca::ORCA_WHIRLPOOL_PROGRAM_ID;
        const WHIRLPOOL_SWAP_DISC: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];
        let tx = make_tx(vec![vec![
            make_ix(
                ORCA_WHIRLPOOL_PROGRAM_ID,
                WHIRLPOOL_SWAP_DISC.to_vec(),
                vec!["x", "y", "POOL_WP_A", "z"],
            ),
            make_ix(
                ORCA_WHIRLPOOL_PROGRAM_ID,
                WHIRLPOOL_SWAP_DISC.to_vec(),
                vec!["x", "y", "POOL_WP_B", "z"],
            ),
        ]]);
        assert_eq!(extract_route(&tx), RouteInfo::MultiHop { distinct_count: 2 });
    }

    #[test]
    fn no_dex_cpi_returns_no_dex_cpi() {
        // System program transfer + token program — nothing routable.
        let tx = make_tx(vec![vec![
            make_ix("11111111111111111111111111111111", vec![2, 0, 0, 0], vec!["x", "y"]),
            make_ix(
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                vec![3],
                vec!["x", "y", "z"],
            ),
        ]]);
        assert_eq!(extract_route(&tx), RouteInfo::NoDexCpi);
    }

    #[test]
    fn jupiter_self_cpis_are_skipped() {
        // Jupiter's internal self-CPIs (e.g. for routing logic) shouldn't
        // count as hops — only real underlying-DEX swaps do.
        use swap_events::dex::jupiter::JUPITER_V6_PROGRAM_ID;
        use swap_events::dex::raydium::RAYDIUM_V4_PROGRAM_ID;
        let tx = make_tx(vec![vec![
            make_ix(JUPITER_V6_PROGRAM_ID, vec![1, 2, 3], vec!["x", "y"]),
            make_ix(
                RAYDIUM_V4_PROGRAM_ID,
                vec![9, 0, 0, 0],
                vec!["x", "POOL_V4", "y"],
            ),
        ]]);
        assert_eq!(
            extract_route(&tx),
            RouteInfo::SingleHop {
                dex: DexType::RaydiumV4,
                pool: "POOL_V4".to_string(),
            }
        );
    }

    #[test]
    fn empty_inner_instructions_returns_no_dex_cpi() {
        let tx = make_tx(vec![]);
        assert_eq!(extract_route(&tx), RouteInfo::NoDexCpi);
    }

    #[test]
    fn raydium_v4_with_wrong_discriminator_skipped() {
        // Discriminator != 9 ⇒ not a swap (could be deposit / withdraw / init).
        use swap_events::dex::raydium::RAYDIUM_V4_PROGRAM_ID;
        let tx = make_tx(vec![vec![make_ix(
            RAYDIUM_V4_PROGRAM_ID,
            vec![3, 0, 0, 0], // some other Raydium V4 ix
            vec!["x", "POOL_V4", "y"],
        )]]);
        assert_eq!(extract_route(&tx), RouteInfo::NoDexCpi);
    }

    #[test]
    fn cross_dex_route_dlmm_to_pumpfun_classifies_as_multi_hop() {
        use swap_events::dex::meteora::METEORA_DLMM_PROGRAM_ID;
        use swap_events::dex::pumpfun::PUMPFUN_PROGRAM_ID;
        let tx = make_tx(vec![vec![
            make_ix(METEORA_DLMM_PROGRAM_ID, vec![0; 8], vec!["LB_PAIR"]),
            make_ix(
                PUMPFUN_PROGRAM_ID,
                vec![0; 8],
                vec!["x", "y", "BC_POOL", "z"],
            ),
        ]]);
        assert_eq!(extract_route(&tx), RouteInfo::MultiHop { distinct_count: 2 });
    }
}
