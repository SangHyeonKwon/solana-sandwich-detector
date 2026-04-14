pub mod rpc;

use async_trait::async_trait;

use crate::error::Result;
use crate::types::BlockData;

/// Abstraction for fetching Solana blocks.
#[async_trait]
pub trait BlockSource: Send + Sync {
    /// Fetch a processed block by slot number.
    async fn get_block(&self, slot: u64) -> Result<BlockData>;

    /// Get the latest confirmed slot number.
    async fn get_latest_slot(&self) -> Result<u64>;
}
