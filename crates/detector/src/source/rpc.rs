use async_trait::async_trait;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_config::RpcBlockConfig;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_transaction_status::{TransactionDetails, UiTransactionEncoding};

use crate::error::{DetectorError, Result};
use crate::parser;
use crate::types::BlockData;

use super::BlockSource;

pub struct RpcBlockSource {
    client: RpcClient,
}

impl RpcBlockSource {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            client: RpcClient::new_with_commitment(
                rpc_url.to_string(),
                CommitmentConfig::confirmed(),
            ),
        }
    }
}

#[async_trait]
impl BlockSource for RpcBlockSource {
    async fn get_block(&self, slot: u64) -> Result<BlockData> {
        let config = RpcBlockConfig {
            encoding: Some(UiTransactionEncoding::Json),
            transaction_details: Some(TransactionDetails::Full),
            rewards: Some(false),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        };

        let block = self
            .client
            .get_block_with_config(slot, config)
            .await
            .map_err(|e| DetectorError::Rpc(e.to_string()))?;

        parser::parse_block(slot, block)
    }

    async fn get_latest_slot(&self) -> Result<u64> {
        self.client
            .get_slot()
            .await
            .map_err(|e| DetectorError::Rpc(e.to_string()))
    }
}
