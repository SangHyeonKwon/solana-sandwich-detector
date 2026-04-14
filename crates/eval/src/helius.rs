use anyhow::{Context, Result};
use serde::Deserialize;

/// Helius Enhanced Transactions API client.
/// Provides human-readable transaction descriptions to accelerate labeling.
pub struct HeliusClient {
    client: reqwest::Client,
    api_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeliusTransaction {
    pub signature: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "type", default)]
    pub tx_type: String,
    #[serde(default)]
    pub fee: u64,
    #[serde(default)]
    pub fee_payer: String,
    #[serde(default)]
    pub slot: u64,
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default)]
    pub token_transfers: Vec<HeliusTokenTransfer>,
    #[serde(default)]
    pub native_transfers: Vec<HeliusNativeTransfer>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeliusTokenTransfer {
    #[serde(default)]
    pub from_user_account: String,
    #[serde(default)]
    pub to_user_account: String,
    #[serde(default)]
    pub mint: String,
    #[serde(default)]
    pub token_amount: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeliusNativeTransfer {
    #[serde(default)]
    pub from_user_account: String,
    #[serde(default)]
    pub to_user_account: String,
    #[serde(default)]
    pub amount: u64,
}

impl HeliusClient {
    pub fn new(api_key: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key: api_key.to_string(),
        }
    }

    /// Fetch enhanced transaction data for a batch of signatures (up to 100).
    pub async fn get_parsed_transactions(
        &self,
        signatures: &[String],
    ) -> Result<Vec<HeliusTransaction>> {
        let url = format!(
            "https://api.helius.xyz/v0/transactions?api-key={}",
            self.api_key
        );

        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "transactions": signatures }))
            .send()
            .await
            .context("Helius API request failed")?;

        resp.error_for_status_ref()
            .context("Helius API returned error")?;

        let txs: Vec<HeliusTransaction> = resp
            .json()
            .await
            .context("Failed to parse Helius response")?;

        Ok(txs)
    }

    /// Fetch a single transaction.
    pub async fn get_parsed_transaction(&self, sig: &str) -> Result<HeliusTransaction> {
        let txs = self.get_parsed_transactions(&[sig.to_string()]).await?;

        txs.into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No transaction found for {}", sig))
    }
}

/// Format a Helius transaction for display during labeling.
pub fn format_for_labeling(tx: &HeliusTransaction) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "  Sig:  {}...{}\n",
        &tx.signature[..8],
        &tx.signature[tx.signature.len().saturating_sub(8)..]
    ));
    out.push_str(&format!(
        "  Type: {} | Fee payer: {}...\n",
        tx.tx_type,
        &tx.fee_payer[..8.min(tx.fee_payer.len())]
    ));
    out.push_str(&format!("  Desc: {}\n", tx.description));

    if !tx.token_transfers.is_empty() {
        out.push_str("  Token transfers:\n");
        for t in &tx.token_transfers {
            out.push_str(&format!(
                "    {:.6} {} from {}... -> {}...\n",
                t.token_amount,
                &t.mint[..8.min(t.mint.len())],
                &t.from_user_account[..8.min(t.from_user_account.len())],
                &t.to_user_account[..8.min(t.to_user_account.len())],
            ));
        }
    }

    if !tx.native_transfers.is_empty() {
        out.push_str("  SOL transfers:\n");
        for t in &tx.native_transfers {
            out.push_str(&format!(
                "    {} lamports from {}... -> {}...\n",
                t.amount,
                &t.from_user_account[..8.min(t.from_user_account.len())],
                &t.to_user_account[..8.min(t.to_user_account.len())],
            ));
        }
    }

    out
}
