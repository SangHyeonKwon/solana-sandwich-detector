use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A single Jito bundle as returned by the bundle history API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitoBundle {
    /// Bundle UUID.
    pub bundle_id: String,
    /// Slot where the bundle landed.
    pub slot: u64,
    /// Transaction signatures in execution order.
    pub transactions: Vec<String>,
    /// Tip paid in lamports.
    #[serde(default)]
    pub landed_tip_lamports: u64,
}

/// A sandwich identified purely from bundle structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSandwich {
    pub bundle_id: String,
    pub slot: u64,
    pub frontrun_sig: String,
    pub victim_sigs: Vec<String>,
    pub backrun_sig: String,
}

pub struct JitoBundleClient {
    client: reqwest::Client,
    base_url: String,
}

impl Default for JitoBundleClient {
    fn default() -> Self {
        Self::new()
    }
}

impl JitoBundleClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: "https://bundles.jito.wtf/api/v1/bundles".to_string(),
        }
    }

    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.to_string(),
        }
    }

    /// Fetch all bundles that landed in the given slot.
    /// Retries up to 3 times on HTTP 429 (rate limit) with exponential backoff.
    pub async fn get_bundles_for_slot(&self, slot: u64) -> Result<Vec<JitoBundle>> {
        let url = format!("{}/slot/{}", self.base_url, slot);
        let mut attempts = 0u32;
        loop {
            let resp = self
                .client
                .get(&url)
                .send()
                .await
                .context("Jito API request failed")?;

            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(Vec::new());
            }

            if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                attempts += 1;
                if attempts >= 3 {
                    anyhow::bail!(
                        "Jito API rate limited after {} attempts for slot {}",
                        attempts,
                        slot,
                    );
                }
                let backoff = std::time::Duration::from_millis(500 * 2u64.pow(attempts));
                tracing::debug!("Jito 429 for slot {}, retrying in {:?}", slot, backoff);
                tokio::time::sleep(backoff).await;
                continue;
            }

            resp.error_for_status_ref()
                .context("Jito API returned error")?;

            let bundles: Vec<JitoBundle> =
                resp.json().await.context("Failed to parse Jito response")?;
            return Ok(bundles);
        }
    }

    /// Fetch bundles for a range of slots.
    pub async fn get_bundles_for_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<JitoBundle>> {
        let mut all_bundles = Vec::new();
        for slot in start..=end {
            match self.get_bundles_for_slot(slot).await {
                Ok(bundles) => all_bundles.extend(bundles),
                Err(e) => {
                    tracing::warn!("Slot {}: {}", slot, e);
                }
            }
        }
        Ok(all_bundles)
    }
}

/// Identify potential sandwich bundles from a list of Jito bundles.
///
/// A bundle is considered a potential sandwich if:
/// - It contains >= 3 transactions
/// - The first and last transaction share the same signer (attacker)
/// - There is at least one middle transaction from a different signer (victim)
///
/// Note: this is a structural heuristic. Full confirmation requires checking
/// swap directions, which needs the swap-events parser.
pub fn identify_sandwich_bundles(
    bundles: &[JitoBundle],
    signer_lookup: &dyn Fn(&str) -> Option<String>,
) -> Vec<BundleSandwich> {
    let mut results = Vec::new();

    for bundle in bundles {
        if bundle.transactions.len() < 3 {
            continue;
        }

        let first_sig = &bundle.transactions[0];
        let last_sig = bundle.transactions.last().unwrap();

        let Some(first_signer) = signer_lookup(first_sig) else {
            continue;
        };
        let Some(last_signer) = signer_lookup(last_sig) else {
            continue;
        };

        // First and last must share the same signer (attacker)
        if first_signer != last_signer {
            continue;
        }

        // Middle transactions must include at least one different signer (victim)
        let victim_sigs: Vec<String> = bundle.transactions[1..bundle.transactions.len() - 1]
            .iter()
            .filter(|sig| {
                signer_lookup(sig)
                    .map(|s| s != first_signer)
                    .unwrap_or(false)
            })
            .cloned()
            .collect();

        if victim_sigs.is_empty() {
            continue;
        }

        results.push(BundleSandwich {
            bundle_id: bundle.bundle_id.clone(),
            slot: bundle.slot,
            frontrun_sig: first_sig.clone(),
            victim_sigs,
            backrun_sig: last_sig.clone(),
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_sandwich_bundle() {
        let bundles = vec![JitoBundle {
            bundle_id: "bundle-1".into(),
            slot: 100,
            transactions: vec!["tx1".into(), "tx2".into(), "tx3".into()],
            landed_tip_lamports: 5000,
        }];

        let lookup = |sig: &str| -> Option<String> {
            match sig {
                "tx1" | "tx3" => Some("attacker".into()),
                "tx2" => Some("victim".into()),
                _ => None,
            }
        };

        let results = identify_sandwich_bundles(&bundles, &lookup);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].frontrun_sig, "tx1");
        assert_eq!(results[0].victim_sigs, vec!["tx2"]);
        assert_eq!(results[0].backrun_sig, "tx3");
    }

    #[test]
    fn rejects_same_signer_bundle() {
        let bundles = vec![JitoBundle {
            bundle_id: "bundle-2".into(),
            slot: 100,
            transactions: vec!["tx1".into(), "tx2".into(), "tx3".into()],
            landed_tip_lamports: 5000,
        }];

        // All same signer
        let lookup = |_sig: &str| -> Option<String> { Some("same".into()) };
        let results = identify_sandwich_bundles(&bundles, &lookup);
        assert!(results.is_empty());
    }

    #[test]
    fn rejects_small_bundle() {
        let bundles = vec![JitoBundle {
            bundle_id: "bundle-3".into(),
            slot: 100,
            transactions: vec!["tx1".into(), "tx2".into()],
            landed_tip_lamports: 5000,
        }];

        let lookup = |sig: &str| -> Option<String> {
            match sig {
                "tx1" => Some("a".into()),
                "tx2" => Some("b".into()),
                _ => None,
            }
        };
        let results = identify_sandwich_bundles(&bundles, &lookup);
        assert!(results.is_empty());
    }
}
