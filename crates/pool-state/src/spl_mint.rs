//! SPL Token + Token-2022 mint account parsing, focused on the
//! `TransferFeeConfig` extension that DLMM Phase 3 needs to apply
//! transfer fees to swap inputs/outputs.
//!
//! # Layout
//!
//! Both legacy SPL Token and Token-2022 mints share the first 82 bytes
//! (`mint_authority_option(4) | mint_authority(32) | supply(8) |
//! decimals(1) | is_initialized(1) | freeze_authority_option(4) |
//! freeze_authority(32)`). Token-2022 mints additionally carry a
//! TLV-encoded extension area starting at offset 166 (after a
//! padding/account-type-byte block at 165).
//!
//! TLV: each entry is `[type:u16][length:u16][data; length]`. Mints
//! that lack extensions or aren't owned by the Token-2022 program
//! ([`spl_token_2022_program_id`]) carry no transfer fee.
//!
//! # Source
//!
//! Mirrors `solana-program/token-2022:interface/src/extension/`
//! TransferFeeConfig + TransferFee (`#[repr(C)]`, packed PodU16/PodU64
//! fields ⇒ byte-exact offsets):
//!
//! ```text
//!   TransferFee (18 bytes):
//!     epoch:                       u64  offset 0
//!     maximum_fee:                 u64  offset 8
//!     transfer_fee_basis_points:   u16  offset 16
//!
//!   TransferFeeConfig (108 bytes):
//!     transfer_fee_config_authority: 32  offset 0
//!     withdraw_withheld_authority:   32  offset 32
//!     withheld_amount:               u64 offset 64
//!     older_transfer_fee:            18  offset 72
//!     newer_transfer_fee:            18  offset 90
//! ```
//!
//! `ExtensionType::TransferFeeConfig` discriminator is `1`.

use std::str::FromStr;

use solana_sdk::pubkey::Pubkey;

/// Length of the mint base (legacy SPL Token mint = entire account).
pub const MINT_LEN: usize = 82;

/// Account-type byte offset in a Token-2022 mint blob. Tagged `1` =
/// Mint, `2` = Account, `0` = uninitialized.
const ACCOUNT_TYPE_OFFSET: usize = 165;

/// First TLV entry offset.
const EXTENSION_TLV_START: usize = ACCOUNT_TYPE_OFFSET + 1; // 166

/// `decimals` byte offset within the legacy mint base.
const DECIMALS_OFFSET: usize = 44;

/// `ExtensionType::TransferFeeConfig` discriminator.
const EXTENSION_TYPE_TRANSFER_FEE_CONFIG: u16 = 1;

/// Size of the `TransferFeeConfig` payload (the value bytes after the
/// 4-byte TLV header).
const TRANSFER_FEE_CONFIG_LEN: usize = 108;

/// Offset within `TransferFeeConfig` payload where `older_transfer_fee`
/// starts (`32 + 32 + 8 = 72`).
const OLDER_TRANSFER_FEE_OFFSET: usize = 72;

/// Each `TransferFee` is `8 + 8 + 2 = 18` bytes.
const TRANSFER_FEE_SIZE: usize = 18;

/// SPL Token program id (legacy). Mints owned by this program never
/// carry extensions.
pub fn spl_token_program_id() -> Pubkey {
    Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        .expect("legacy SPL Token program id is hardcoded valid base58 pubkey")
}

/// Token-2022 program id. Mints owned by this program may carry the
/// `TransferFeeConfig` extension we care about (and others we ignore).
pub fn spl_token_2022_program_id() -> Pubkey {
    Pubkey::from_str("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
        .expect("Token-2022 program id is hardcoded valid base58 pubkey")
}

/// Convenience: `mint_owner` belongs to the Token-2022 program. Legacy
/// mints (`spl_token_program_id`) skip the extension search entirely.
pub fn is_token_2022_mint(mint_owner: &Pubkey) -> bool {
    *mint_owner == spl_token_2022_program_id()
}

/// One epoch's transfer-fee configuration. `transfer_fee_basis_points`
/// is over `BASIS_POINT_MAX = 10_000`; `maximum_fee` caps the absolute
/// fee charged regardless of basis-point computation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransferFee {
    pub epoch: u64,
    pub maximum_fee: u64,
    pub transfer_fee_basis_points: u16,
}

impl TransferFee {
    /// Compute the fee charged on `amount`. Mirrors
    /// `TransferFee::calculate_fee` in spl-token-2022:
    /// `min(maximum_fee, ceil(amount * basis_points / 10_000))`.
    /// Short-circuits to 0 when `transfer_fee_basis_points == 0` —
    /// the common "no fee" config — so the ceil + cap dance only
    /// runs when there's actually a fee.
    pub fn calculate_fee(&self, amount: u64) -> Option<u64> {
        if self.transfer_fee_basis_points == 0 || amount == 0 {
            return Some(0);
        }
        let num = u128::from(amount).checked_mul(u128::from(self.transfer_fee_basis_points))?;
        let den: u128 = 10_000;
        let fee = num.checked_add(den.checked_sub(1)?)?.checked_div(den)?;
        let fee_u64: u64 = fee.try_into().ok()?;
        Some(fee_u64.min(self.maximum_fee))
    }
}

/// On-chain `TransferFeeConfig`. The extension carries two
/// `TransferFee` slots so a config update takes effect at the next
/// epoch boundary without disrupting in-flight transfers — older for
/// past epochs, newer once `current_epoch >= newer_transfer_fee.epoch`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransferFeeConfig {
    pub older_transfer_fee: TransferFee,
    pub newer_transfer_fee: TransferFee,
}

impl TransferFeeConfig {
    /// Resolve which transfer-fee tier applies at `epoch`. Mirrors
    /// `TransferFeeConfig::get_epoch_fee`.
    pub fn epoch_fee(&self, epoch: u64) -> &TransferFee {
        if epoch >= self.newer_transfer_fee.epoch {
            &self.newer_transfer_fee
        } else {
            &self.older_transfer_fee
        }
    }
}

/// Subset of a parsed mint surfacing only the fields swap-replay
/// needs. Other extensions (interest-bearing, transfer hook, etc.)
/// don't affect victim-loss math and are skipped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MintInfo {
    pub decimals: u8,
    /// Present only on Token-2022 mints with the `TransferFeeConfig`
    /// extension. Legacy SPL Token mints — and Token-2022 mints
    /// without this extension — return `None`.
    pub transfer_fee_config: Option<TransferFeeConfig>,
}

impl MintInfo {
    /// Active transfer fee at `epoch`, or `None` when the mint has
    /// no `TransferFeeConfig` extension. Convenience wrapper over the
    /// two-step `transfer_fee_config + epoch_fee` lookup.
    pub fn transfer_fee_at(&self, epoch: u64) -> Option<TransferFee> {
        self.transfer_fee_config.map(|c| *c.epoch_fee(epoch))
    }
}

/// Parse a mint account blob. Returns `None` when the blob is shorter
/// than [`MINT_LEN`]. Token-2022 extension search runs only when the
/// blob is at least [`EXTENSION_TLV_START`] bytes long *and* the
/// account-type byte at offset 165 is `1` (= Mint) — guards against
/// mis-parsing a Token-2022 token-account as a mint.
pub fn parse_mint(account_data: &[u8]) -> Option<MintInfo> {
    if account_data.len() < MINT_LEN {
        return None;
    }
    let decimals = account_data[DECIMALS_OFFSET];

    let transfer_fee_config =
        if account_data.len() > EXTENSION_TLV_START && account_data[ACCOUNT_TYPE_OFFSET] == 1 {
            find_transfer_fee_config(account_data)
        } else {
            None
        };

    Some(MintInfo {
        decimals,
        transfer_fee_config,
    })
}

/// Hard cap on TLV iteration count. Real Token-2022 mints carry at
/// most a handful of extensions (the [`ExtensionType`] enum has ~30
/// variants); a malformed blob with all-zero `length` fields would
/// otherwise let the walker grind through the entire 10MB account
/// in 4-byte steps. 64 is generous (2x the enum size).
const MAX_TLV_ITERATIONS: usize = 64;

/// Walk the TLV chain at offset 166 looking for a
/// `TransferFeeConfig` (extension type 1). Returns `None` if the
/// extension isn't present, the blob is malformed (length runs past
/// the buffer), or the payload is shorter than the expected 108 bytes.
fn find_transfer_fee_config(data: &[u8]) -> Option<TransferFeeConfig> {
    let mut cursor = EXTENSION_TLV_START;
    for _ in 0..MAX_TLV_ITERATIONS {
        if cursor + 4 > data.len() {
            return None;
        }
        let ext_type = u16::from_le_bytes(data[cursor..cursor + 2].try_into().ok()?);
        let length = u16::from_le_bytes(data[cursor + 2..cursor + 4].try_into().ok()?) as usize;
        let payload_start = cursor + 4;
        let payload_end = payload_start.checked_add(length)?;
        if payload_end > data.len() {
            return None;
        }
        // ext_type 0 (Uninitialized) ends the chain — Token-2022
        // writes zeroed trailing bytes for unused capacity.
        if ext_type == 0 {
            return None;
        }
        if ext_type == EXTENSION_TYPE_TRANSFER_FEE_CONFIG {
            if length < TRANSFER_FEE_CONFIG_LEN {
                return None;
            }
            return parse_transfer_fee_config(&data[payload_start..payload_end]);
        }
        cursor = payload_end;
    }
    None
}

fn parse_transfer_fee_config(data: &[u8]) -> Option<TransferFeeConfig> {
    if data.len() < TRANSFER_FEE_CONFIG_LEN {
        return None;
    }
    let older = parse_transfer_fee(
        &data[OLDER_TRANSFER_FEE_OFFSET..OLDER_TRANSFER_FEE_OFFSET + TRANSFER_FEE_SIZE],
    )?;
    let newer_offset = OLDER_TRANSFER_FEE_OFFSET + TRANSFER_FEE_SIZE;
    let newer = parse_transfer_fee(&data[newer_offset..newer_offset + TRANSFER_FEE_SIZE])?;
    Some(TransferFeeConfig {
        older_transfer_fee: older,
        newer_transfer_fee: newer,
    })
}

fn parse_transfer_fee(data: &[u8]) -> Option<TransferFee> {
    if data.len() < TRANSFER_FEE_SIZE {
        return None;
    }
    let epoch = u64::from_le_bytes(data[0..8].try_into().ok()?);
    let maximum_fee = u64::from_le_bytes(data[8..16].try_into().ok()?);
    let transfer_fee_basis_points = u16::from_le_bytes(data[16..18].try_into().ok()?);
    Some(TransferFee {
        epoch,
        maximum_fee,
        transfer_fee_basis_points,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Legacy SPL Token mint blob: 82 bytes, decimals at offset 44.
    /// No extension search runs ⇒ transfer_fee_config = None.
    #[test]
    fn parse_legacy_mint_returns_none_for_transfer_fee() {
        let mut data = vec![0u8; MINT_LEN];
        data[DECIMALS_OFFSET] = 9;
        let mint = parse_mint(&data).unwrap();
        assert_eq!(mint.decimals, 9);
        assert!(mint.transfer_fee_config.is_none());
    }

    /// Token-2022 mint blob without extensions (account_type=1, no
    /// TLV entries) returns `None` for transfer_fee_config — the
    /// search walks zeroed trailing bytes and bails on `ext_type == 0`.
    #[test]
    fn parse_token_2022_mint_without_extensions() {
        // Capacity beyond EXTENSION_TLV_START to trigger search.
        let mut data = vec![0u8; EXTENSION_TLV_START + 20];
        data[DECIMALS_OFFSET] = 6;
        data[ACCOUNT_TYPE_OFFSET] = 1;
        let mint = parse_mint(&data).unwrap();
        assert_eq!(mint.decimals, 6);
        assert!(mint.transfer_fee_config.is_none());
    }

    /// Token-2022 mint with a synthetic TransferFeeConfig TLV entry.
    /// Pin both the TLV walk and the per-`TransferFee` byte layout.
    #[test]
    fn parse_token_2022_mint_with_transfer_fee_config() {
        let mut data = vec![0u8; EXTENSION_TLV_START + 4 + TRANSFER_FEE_CONFIG_LEN];
        data[DECIMALS_OFFSET] = 6;
        data[ACCOUNT_TYPE_OFFSET] = 1;
        // TLV header: type=1, length=108.
        data[EXTENSION_TLV_START..EXTENSION_TLV_START + 2]
            .copy_from_slice(&EXTENSION_TYPE_TRANSFER_FEE_CONFIG.to_le_bytes());
        data[EXTENSION_TLV_START + 2..EXTENSION_TLV_START + 4]
            .copy_from_slice(&(TRANSFER_FEE_CONFIG_LEN as u16).to_le_bytes());

        let payload_start = EXTENSION_TLV_START + 4;
        // older_transfer_fee at payload+72: epoch=10, max=1_000, bp=50.
        let older_off = payload_start + OLDER_TRANSFER_FEE_OFFSET;
        data[older_off..older_off + 8].copy_from_slice(&10u64.to_le_bytes());
        data[older_off + 8..older_off + 16].copy_from_slice(&1_000u64.to_le_bytes());
        data[older_off + 16..older_off + 18].copy_from_slice(&50u16.to_le_bytes());

        // newer_transfer_fee at payload+90: epoch=20, max=2_000, bp=100.
        let newer_off = older_off + TRANSFER_FEE_SIZE;
        data[newer_off..newer_off + 8].copy_from_slice(&20u64.to_le_bytes());
        data[newer_off + 8..newer_off + 16].copy_from_slice(&2_000u64.to_le_bytes());
        data[newer_off + 16..newer_off + 18].copy_from_slice(&100u16.to_le_bytes());

        let mint = parse_mint(&data).unwrap();
        let cfg = mint.transfer_fee_config.unwrap();
        assert_eq!(cfg.older_transfer_fee.epoch, 10);
        assert_eq!(cfg.older_transfer_fee.maximum_fee, 1_000);
        assert_eq!(cfg.older_transfer_fee.transfer_fee_basis_points, 50);
        assert_eq!(cfg.newer_transfer_fee.epoch, 20);
        assert_eq!(cfg.newer_transfer_fee.maximum_fee, 2_000);
        assert_eq!(cfg.newer_transfer_fee.transfer_fee_basis_points, 100);

        // epoch=15 ⇒ older (newer.epoch=20 > 15).
        assert_eq!(cfg.epoch_fee(15).transfer_fee_basis_points, 50);
        // epoch=25 ⇒ newer.
        assert_eq!(cfg.epoch_fee(25).transfer_fee_basis_points, 100);
    }

    /// Token-2022 mint where TransferFeeConfig sits *after* another
    /// extension. Pins that the TLV walker doesn't bail at the first
    /// non-matching entry.
    #[test]
    fn parse_skips_unrelated_extension_to_find_transfer_fee_config() {
        // First entry: type=3 (MintCloseAuthority), length=32 (a Pubkey).
        // Second entry: type=1 (TransferFeeConfig), length=108.
        let unrelated_len = 32usize;
        let mut data = vec![
            0u8;
            EXTENSION_TLV_START
                + 4 + unrelated_len   // first TLV
                + 4 + TRANSFER_FEE_CONFIG_LEN
        ];
        data[ACCOUNT_TYPE_OFFSET] = 1;
        // First TLV
        data[EXTENSION_TLV_START..EXTENSION_TLV_START + 2].copy_from_slice(&3u16.to_le_bytes());
        data[EXTENSION_TLV_START + 2..EXTENSION_TLV_START + 4]
            .copy_from_slice(&(unrelated_len as u16).to_le_bytes());
        // Second TLV (TransferFeeConfig)
        let second_tlv = EXTENSION_TLV_START + 4 + unrelated_len;
        data[second_tlv..second_tlv + 2]
            .copy_from_slice(&EXTENSION_TYPE_TRANSFER_FEE_CONFIG.to_le_bytes());
        data[second_tlv + 2..second_tlv + 4]
            .copy_from_slice(&(TRANSFER_FEE_CONFIG_LEN as u16).to_le_bytes());

        let mint = parse_mint(&data).unwrap();
        assert!(mint.transfer_fee_config.is_some());
    }

    /// `TransferFee::calculate_fee` ceil-rounds and caps at
    /// `maximum_fee`. Two cases:
    ///   - 100 bp on 1_000 = exact 10, well under cap → 10.
    ///   - 100 bp on 1_001 = ceil(10.01) = 11.
    ///   - cap kicks in: 100 bp on 1_000_000 = 10_000, capped at 50 → 50.
    #[test]
    fn transfer_fee_calculate_fee_ceil_and_cap() {
        let fee = TransferFee {
            epoch: 0,
            maximum_fee: 50,
            transfer_fee_basis_points: 100,
        };
        assert_eq!(fee.calculate_fee(1_000).unwrap(), 10);
        assert_eq!(fee.calculate_fee(1_001).unwrap(), 11);
        assert_eq!(fee.calculate_fee(1_000_000).unwrap(), 50);
        // Zero-bp short-circuit.
        let zero = TransferFee {
            epoch: 0,
            maximum_fee: 0,
            transfer_fee_basis_points: 0,
        };
        assert_eq!(zero.calculate_fee(u64::MAX).unwrap(), 0);
    }

    /// `is_token_2022_mint` distinguishes the two program ids.
    #[test]
    fn token_2022_program_id_check() {
        assert!(is_token_2022_mint(&spl_token_2022_program_id()));
        assert!(!is_token_2022_mint(&spl_token_program_id()));
        assert!(!is_token_2022_mint(&Pubkey::new_unique()));
    }

    /// Short blob ⇒ None.
    #[test]
    fn rejects_short_data() {
        assert!(parse_mint(&[0u8; 10]).is_none());
    }
}
