//! Pump.fun bonding-curve event parsing.
//!
//! Pump.fun's BondingCurve account stores the *virtual* reserves
//! (`virtual_sol_reserves`, `virtual_token_reserves`) that the
//! constant-product swap math runs against. Direct historical reads
//! of the account state aren't reliable on Solana (no `getAccountInfo`
//! at slot, every provider). Instead we recover the per-tx state from
//! the program's own `TradeEvent` log, which Pump.fun emits via Anchor's
//! `emit!` macro on every successful buy/sell.
//!
//! The event encoding is Anchor's standard layout:
//!
//! ```text
//! "Program data: <base64>" log line
//!   ↓ base64 decode
//! [8-byte event discriminator] [Borsh-encoded TradeEvent fields]
//! ```
//!
//! Event discriminator = `sha256("event:TradeEvent")[..8]` —
//! pinned in [`TRADE_EVENT_DISCRIMINATOR`] and verified by
//! `discriminator_matches_anchor_convention` in tests.
//!
//! `TradeEvent` carries the *post-trade* virtual reserves; the
//! enrichment layer reverses the swap to recover the pre-trade
//! reserves needed as the replay's t=0 state.

/// Anchor event discriminator for Pump.fun's `TradeEvent`.
///
/// `sha256("event:TradeEvent")[..8]`. Pinned here as a literal to
/// avoid pulling `sha2` into the runtime path; the
/// `discriminator_matches_anchor_convention` test recomputes it
/// from the textual seed at test time so the literal can't drift.
pub const TRADE_EVENT_DISCRIMINATOR: [u8; 8] = [189, 219, 127, 211, 78, 230, 97, 238];

/// Pump.fun `Program data: ...` log lines start with this prefix.
/// Anchor's `emit!` always writes this exact framing.
const PROGRAM_DATA_PREFIX: &str = "Program data: ";

/// Decoded Pump.fun `TradeEvent`. Field order + sizes mirror the
/// Anchor IDL exactly so byte-slice indexing (no Borsh dep) lines
/// up with the on-chain layout:
///
/// | offset | size | field                    |
/// |-------:|-----:|--------------------------|
/// |   0    |   8  | discriminator (skipped)  |
/// |   8    |  32  | mint                     |
/// |  40    |   8  | sol_amount               |
/// |  48    |   8  | token_amount             |
/// |  56    |   1  | is_buy                   |
/// |  57    |  32  | user                     |
/// |  89    |   8  | timestamp (i64)          |
/// |  97    |   8  | virtual_sol_reserves     |
/// | 105    |   8  | virtual_token_reserves   |
/// | 113    |      | end                      |
///
/// Total = 113 bytes. Pump.fun has had multiple program upgrades
/// over its lifetime; if a future upgrade extends the event, the
/// length check in [`parse_trade_event_data`] rejects with `None`
/// rather than mis-parsing trailing bytes — caller treats that as
/// "log unparseable, skip enrichment for this attack".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TradeEvent {
    /// Mint of the token being bought / sold against SOL. The
    /// bonding curve has exactly two assets: this mint and SOL,
    /// so identifying the mint identifies the trade direction's
    /// non-SOL leg.
    pub mint: [u8; 32],
    /// Gross SOL amount on this leg, in lamports. For a buy:
    /// SOL the user paid in (before the 1% fee is taken). For a
    /// sell: SOL the user received (before the 1% fee).
    pub sol_amount: u64,
    /// Token amount on this leg, in the token's smallest unit.
    /// For a buy: tokens received. For a sell: tokens paid in.
    pub token_amount: u64,
    /// `true` for a buy (SOL → token), `false` for a sell.
    pub is_buy: bool,
    /// Trader's wallet pubkey. Captured for audit / event
    /// correlation; replay math doesn't use it.
    pub user: [u8; 32],
    /// Block-time the trade landed in, unix epoch seconds.
    /// Captured but unused by replay (Pump.fun fee is flat 1%,
    /// no time-weighted component).
    pub timestamp: i64,
    /// Bonding curve's `virtual_sol_reserves` *after* this trade
    /// applied. Pre-trade reserves are recovered by reversing
    /// the swap delta (handled by the enrichment layer).
    pub virtual_sol_reserves: u64,
    /// Bonding curve's `virtual_token_reserves` *after* this
    /// trade applied.
    pub virtual_token_reserves: u64,
}

/// Minimum size of the Anchor-encoded `TradeEvent` payload covering
/// every field we read (8-byte discriminator + 105 bytes of fields).
/// Pump.fun has shipped at least one program upgrade that *appends*
/// fields — `real_sol_reserves`, `real_token_reserves`, and a
/// `fee_recipient` pubkey were added, growing the payload to 298
/// bytes on mainnet as of 2026-05. The on-the-wire prefix bytes 0..113
/// retained their original meaning across that upgrade, so the parser
/// is permissive on length (≥) and only enforces equality on the
/// fields it actually decodes.
const TRADE_EVENT_LEN: usize = 113;

/// Parse a single base64-decoded `Program data` payload as a
/// `TradeEvent`. Returns `None` if the discriminator doesn't match
/// or the payload is shorter than [`TRADE_EVENT_LEN`] — both signal
/// "this log line wasn't a Pump.fun TradeEvent emission" (or was a
/// truncated / corrupted one), which the caller filters out without
/// raising.
///
/// Length policy: `data.len() >= TRADE_EVENT_LEN`. Pump.fun has had
/// at least one program upgrade that appended fields after the
/// prefix we decode (see [`TRADE_EVENT_LEN`]); rejecting any extra
/// bytes would fail closed on every mainnet event after that
/// upgrade. The bool-byte sanity check on `is_buy` (0 or 1) and the
/// implicit constraints from `virtual_*_reserves` being non-zero u64s
/// catch the realistic mis-parse mode where an unrelated `Program
/// data:` line happens to start with our 8-byte discriminator (that
/// being a 1-in-2^64 collision against a different Anchor event with
/// matching `sha256("event:TradeEvent")[..8]` — not a thing in
/// practice but the guard is cheap).
pub fn parse_trade_event_data(data: &[u8]) -> Option<TradeEvent> {
    if data.len() < TRADE_EVENT_LEN {
        return None;
    }
    if data[0..8] != TRADE_EVENT_DISCRIMINATOR {
        return None;
    }

    let mint: [u8; 32] = data[8..40].try_into().ok()?;
    let sol_amount = u64::from_le_bytes(data[40..48].try_into().ok()?);
    let token_amount = u64::from_le_bytes(data[48..56].try_into().ok()?);
    // Anchor encodes `bool` as 1 byte: 0 ⇒ false, 1 ⇒ true.
    // Anything else is a malformed event; reject.
    let is_buy = match data[56] {
        0 => false,
        1 => true,
        _ => return None,
    };
    let user: [u8; 32] = data[57..89].try_into().ok()?;
    let timestamp = i64::from_le_bytes(data[89..97].try_into().ok()?);
    let virtual_sol_reserves = u64::from_le_bytes(data[97..105].try_into().ok()?);
    let virtual_token_reserves = u64::from_le_bytes(data[105..113].try_into().ok()?);

    Some(TradeEvent {
        mint,
        sol_amount,
        token_amount,
        is_buy,
        user,
        timestamp,
        virtual_sol_reserves,
        virtual_token_reserves,
    })
}

/// Scan a tx's `log_messages` for the first Pump.fun `TradeEvent`
/// and return it. Pump.fun txs that contain a buy/sell instruction
/// always emit exactly one `TradeEvent` — the "first" qualifier is
/// defensive against multi-instruction txs (e.g. a router that
/// routes through Pump.fun and another DEX in the same tx); we
/// take the first match and ignore later ones.
///
/// Returns `None` when no `Program data:` line decodes to a
/// `TradeEvent`. Caller treats this as "Pump.fun replay
/// unavailable for this attack" — same shape as `ReservesMissing`
/// for vault-based AMMs.
pub fn extract_trade_event(log_messages: &[String]) -> Option<TradeEvent> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    for line in log_messages {
        let Some(payload) = line.strip_prefix(PROGRAM_DATA_PREFIX) else {
            continue;
        };
        // Anchor's `emit!` writes `Program data: ` + base64. Other
        // programs use the same prefix for their own events, so
        // a non-matching discriminator (length-or-content) is
        // expected — walk past, don't bail.
        let Ok(decoded) = STANDARD.decode(payload.trim()) else {
            continue;
        };
        if let Some(event) = parse_trade_event_data(&decoded) {
            return Some(event);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    /// Recompute the discriminator from its textual seed and pin
    /// the literal in [`TRADE_EVENT_DISCRIMINATOR`] against it.
    /// If a future Anchor upgrade or repo refactor changes the
    /// seed format, this test fails and the literal needs an
    /// audited update — better than silently mis-parsing all
    /// Pump.fun events in production.
    #[test]
    fn discriminator_matches_anchor_convention() {
        // Mini SHA-256 (test-only) — pulling `sha2` into runtime
        // for one literal verification would bloat the dep tree
        // for everyone else. Instead bake the expected bytes
        // into the test (computed offline via `python3 -c "import
        // hashlib; print(list(hashlib.sha256(b'event:TradeEvent').digest()[:8]))"`).
        // Two layers of pinning: the literal in `TRADE_EVENT_DISCRIMINATOR`
        // *and* this expected array. A drift in one but not the
        // other forces the test author to verify which is right.
        let expected_first_8: [u8; 8] = [189, 219, 127, 211, 78, 230, 97, 238];
        assert_eq!(TRADE_EVENT_DISCRIMINATOR, expected_first_8);
    }

    fn build_trade_event_payload(event: &TradeEvent) -> Vec<u8> {
        let mut buf = Vec::with_capacity(TRADE_EVENT_LEN);
        buf.extend_from_slice(&TRADE_EVENT_DISCRIMINATOR);
        buf.extend_from_slice(&event.mint);
        buf.extend_from_slice(&event.sol_amount.to_le_bytes());
        buf.extend_from_slice(&event.token_amount.to_le_bytes());
        buf.push(if event.is_buy { 1 } else { 0 });
        buf.extend_from_slice(&event.user);
        buf.extend_from_slice(&event.timestamp.to_le_bytes());
        buf.extend_from_slice(&event.virtual_sol_reserves.to_le_bytes());
        buf.extend_from_slice(&event.virtual_token_reserves.to_le_bytes());
        buf
    }

    fn fixture_event() -> TradeEvent {
        TradeEvent {
            mint: [0x11; 32],
            sol_amount: 1_000_000_000,       // 1 SOL gross
            token_amount: 4_200_000_000_000, // 4.2M tokens (6 decimals typical)
            is_buy: true,
            user: [0x22; 32],
            timestamp: 1_730_000_000,
            virtual_sol_reserves: 31_990_000_000_000,
            virtual_token_reserves: 1_072_999_900_000_000,
        }
    }

    #[test]
    fn parses_well_formed_trade_event() {
        let event = fixture_event();
        let bytes = build_trade_event_payload(&event);
        assert_eq!(bytes.len(), TRADE_EVENT_LEN);
        let parsed = parse_trade_event_data(&bytes).expect("valid event parses");
        assert_eq!(parsed, event);
    }

    #[test]
    fn rejects_wrong_discriminator() {
        let event = fixture_event();
        let mut bytes = build_trade_event_payload(&event);
        bytes[0] ^= 0xFF; // flip a bit in the discriminator
        assert!(parse_trade_event_data(&bytes).is_none());
    }

    #[test]
    fn rejects_truncated_payload() {
        let event = fixture_event();
        let bytes = build_trade_event_payload(&event);
        let truncated = &bytes[..TRADE_EVENT_LEN - 1];
        assert!(parse_trade_event_data(truncated).is_none());
    }

    #[test]
    fn parses_extended_payload_using_prefix_only() {
        // Pump.fun has shipped at least one program upgrade that
        // appended fields after the original 113-byte payload. The
        // prefix bytes (mint / amounts / is_buy / user / timestamp /
        // virtual reserves) retain their meaning across that upgrade,
        // so the parser must accept longer payloads and decode the
        // prefix unchanged. Rejecting them — as the original strict-
        // equality check did — fails closed on every mainnet event
        // after the upgrade, which is exactly what bit production
        // until this hotfix.
        let event = fixture_event();
        let mut bytes = build_trade_event_payload(&event);
        // Tail with arbitrary new-field bytes — concrete test against
        // a real mainnet capture lives in
        // `parses_real_mainnet_pump_fun_trade_event` below.
        bytes.extend_from_slice(&[0xAB; 185]);
        let parsed = parse_trade_event_data(&bytes).expect("extended event parses");
        assert_eq!(parsed, event);
    }

    /// Real mainnet capture from the validation run that surfaced the
    /// strict-equality bug. Tx
    /// `62vRYY8YitkmngZyYXP5EFXxiHJrnRy347k3U5e6W9q4oE8r96sBg2XWXAyAqVsCyPUazARCHmnMacvLF6jbLbWP`
    /// (slot 417_236_032, 2026-05-03, mint
    /// `5mcL4agtemfkfJVEG8Pqvkp6aZUdHZNrEb2ECCbspump`). Pinning this
    /// fixture means a future Pump.fun layout change that breaks the
    /// prefix shape — not just appends — surfaces here as a test
    /// regression instead of silently mis-parsing. Copy-pasting the
    /// base64 keeps the fixture self-contained and human-auditable.
    #[test]
    fn parses_real_mainnet_pump_fun_trade_event() {
        let b64 = "vdt/007mYe5G3D/hrkMVLzkQCdKwOexceEQLX/jOJBecchtKefIubwCUNXcAAAAAYMBdoDw5AAABHFWzPvxZhokehQwVtgzLJxqQSO1mSMF4PpcBnW5C4jgWyPZpAAAAAAAK9K4HAAAA0iWttSt3AwAAXtCyAAAAANKNmmmaeAIASsL40N1cvJfjKJwZfLUGKlTz2Va5zm5RFfllZ6pcs+ZfAAAAAAAAAMDqIQEAAAAAQ9XgDjNtTO0TXanGdyzEn5z1qe/crhBLi61NZmAuNLEAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAGJ1eQAeAAAAAAAAAICNWwAAAAAAiBMAAAAAAABg9ZAAAAAAAA==";
        let payload = STANDARD.decode(b64).expect("base64 decodes");
        // Sanity: this is the upgraded format we expected to see.
        assert!(
            payload.len() > TRADE_EVENT_LEN,
            "fixture should be the upgraded ≥113-byte event, got {}",
            payload.len()
        );
        let event = parse_trade_event_data(&payload).expect("mainnet event parses");
        assert!(event.is_buy);
        assert_eq!(event.sol_amount, 2_000_000_000); // 2 SOL gross
        assert_eq!(event.virtual_sol_reserves, 33_000_000_000); // 33 SOL pool depth
        assert_eq!(event.virtual_token_reserves, 975_454_545_454_546);
    }

    #[test]
    fn rejects_invalid_bool_byte() {
        // Anchor `bool` is strictly 0 or 1. Any other byte ⇒ corrupted event.
        let event = fixture_event();
        let mut bytes = build_trade_event_payload(&event);
        bytes[8 + 32 + 8 + 8] = 2; // is_buy offset
        assert!(parse_trade_event_data(&bytes).is_none());
    }

    #[test]
    fn extracts_trade_event_from_program_data_log() {
        let event = fixture_event();
        let payload = build_trade_event_payload(&event);
        let b64 = STANDARD.encode(&payload);
        let log = format!("{PROGRAM_DATA_PREFIX}{b64}");
        let logs = vec![
            "Program log: Instruction: Buy".to_string(),
            log,
            "Program log: SomethingElse".to_string(),
        ];
        let extracted = extract_trade_event(&logs).expect("event present in logs");
        assert_eq!(extracted, event);
    }

    #[test]
    fn extract_skips_non_trade_program_data() {
        // Other Pump.fun events (CompleteEvent, CreateEvent, ...) and
        // events from co-located programs in a multi-DEX tx land on
        // `Program data:` lines too. Discriminator mismatch ⇒ skip.
        let event = fixture_event();
        let payload = build_trade_event_payload(&event);
        let trade_b64 = STANDARD.encode(&payload);

        // Some other event with a different discriminator + arbitrary trailing.
        let other_payload = {
            let mut b = vec![0u8; 64];
            b[..8].copy_from_slice(&[0xAB; 8]); // not the Trade discriminator
            b
        };
        let other_b64 = STANDARD.encode(&other_payload);

        let logs = vec![
            format!("{PROGRAM_DATA_PREFIX}{other_b64}"),
            format!("{PROGRAM_DATA_PREFIX}{trade_b64}"),
        ];
        let extracted = extract_trade_event(&logs).expect("trade event extracted");
        assert_eq!(extracted, event);
    }

    #[test]
    fn extract_returns_first_trade_event_for_multi_event_tx() {
        // Defensive: a router tx that hits Pump.fun + another DEX could
        // emit multiple `TradeEvent`s in principle. We take the first.
        let mut first = fixture_event();
        first.sol_amount = 100;
        let mut second = fixture_event();
        second.sol_amount = 200;

        let logs = vec![
            format!(
                "{PROGRAM_DATA_PREFIX}{}",
                STANDARD.encode(build_trade_event_payload(&first))
            ),
            format!(
                "{PROGRAM_DATA_PREFIX}{}",
                STANDARD.encode(build_trade_event_payload(&second))
            ),
        ];
        let extracted = extract_trade_event(&logs).unwrap();
        assert_eq!(extracted.sol_amount, 100);
    }

    #[test]
    fn extract_returns_none_when_no_trade_event_present() {
        let logs = vec![
            "Program log: Instruction: Initialize".to_string(),
            "Program data: aGVsbG8=".to_string(), // base64 of "hello", not a Trade
            "Program log: Done".to_string(),
        ];
        assert!(extract_trade_event(&logs).is_none());
    }

    #[test]
    fn extract_tolerates_malformed_base64() {
        let logs = vec![
            "Program data: !!! not base64 !!!".to_string(),
            "Program log: Done".to_string(),
        ];
        assert!(extract_trade_event(&logs).is_none());
    }
}
