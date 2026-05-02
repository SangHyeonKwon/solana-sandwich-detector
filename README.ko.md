<p align="center">
  <h1 align="center">solana-sandwich-detector</h1>
  <p align="center">
    솔라나의 same-block / cross-slot 샌드위치 공격을 탐지하는 Rust 라이브러리.<br/>
    8개 DEX의 swap 이벤트를 파싱하고, 슬라이딩 윈도우 상관·정밀 필터·AMM 정확 재연(replay)으로 frontrun/victim/backrun 패턴을 식별합니다.
  </p>
</p>

<p align="center">
  <a href="README.md">English</a> &middot;
  <strong>한국어</strong> &middot;
  <a href="README.es.md">Español</a>
</p>

<p align="center">
  <a href="https://github.com/SangHyeonKwon/solana-sandwich-detector/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/SangHyeonKwon/solana-sandwich-detector/ci.yml?style=for-the-badge&label=CI" alt="CI" /></a>
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/Solana-9945FF?style=for-the-badge&logo=solana&logoColor=white" alt="Solana" />
  <img src="https://img.shields.io/badge/Tokio-232323?style=for-the-badge&logo=rust&logoColor=white" alt="Tokio" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License" />
</p>

<p align="center">
  <a href="#빠른-시작">빠른 시작</a> &middot;
  <a href="#동작-원리">동작 원리</a> &middot;
  <a href="#vigil-통합">Vigil 통합</a> &middot;
  <a href="#라이브러리로-사용">라이브러리</a> &middot;
  <a href="#범위">범위</a> &middot;
  <a href="#기여">기여</a>
</p>

---

샌드위치 공격은 솔라나에서 가장 흔한 MEV 추출 패턴입니다. 공격자는 피해자의 swap을 앞질러 frontrun으로 가격을 밀고, 뒤이은 backrun으로 차익을 회수합니다 — 같은 블록 안에서, 또는 인접한 슬롯에 걸쳐서.

**solana-sandwich-detector**는 솔라나 블록 스트림을 탐지된 공격의 스트림으로 변환하는 Rust 라이브러리입니다. **same-block 탐지**(고전적 단일 슬롯 패턴)와 **cross-slot 윈도우 탐지**(여러 슬롯에 걸친 공격, Jito 번들 출처·경제적 타당성·피해자 그럴듯함 필터 포함)를 모두 지원합니다. AMM 재연 enrichment는 단순 `amount_out - amount_in` 휴리스틱이 아닌 *실제 victim loss*를 계산합니다. 스트리밍 CLI(`sandwich-detect`), 평가 프레임워크(`sandwich-eval`), 두 개의 diff 도구(`balance-diff`로 parser-vs-RPC victim 교차검증; `archival-diff`로 replay-vs-chain pool-state 비교 — 현재 placeholder, Solana RPC가 노출하지 않는 archival account fetcher 대기 중)가 함께 제공됩니다.

> [Vigil](https://github.com/EarthIsMine/Vigil-RPC) — 솔라나 MEV 투명성 플랫폼 — 의 탐지 primitive로 사용됩니다. 검증인 점수·영속성·알림·대시보드는 Vigil에 살고, 이 저장소는 **stream-in → stream-out**에 집중합니다. [범위](#범위) 및 [Vigil 통합](#vigil-통합) 참조.

### 지원 DEX

| DEX | Swap 이벤트 파싱 | AMM 재연 (victim loss) |
|-----|------------------|------------------------|
| Raydium V4 | Direct + CPI | ✅ Constant product |
| Raydium CPMM | Direct + CPI | ✅ Constant product |
| Raydium CLMM | Direct + CPI | — |
| Orca Whirlpool | Direct + CPI | ✅ Concentrated, within-tick + cross-tick |
| Meteora DLMM | Direct + CPI | ✅ Constant-sum, within-bin + cross-bin |
| Jupiter V6 | Route-through (underlying pool 해석) | (underlying pool 경유) |
| Pump.fun | Direct + CPI | — |
| Phoenix | Direct + CPI | — |

> 새 DEX 추가는 swap 파싱이 ~50줄, replay 지원은 별도 모듈. [기여](#기여) 참조.

---

## 빠른 시작

`sandwich-detect`은 라이브러리를 감싼 스트리밍 CLI입니다 — 스모크 테스트, 임시 분석, 다른 도구(Vigil, `jq`, DB, 자체 대시보드)로 파이핑할 때 유용합니다. 자체 서비스에 임베드하려면 [라이브러리를 직접 사용](#라이브러리로-사용)하세요.

```bash
# 빌드
cargo build --release

# 신규 블록 스트리밍 + 탐지된 샌드위치를 JSON 라인으로 출력
./target/release/sandwich-detect --rpc $RPC_URL --follow
```

탐지된 샌드위치는 stdout에 JSON 라인으로 찍힙니다:

```jsonc
{
  "slot": 285012345,
  "attacker": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
  "frontrun": { "signature": "4vJ9JU1b...", "dex": "raydium_v4", "direction": "buy",  "amount_in": 5000000000, "amount_out": 128934512 },
  "victim":   { "signature": "3kPnR8xz...", "dex": "raydium_v4", "direction": "buy",  "amount_in": 2000000000, "amount_out":  48201100 },
  "backrun":  { "signature": "5tYm2Wqp...", "dex": "raydium_v4", "direction": "sell", "amount_in":  128934512, "amount_out": 5127300000 },
  "pool": "58oQChx4yWmvKdwLLZzBi4ChoCc2fqCUWBkwMihLYQo2",
  "dex": "raydium_v4",
  "victim_loss_lamports": 8423100,
  "attacker_profit": 6210400,
  "price_impact_bps": 142,
  "severity": "medium",
  "confidence": 0.86,
  "confidence_level": "high"
}
```

`jq`, DB, 알림 시스템, 자체 대시보드 — 어디로든 파이핑 가능.

### 추가 예시

```bash
# 특정 슬롯 분석
sandwich-detect --rpc $RPC_URL --slot 285012345

# 슬롯 범위 스캔
sandwich-detect --rpc $RPC_URL --range 285012000-285012100

# 4-슬롯 슬라이딩 윈도우로 cross-slot 탐지
sandwich-detect --rpc $RPC_URL --range 285012000-285012100 --window 4

# 사람이 읽기 좋게 pretty-print
sandwich-detect --rpc $RPC_URL --follow --format pretty

# 범위 스캔 + 끝에 경제 요약 출력
# (enrichment는 기본 ON; --no-enrich로 끔)
sandwich-detect --rpc $RPC_URL --range 285012000-285012100 --window 4 --summary
```

`RPC_URL`은 `--rpc` 플래그 또는 환경 변수로 전달 가능. Pool-state enrichment도 같은 RPC를 기본 사용; `--pool-state $OTHER_URL` (혹은 `POOL_STATE_RPC`)로 config fetch만 별도 라우팅 가능.

---

## 동작 원리

### Same-block 탐지

```
Block (slot N)
 |
 +-- 트랜잭션 파싱 --> DEX별 swap 이벤트 추출
 |                     (instruction accounts + 토큰 잔액 변화)
 |
 +-- pool 별 그룹화
 |
 +-- 패턴 탐지:
      tx[i]  attacker BUYS   -+
      tx[j]  victim   BUYS    +-- 같은 pool, 같은 방향
      tx[k]  attacker SELLS  -+   반대 방향, tx[i]와 같은 signer
```

### Cross-slot 윈도우 탐지

```
Slot N:    pool P에서 attacker BUYS    (frontrun)
Slot N+1:  pool P에서 victim BUYS      (frontrun과 같은 방향)
Slot N+2:  pool P에서 attacker SELLS   (backrun — 반대 방향)
```

`FilteredWindowDetector`는 pool별 W-슬롯 슬라이딩 윈도우를 유지하며 세 가지 정밀 필터를 적용합니다:

1. **번들 출처** — Jito 번들 동소성 (AtomicBundle > SpanningBundle > TipRace > Organic)
2. **경제적 타당성** — `backrun.amount_out - frontrun.amount_in > 트랜잭션 수수료`
3. **피해자 그럴듯함** — 사이즈 비율 검사 + 알려진 공격자 제외

각 탐지에 가중 합성 **신뢰도 점수**(0.0–1.0)가 매겨집니다.

### 탐지 규칙

| 조건 | 이유 |
|------|------|
| `frontrun.signer == backrun.signer` | 같은 공격자 |
| `frontrun.direction != backrun.direction` | 반대 거래 (사고 → 팔고) |
| `victim.direction == frontrun.direction` | 피해자가 가격을 더 밀어줌 |
| `victim.signer != attacker` | 다른 지갑 |
| 같은 pool | 가격 영향이 그 pool에 국지적 |
| 같은 slot 또는 윈도우 W 내 | 시간적 근접성 |

탐지기는 **하이브리드 파싱**을 사용합니다: instruction discriminator로 DEX 프로그램과 pool 주소를 식별하고, pre/post 토큰 잔액 변화로 swap 방향과 금액을 결정합니다. 순수 instruction 디코딩보다 견고 — instruction 형식이 바뀌어도 동작.

### Victim loss 계측 (AMM 재연)

규칙 기반 탐지는 *"이게 샌드위치였나?"*에 답할 뿐, *"피해자는 얼마를 잃었나?"*는 답하지 못합니다 — 단순 `backrun.amount_out - frontrun.amount_in` 휴리스틱은 multi-token 페어에서 깨지고 가격 영향 동학을 무시합니다. `pool-state` 크레이트는 각 swap을 AMM의 자체 수학으로 재연해서 둘 다 해결합니다:

```
state_0  = frontrun 직전 pool 잔액  (tx 메타에서)
state_1  = frontrun 적용 후 state_0  (재연)
state_2  = victim 적용 후 state_1   (재연, "실제")
state_2c = frontrun 없이 victim     (재연, "반사실")
victim_loss = victim_out(state_2c) - victim_out(state_2)
```

각 단계의 잔액은 트랜잭션 자체의 `pre_token_balances` / `post_token_balances`에서 옴 — constant-product pool은 historical RPC 불필요. Concentrated-liquidity AMM(Whirlpool, DLMM)은 동적 `sqrt_price` / `liquidity` / `active_id` 스냅샷이 필요하며 pool 계정에 `getAccountInfo`로 가져옴; `AccountFetcher` trait를 통해 백필용 archival provider를 끼워 넣을 수 있습니다.

Enrichment 성공 시 각 `SandwichAttack`은 다음을 갖습니다:

- `victim_loss_lamports` — AMM 정확, quote 토큰 최소 단위
- `victim_loss_lamports_lower` / `_upper` — 단계별 parser-vs-model 잔차에서 도출한 신뢰 구간
- `attacker_profit` — 반사실 attacker 총 이익 (rule 기반이 과대 귀속할 때 `estimated_attacker_profit`과 차이 발생)
- `price_impact_bps` — frontrun이 유발한 가격 변화 (bp)
- `severity` — loss 대비 pool TVL 비율의 버킷
- DEX별 trace: `amm_replay`(constant product), `whirlpool_replay`, `dlmm_replay` — 다운스트림 소비자가 raw 산술로 loss를 재계산 가능

미지원 DEX의 공격은 이 필드들이 `None`인 채로 통과됩니다.

---

## Vigil 통합

이 저장소는 [Vigil](https://github.com/EarthIsMine/Vigil-RPC)의 상위(upstream) 탐지 primitive입니다. contract surface는 Vigil의 BE/FE가 *지금 출시 가능*할 만큼 안정적이며, 다운스트림 소비자가 결합해야 할 네 조각은 다음과 같습니다.

### 1. JSONL 스트림 contract

`sandwich-detect`은 stdout으로 세 가지 라인 형태를 newline-delimited JSON으로 emit합니다. 소비자는 discriminator로 분기:

```jsonc
// Header — 시작 시 한 번 emit.
{ "_header": true, "schema_version": "vigil-v1", "tool_version": "0.x.y", "started_at_ms": 1730000000000 }

// Heartbeat — 실행 중 30초마다. enrichment 메트릭 스냅샷 포함.
{ "_heartbeat": true, "ts_ms": 1730000030000, "metrics": {
    "enriched": 142, "unsupported_dex": 18, "config_unavailable": 3,
    "reserves_missing": 1, "replay_failed": 0, "cross_boundary_unsupported": 4 } }

// SandwichAttack — 탐지당 1개. 전체 스키마는 vigil-v1.json.
{ "slot": 285012345, "attacker": "...", "frontrun": {...}, "victim": {...}, ... }
```

### 2. Schema + TypeScript 타입

| 파일 | 용도 |
|------|------|
| `crates/swap-events/schema/vigil-v1.json` | `SandwichAttack`의 정규 JSON Schema. `cargo run -p swap-events --bin gen-schema`로 재생성. |
| `contrib/vigil-types.ts` | 스키마와 매칭되는 손튜닝된 TS 인터페이스. `parseDetectorLine()` discriminator + u128 필드(sqrt_price, liquidity, bin_price)에 대한 BigInt 가이드. |
| `swap_events::SCHEMA_VERSION` | Rust 상수 `"vigil-v1"`. 호환성 깨짐(breaking) 시 bump. |

### 3. BE 친화적 Rust 헬퍼

```rust
// 일회성 변환: SandwichAttack → MevReceipt (Vigil의 `mev_receipt` 테이블용 피해자별 행).
let receipt = MevReceipt::from_attack(&attack);

// 멱등(idempotent): 원시 detector 출력으로부터 Vigil 모양의 필드(attack_signature,
// attack_type, confidence_level, victim_signer/amount_*, receipts vec)를 도출.
// 호출자가 어떤 필드든 미리 설정해서 오버라이드 가능; finalize()는 이미 None이 아닌 값을 보존.
attack.finalize_for_vigil();
```

`finalize_for_vigil()`은 의도적으로 **`severity`를 설정하지 않습니다** — pool-TVL 컨텍스트가 필요하고 그건 BE가 보유. 영수증의 USD 가격도 동일. 다른 Vigil 컬럼(slot leader, validator identity)은 Tier 2 enrichment가 구성되어 있을 때 채워집니다.

### 4. NestJS 소비자 예시

`contrib/vigil-service.example.ts`는 완성된 NestJS 서비스를 제공합니다: `sandwich-detect --follow` 스폰, readline으로 stdout 읽기, header/heartbeat/attack 라인 분기, graceful 재시작 처리, DB write/WebSocket broadcast 자리표시자 포함. 즉시 사용 가능한 시작점.

---

## 라이브러리로 사용

`Cargo.toml`에 추가:

```toml
[dependencies]
sandwich-detector = { git = "https://github.com/SangHyeonKwon/solana-sandwich-detector" }
```

### Same-block 탐지

```rust
use sandwich_detector::{detector, dex, source::{BlockSource, rpc::RpcBlockSource}};

let source = RpcBlockSource::new("https://api.mainnet-beta.solana.com");
let parsers = dex::all_parsers();

let block = source.get_block(slot).await?;
let swaps: Vec<_> = block.transactions.iter()
    .flat_map(|tx| dex::extract_swaps(tx, &parsers))
    .collect();

let sandwiches = detector::detect_sandwiches(slot, &swaps);
```

### Cross-slot 윈도우 탐지

```rust
use sandwich_detector::window::{FilteredWindowDetector, WindowDetector};

let mut detector = FilteredWindowDetector::new(4); // 4-슬롯 윈도우

// 슬롯을 순서대로 공급
for (slot, swaps) in blocks_stream {
    let attacks = detector.ingest_slot(slot, swaps);
    for attack in &attacks {
        println!("Sandwich: confidence={:.2}", attack.confidence.unwrap_or(0.0));
    }
}

// 버퍼에 남은 탐지 flush
let remaining = detector.flush();
```

### 핵심 타입

| 타입 | 설명 |
|------|------|
| `SwapEvent` | 단일 파싱된 swap (signer, pool, direction, amounts) |
| `SandwichAttack` | 탐지된 샌드위치 (frontrun + victim + backrun + confidence + replay) |
| `BlockSource` | Trait — 자체 block fetcher 끼우기 (RPC, gRPC, WebSocket) |
| `DexParser` | Trait — 임의의 DEX 지원을 ~50줄에 추가 |
| `WindowDetector` | Trait — 슬라이딩 윈도우 cross-slot 탐지 |
| `FilteredWindowDetector` | 3개 정밀 필터 + 신뢰도 채점이 있는 프로덕션 탐지기 |
| `FilterConfig` | 설정 가능한 임계치 (min profit, victim ratio, confidence) |
| `BundleLookup` | Trait — 출처 분류용 Jito 번들 데이터 주입 |
| `PoolStateLookup` | Trait — AMM 재연용 config + 동적 상태 + tick/bin array fetch |
| `AccountFetcher` | Trait — archival provider용 슬롯 인지 account fetch surface |
| `MevReceipt` | 다운스트림 영속화용 피해자별 행 모양 |

---

## 프로젝트 구조

```
crates/
  swap-events/           Swap 이벤트 타입, DEX 파서, 블록 소스
                         + JSON 스키마(vigil-v1.json) + gen-schema bin
  detector-sameblock/    Same-block 샌드위치 탐지
  detector-window/       Cross-slot 윈도우 탐지기 + 정밀 필터
  pool-state/            AMM 수학 + pool-state enrichment + archival diff
                         (constant product / Whirlpool / DLMM)
  detector/              파사드 크레이트 (하위 호환성용 re-export)
  cli/                   CLI 바이너리 (sandwich-detect, balance-diff, archival-diff)
  eval/                  평가 프레임워크 + 경제 집계

contrib/
  vigil-types.ts         vigil-v1.json과 일치하는 TS 인터페이스
  vigil-service.example.ts  NestJS 소비자 드라이버
```

---

## 범위

이 라이브러리는 **블록 스트림에 대한 탐지** — same-block과 cross-slot 패턴, 그리고 AMM 정확 victim-loss 재연 — 을 다룹니다. 상태(stateful)·견해(opinionated)·제품 형태인 것은 범위 밖이며 다운스트림 소비자인 [Vigil](https://github.com/EarthIsMine/Vigil-RPC)에 살게 됩니다.

**범위 안** (PR 환영):

- 새 DEX 파서 (Lifinity, Marinade, Sanctum, ...)
- 새 `BlockSource` 구현 (Yellowstone gRPC, Geyser, fixture file, WebSocket)
- Same-block / cross-slot 탐지 정확도 개선
- 신뢰도 채점과 필터 튜닝
- Jito 번들 통합 개선
- 평가 프레임워크 개선 (메트릭, 라벨링 도구)
- 더 많은 AMM의 pool-state 커버리지 (Raydium CLMM, Lifinity, ...)
- 메인넷 테스트 fixture
- 성능: 할당 감소, 병렬화, 배치
- API 인체공학·문서·예시
- "stream in → stream out" 안에 머무는 CLI 플래그

**범위 밖** (Vigil 같은 다운스트림 소비자에 속함):

- 검증인 인지 / 리더 인지 분석
- 멀티홉 Jupiter 라우트 해석
- Wash-trading 거짓양성 필터
- ML 기반 신뢰도 채점
- 영속성 (DB, 파일 스토어, 인덱서)
- 알림 (webhook, Slack, Discord, 이메일, ...)
- 메트릭 엔드포인트 (Prometheus, OpenTelemetry, ...)
- 웹 UI, 대시보드, 시각화
- CLI에 박힌 어떤 stateful 서비스든

원칙: **"스트림 위 계산"**은 여기에, **"상태·출력·표현"**은 다운스트림에.

---

## 기여

PR 환영. 도움이 가장 가치 있는 곳:

- **DEX 파서 추가** — 새 프로토콜에 `DexParser` 구현 (Lifinity, Marinade, Sanctum, ...)
- **테스트 fixture 추가** — 확인된 샌드위치가 있는 메인넷 블록을 `fixtures/`에 캡처
- **탐지 개선** — 엣지 케이스, cross-slot 정확도, 신뢰도 튜닝
- **평가 프레임워크** — 라벨링 데이터셋 추가, 메트릭 개선, 새 평가 모드
- **블록 소스 추가** — gRPC (Yellowstone), WebSocket 구독
- **Pool-state 커버리지** — 새 AMM의 replay 추가 (다음 후보: Raydium CLMM)

```bash
# 테스트 실행
cargo test --workspace

# 전체 컴파일 확인
cargo check --workspace

# Vigil 스키마 재생성 (스키마 변경 commit 전에 실행)
cargo run -p swap-events --bin gen-schema > crates/swap-events/schema/vigil-v1.json
```

---

## 수치 재현

측정 흐름은 결정론적입니다 — 슬롯 범위와 RPC 엔드포인트가 같으면 누가 돌려도 같은 출력. 실행 재현법:

```bash
# 원시 탐지를 JSONL로 (한 줄당 하나). 다일(多日) 실행은 이걸 사용 —
# 스캐너는 버퍼링 안 하고 그대로 디스크에 스트리밍.
sandwich-detect \
    --rpc $RPC_URL \
    --range <START>-<END> \
    --window 4 \
    --pool-state $RPC_URL \
  > detections.jsonl

# JSONL을 메인 리포트(사람용 또는 JSON)로 집계.
sandwich-eval summarize --input detections.jsonl > report.txt
sandwich-eval summarize --input detections.jsonl --json > report.json
```

짧은 실행은 스캐너 자체에 `--summary`를 붙여 리포트를 emit할 수도 있습니다; 인메모리 집계라 수백 MB까지는 OK이지만 다일 스캔에는 부적합.

요약은 총 victim loss(quote 토큰 최소 단위), 고유 attacker/victim/pool 수, DEX별 분해, 추출 가치 기준 상위 attacker, 그리고 *재분류율* — 단순 규칙 기반 이익 휴리스틱이 흑자라고 표시하지만 AMM 재연 결과 적자인 샌드위치의 비율 — 을 포함합니다. 이 재분류율이 pool-state enrichment를 돌릴 가치를 만드는 신호입니다.

특정 슬롯 범위에 대한 결과(와 그 raw JSONL)는 글과 함께 게시됩니다; 진행 중인 실행은 [Vigil](https://github.com/EarthIsMine/Vigil-RPC) 참조.

---

## 라이선스

MIT
