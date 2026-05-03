<p align="center">
  <h1 align="center">solana-sandwich-detector</h1>
  <p align="center">
    Una librería en Rust para detectar ataques sandwich same-block y cross-slot en Solana.<br/>
    Parsea eventos de swap de 8 DEX e identifica patrones frontrun/víctima/backrun mediante correlación por ventana deslizante, filtros de precisión y replay AMM-correcto del victim loss.
  </p>
</p>

<p align="center">
  <a href="README.md">English</a> &middot;
  <a href="README.ko.md">한국어</a> &middot;
  <strong>Español</strong>
</p>

<p align="center">
  <a href="https://github.com/SangHyeonKwon/solana-sandwich-detector/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/SangHyeonKwon/solana-sandwich-detector/ci.yml?style=for-the-badge&label=CI" alt="CI" /></a>
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/Solana-9945FF?style=for-the-badge&logo=solana&logoColor=white" alt="Solana" />
  <img src="https://img.shields.io/badge/Tokio-232323?style=for-the-badge&logo=rust&logoColor=white" alt="Tokio" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License" />
</p>

<p align="center">
  <a href="#inicio-rápido">Inicio rápido</a> &middot;
  <a href="#cómo-funciona">Cómo funciona</a> &middot;
  <a href="#integración-con-vigil">Integración con Vigil</a> &middot;
  <a href="#uso-como-librería">Librería</a> &middot;
  <a href="#alcance">Alcance</a> &middot;
  <a href="#contribuir">Contribuir</a>
</p>

---

Los ataques sandwich son la forma más común de extracción de MEV en Solana. Un atacante adelanta el swap de la víctima, empuja el precio y luego ejecuta un backrun para obtener ganancias — dentro del mismo bloque o a través de slots cercanos.

**solana-sandwich-detector** es una librería en Rust que convierte un stream de bloques de Solana en un stream de ataques detectados. Soporta **detección same-block** (patrón clásico de un solo slot) y **detección cross-slot** (ataques que abarcan múltiples slots, con filtros de procedencia de bundles Jito, factibilidad económica y plausibilidad de la víctima). El enriquecimiento por replay AMM calcula la *pérdida real de la víctima* — no la heurística ingenua `amount_out - amount_in`. Se incluyen un CLI streaming (`sandwich-detect`), un framework de evaluación (`sandwich-eval`) y dos herramientas de diff (`balance-diff` para verificación cruzada parser-vs-RPC de la víctima; `archival-diff` para comparación replay-vs-chain del estado del pool — actualmente un placeholder, a la espera de un fetcher de cuentas archival que ningún RPC mayor de Solana expone hoy).

> Es la primitiva de detección que alimenta a [Vigil](https://github.com/EarthIsMine/Vigil-RPC) — una plataforma de transparencia MEV en Solana. La puntuación de validadores, la persistencia, las alertas y los dashboards viven en Vigil; este repositorio se centra en **stream-in → stream-out**. Ver [Alcance](#alcance) e [Integración con Vigil](#integración-con-vigil).

### DEX soportados

| DEX | Parsing de swap | Replay AMM (victim loss) |
|-----|-----------------|--------------------------|
| Raydium V4 | Directo + CPI | ✅ Producto constante |
| Raydium CPMM | Directo + CPI | ✅ Producto constante |
| Raydium CLMM | Directo + CPI | — |
| Orca Whirlpool | Directo + CPI | ✅ Concentrada, dentro-tick + cross-tick |
| Meteora DLMM | Directo + CPI | ✅ Suma constante, dentro-bin + cross-bin |
| Jupiter V6 | Route-through (resuelve pool subyacente) | (vía pool subyacente) |
| Pump.fun | Directo + CPI | — |
| Phoenix | Directo + CPI | — |

> Añadir un nuevo DEX toma ~50 líneas para parsear swaps; el replay añade un módulo aparte. Ver [Contribuir](#contribuir).

---

## Inicio rápido

El repositorio incluye `sandwich-detect`, un CLI streaming que envuelve la librería — útil para pruebas rápidas, análisis ad-hoc y para canalizar detecciones a otras herramientas (Vigil, `jq`, una base de datos, tu propio dashboard). Para integrar en tu propio servicio, [usa la librería directamente](#uso-como-librería).

```bash
# Compilar
cargo build --release

# Stream de bloques nuevos imprimiendo cada sandwich detectado como línea JSON
./target/release/sandwich-detect --rpc $RPC_URL --follow
```

Cada sandwich detectado se imprime como una línea JSON en stdout:

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

Canaliza a donde sea — `jq`, una BD, un sistema de alertas, tu propio dashboard.

### Más ejemplos

```bash
# Analizar un slot específico
sandwich-detect --rpc $RPC_URL --slot 285012345

# Escanear un rango de slots
sandwich-detect --rpc $RPC_URL --range 285012000-285012100

# Detección cross-slot con ventana deslizante de 4 slots
sandwich-detect --rpc $RPC_URL --range 285012000-285012100 --window 4

# Pretty-print legible
sandwich-detect --rpc $RPC_URL --follow --format pretty

# Escanear un rango y emitir un resumen económico al final
# (el enriquecimiento está activo por defecto; usa --no-enrich para desactivarlo)
sandwich-detect --rpc $RPC_URL --range 285012000-285012100 --window 4 --summary
```

`RPC_URL` se puede pasar vía flag `--rpc` o como variable de entorno. El enriquecimiento de pool-state también usa ese RPC por defecto; configura `--pool-state $OTHER_URL` (o `POOL_STATE_RPC`) para enrutar las búsquedas de config a otro endpoint.

---

## Cómo funciona

### Detección same-block

```
Bloque (slot N)
 |
 +-- Parsear transacciones --> Extraer eventos de swap por DEX
 |                              (instruction accounts + deltas de balance de tokens)
 |
 +-- Agrupar por pool
 |
 +-- Detectar patrón:
      tx[i]  attacker BUYS   -+
      tx[j]  victim   BUYS    +-- mismo pool, misma dirección
      tx[k]  attacker SELLS  -+   dirección opuesta, mismo signer que tx[i]
```

### Detección cross-slot por ventana

```
Slot N:    attacker BUYS en pool P    (frontrun)
Slot N+1:  victim BUYS en pool P      (misma dirección que frontrun)
Slot N+2:  attacker SELLS en pool P   (backrun — dirección opuesta)
```

El detector cross-slot (`FilteredWindowDetector`) mantiene una ventana deslizante de W slots por pool y aplica tres filtros de precisión:

1. **Procedencia de bundles** — co-localización de bundles Jito (AtomicBundle > SpanningBundle > TipRace > Organic)
2. **Factibilidad económica** — `backrun.amount_out - frontrun.amount_in > comisiones de tx`
3. **Plausibilidad de víctima** — chequeo de razón de tamaño + exclusión de atacantes conocidos

A cada detección se le asigna una **puntuación de confianza** compuesta (0.0–1.0) ponderada por estos filtros.

### Reglas de detección

| Condición | Por qué |
|-----------|---------|
| `frontrun.signer == backrun.signer` | Mismo atacante |
| `frontrun.direction != backrun.direction` | Trades opuestos (compra y luego venta) |
| `victim.direction == frontrun.direction` | La víctima empuja el precio aún más |
| `victim.signer != attacker` | Wallet diferente |
| Mismo pool | El impacto en el precio es local al pool |
| Mismo slot (same-block) o dentro de W slots (window) | Proximidad temporal |

El detector usa un **enfoque de parsing híbrido**: los discriminators de instrucciones identifican el programa DEX y el pool, mientras que los cambios de balance pre/post de tokens determinan dirección y montos del swap. Más robusto que decodificar puramente la instrucción, ya que sigue funcionando aunque el formato cambie.

### Medición del victim loss (replay AMM)

La detección por reglas responde *"¿esto fue un sandwich?"* pero no *"¿cuánto perdió la víctima?"* — la heurística ingenua `backrun.amount_out - frontrun.amount_in` se rompe en pares multi-token e ignora la dinámica del impacto en el precio. La crate `pool-state` resuelve ambas cosas reproduciendo cada swap con la matemática propia del AMM:

```
state_0  = reservas del pool justo antes del frontrun  (de tx meta)
state_1  = state_0 después del frontrun                 (replay)
state_2  = state_1 después de la víctima                (replay, "actual")
state_2c = state_0 después de la víctima, sin frontrun  (replay, "contrafactual")
victim_loss = victim_out(state_2c) - victim_out(state_2)
```

Las reservas de cada paso vienen de los `pre_token_balances` / `post_token_balances` de la propia transacción — no se requiere RPC histórico para pools de producto constante. Los AMMs de liquidez concentrada (Whirlpool, DLMM) requieren el snapshot dinámico (`sqrt_price` / `liquidity` / `active_id`), obtenido vía `getAccountInfo` sobre la cuenta del pool; el trait `AccountFetcher` permite enchufar proveedores archival para backfill.

Cuando el enriquecimiento tiene éxito, cada `SandwichAttack` recibe:

- `victim_loss_lamports` — AMM-correcto, en la unidad mínima del token quote
- `victim_loss_lamports_lower` / `_upper` — intervalo de confianza derivado de los residuales parser-vs-modelo por paso
- `attacker_profit` — ganancia bruta contrafactual del atacante (difiere de `estimated_attacker_profit` cuando la lógica por reglas sobre-atribuye)
- `price_impact_bps` — desplazamiento de precio inducido por el frontrun (en bps)
- `severity` — categoría según la razón loss/TVL del pool
- Trace por DEX: `amm_replay` (producto constante), `clmm_replay` (V3-style: Whirlpool + Raydium CLMM), `dlmm_replay` — permite a un consumidor downstream recalcular la pérdida desde la aritmética cruda

Los ataques en DEXes no soportados pasan con estos campos en `None`.

---

## Integración con Vigil

Este repositorio es la primitiva de detección upstream de [Vigil](https://github.com/EarthIsMine/Vigil-RPC). La superficie de contrato es lo bastante estable para que el BE/FE de Vigil pueda salir hoy mismo; los cuatro elementos a continuación son contra los que se conecta un consumidor downstream.

### 1. Contrato de stream JSONL

`sandwich-detect` emite tres formas de línea por stdout, todas JSON delimitado por nueva línea. Un consumidor despacha por discriminador:

```jsonc
// Header — emitido una vez al iniciar.
{ "_header": true, "schema_version": "vigil-v1", "tool_version": "0.x.y", "started_at_ms": 1730000000000 }

// Heartbeat — cada 30s mientras corre. Snapshot de métricas de enriquecimiento,
// bucketed por `DexType` para que ops vean qué DEX está sub-buscando su ventana
// de 5-array. Las 8 claves DexType siempre están presentes (rellenadas con cero).
// `_heartbeat` es el timestamp unix-ms (no un booleano).
{ "_heartbeat": 1730000030000, "metrics": {
    "raydium_v4":     { "enriched": 90, "unsupported_dex": 0, "config_unavailable": 1,
                        "reserves_missing": 0, "replay_failed": 0, "cross_boundary_unsupported": 0 },
    "orca_whirlpool": { "enriched": 32, "unsupported_dex": 0, "config_unavailable": 1,
                        "reserves_missing": 1, "replay_failed": 0, "cross_boundary_unsupported": 3 },
    "meteora_dlmm":   { "enriched": 20, "unsupported_dex": 0, "config_unavailable": 1,
                        "reserves_missing": 0, "replay_failed": 0, "cross_boundary_unsupported": 1 },
    /* raydium_clmm, raydium_cpmm, jupiter_v6, pump_fun, phoenix omitidos */ } }

// SandwichAttack — uno por detección. Esquema completo en vigil-v1.json.
{ "slot": 285012345, "attacker": "...", "frontrun": {...}, "victim": {...}, ... }
```

### 2. Esquema + tipos TypeScript

| Archivo | Propósito |
|---------|-----------|
| `crates/swap-events/schema/vigil-v1.json` | JSON Schema canónico para `SandwichAttack`. Generado por `cargo run -p swap-events --bin gen-schema`. |
| `contrib/vigil-types.ts` | Interfaces TS afinadas a mano que coinciden con el esquema. Incluye `parseDetectorLine()` (discriminador) + guía de BigInt para campos u128 (sqrt_price, liquidity, bin_price). |
| `swap_events::SCHEMA_VERSION` | Constante Rust `"vigil-v1"`. Se incrementa con cambios incompatibles. |

### 3. Helpers Rust amigables al BE

```rust
// Conversión de un solo paso: SandwichAttack → MevReceipt (fila por víctima para la tabla
// `mev_receipt` de Vigil).
let receipt = MevReceipt::from_attack(&attack);

// Idempotente: deriva campos en formato Vigil (attack_signature, attack_type,
// confidence_level, victim_signer/amount_*, vec de receipts) desde la salida cruda del
// detector. El llamador puede pre-establecer cualquier campo para sobreescribir;
// finalize() preserva lo que ya no es None.
attack.finalize_for_vigil();
```

`finalize_for_vigil()` deliberadamente **no establece `severity`** — eso requiere contexto de TVL del pool que tiene el BE. Lo mismo para precios USD en los receipts. Otras columnas de Vigil (slot leader, identidad del validador) las completa el enriquecimiento Tier 2 cuando está configurado.

### 4. Ejemplo de consumidor NestJS

`contrib/vigil-service.example.ts` provee un servicio NestJS completo: arranca `sandwich-detect --follow`, lee stdout vía readline, despacha líneas header/heartbeat/attack, maneja reinicio elegante y deja stubs para escrituras a BD / broadcasts WebSocket. Punto de partida listo para enchufar.

---

## Uso como librería

Añade a tu `Cargo.toml`:

```toml
[dependencies]
sandwich-detector = { git = "https://github.com/SangHyeonKwon/solana-sandwich-detector" }
```

### Detección same-block

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

### Detección cross-slot por ventana

```rust
use sandwich_detector::window::{FilteredWindowDetector, WindowDetector};

let mut detector = FilteredWindowDetector::new(4); // ventana de 4 slots

// Alimenta los slots en orden
for (slot, swaps) in blocks_stream {
    let attacks = detector.ingest_slot(slot, swaps);
    for attack in &attacks {
        println!("Sandwich: confidence={:.2}", attack.confidence.unwrap_or(0.0));
    }
}

// Vacía las detecciones pendientes en buffer
let remaining = detector.flush();
```

### Tipos clave

| Tipo | Descripción |
|------|-------------|
| `SwapEvent` | Un swap parseado (signer, pool, dirección, montos) |
| `SandwichAttack` | Un sandwich detectado (frontrun + víctima + backrun + confianza + replay) |
| `BlockSource` | Trait — enchufa tu propio fetcher de bloques (RPC, gRPC, WebSocket) |
| `DexParser` | Trait — soporte para cualquier DEX en ~50 líneas |
| `WindowDetector` | Trait — detección cross-slot con ventana deslizante |
| `FilteredWindowDetector` | Detector de producción con 3 filtros de precisión + scoring de confianza |
| `FilterConfig` | Umbrales configurables (profit mínimo, ratio víctima, confianza) |
| `BundleLookup` | Trait — inyecta datos de bundles Jito para clasificar procedencia |
| `PoolStateLookup` | Trait — config + estado dinámico + fetch de tick/bin arrays para replay AMM |
| `AccountFetcher` | Trait — superficie de fetch de cuentas slot-aware para proveedores archival |
| `MevReceipt` | Forma de fila por víctima para persistencia downstream |

---

## Estructura del proyecto

```
crates/
  swap-events/           Tipos de eventos de swap, parsers DEX, fuentes de bloques
                         + JSON schema (vigil-v1.json) + bin gen-schema
  detector-sameblock/    Detección same-block
  detector-window/       Detector cross-slot por ventana + filtros de precisión
  pool-state/            Matemática AMM + enriquecimiento + diff archival
                         (producto constante / Whirlpool / DLMM)
  detector/              Crate fachada (re-exports para retrocompatibilidad)
  cli/                   Binarios CLI (sandwich-detect, balance-diff, archival-diff)
  eval/                  Framework de evaluación + agregados económicos

contrib/
  vigil-types.ts         Interfaces TS que coinciden con vigil-v1.json
  vigil-service.example.ts  Driver consumidor NestJS
```

---

## Alcance

Esta librería cubre **detección sobre un stream de bloques** — tanto patrones same-block como cross-slot, más replay AMM-correcto del victim loss. Cualquier cosa con estado, opinada o con forma de producto está fuera de alcance y vive en el consumidor downstream [Vigil](https://github.com/EarthIsMine/Vigil-RPC).

**En alcance** (PRs bienvenidas):

- Nuevos parsers DEX (Lifinity, Marinade, Sanctum, ...)
- Nuevas implementaciones de `BlockSource` (Yellowstone gRPC, Geyser, archivo de fixtures, WebSocket)
- Mejoras de exactitud en detección same-block y cross-slot
- Tuning de scoring de confianza y filtros
- Mejoras a la integración de bundles Jito
- Mejoras al framework de evaluación (métricas, herramientas de etiquetado)
- Cobertura de pool-state para más AMMs (Raydium CLMM, Lifinity, ...)
- Fixtures de mainnet
- Rendimiento: reducción de allocations, paralelismo, batching
- Ergonomía de la API, documentación, ejemplos
- Flags de CLI que se mantengan en "stream in → stream out"

**Fuera de alcance** (pertenecen a un consumidor downstream como Vigil):

- Análisis con conciencia de validador o leader
- Resolución multi-hop de rutas Jupiter
- Filtros de falsos positivos por wash-trading
- Scoring de confianza basado en ML
- Persistencia (BDs, file stores, indexers)
- Alertas (webhooks, Slack, Discord, email, ...)
- Endpoints de métricas (Prometheus, OpenTelemetry, ...)
- UIs web, dashboards, visualizaciones
- Servicios con estado de cualquier tipo dentro del CLI

Regla práctica: **"cómputo sobre un stream"** se queda aquí, **"estado, salida, presentación"** se va downstream.

---

## Contribuir

PRs bienvenidas. Aquí es donde la ayuda es más valiosa:

- **Añadir un parser DEX** — implementa `DexParser` para un nuevo protocolo (Lifinity, Marinade, Sanctum, ...)
- **Añadir test fixtures** — captura bloques de mainnet con sandwiches confirmados bajo `fixtures/`
- **Mejorar la detección** — casos borde, exactitud cross-slot, tuning de confianza
- **Framework de evaluación** — añadir datasets etiquetados, mejorar métricas, nuevos modos
- **Añadir block sources** — gRPC (Yellowstone), suscripciones WebSocket
- **Cobertura de pool-state** — añadir el replay de un AMM nuevo (próximo en la lista: Raydium CLMM)

```bash
# Ejecutar tests
cargo test --workspace

# Verificar que todo compila
cargo check --workspace

# Regenerar el esquema Vigil (ejecuta antes de commitear cambios al esquema)
cargo run -p swap-events --bin gen-schema > crates/swap-events/schema/vigil-v1.json
```

---

## Reproducir los números

El flujo de medición es determinista — dado un rango de slots y un endpoint RPC, cualquiera obtiene la misma salida. Para reproducir una corrida:

```bash
# Detecciones crudas en JSONL (una por línea). Úsalo para corridas multi-día —
# el escáner no buferiza, simplemente escribe en streaming a disco.
sandwich-detect \
    --rpc $RPC_URL \
    --range <START>-<END> \
    --window 4 \
    --pool-state $RPC_URL \
  > detections.jsonl

# Agrega el JSONL en el reporte principal (legible o JSON).
sandwich-eval summarize --input detections.jsonl > report.txt
sandwich-eval summarize --input detections.jsonl --json > report.json
```

Para corridas cortas el escáner también puede emitir el reporte directamente con `--summary`; la agregación corre en memoria, OK hasta unos cientos de MB de detecciones pero no para escaneos multi-día.

El resumen incluye victim loss total (unidad mínima del token quote), atacantes/víctimas/pools únicos, desglose por DEX, top atacantes por valor extraído y una *tasa de reclasificación* — la fracción de sandwiches que la heurística por reglas marca como rentables pero el replay AMM revela como pérdida. Esa reclasificación es la señal que hace que valga la pena correr el enriquecimiento de pool-state.

Resultados para rangos de slots específicos (y el JSONL crudo usado para producirlos) se publicarán junto con write-ups; ver [Vigil](https://github.com/EarthIsMine/Vigil-RPC) para corridas en curso.

---

## Licencia

MIT
