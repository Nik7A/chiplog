# Benchmarks

What the hot path costs, and what changed in v0.2.

**Read the machine column before quoting any number.** This file reports two machines, and they are not interchangeable:

- **Hetzner CCX13** — the v0.1 reference, measured 2026-06-23. Server-class Linux, cheap `fsync()`. Historical: these are v0.1 numbers and no v0.2 number was measured there.
- **Apple M2 Max** — the v0.2 measurement machine, measured 2026-07-16. A dev box with `F_FULLFSYNC` (true platter sync), which is several times more expensive than Linux `fsync()`.

The v0.1→v0.2 delta below is **M2 Max vs M2 Max**. Comparing v0.2-on-Mac against v0.1-on-Hetzner would be measuring the machine, not the release, so that comparison is not drawn anywhere in this file. There is no v0.2 Hetzner column because that run was not performed; when it is, it goes here.

## Machines

| | CPU | Cores | RAM | Storage | OS | Python |
| --- | --- | --- | --- | --- | --- | --- |
| **Hetzner CCX13** (v0.1 ref) | AMD EPYC Milan | 2 dedicated vCPU | 8 GB | local NVMe, ext4, `fsync()` | Ubuntu 24.04 (kernel 6.8) | 3.14.6 |
| **Apple M2 Max** (v0.2 ref) | Apple M2 Max | 12 | 32 GB | internal SSD, APFS, `F_FULLFSYNC` | macOS 26.5.2 | 3.14.3 |

Method: `bench/`, `pytest-benchmark`, 3 full suite runs per version. Each run reports a median over its rounds; the tables below give the **median of the 3 run-medians**, with the **min..max of those run-medians** in brackets as the spread. A single run is not a measurement. Both versions were run back-to-back on an otherwise idle machine, alternating, to spread OS background noise across both.

Reproduce: `uv run pytest bench/`. Full instructions in [`bench/README.md`](bench/README.md).

---

## v0.1 → v0.2, same machine (Apple M2 Max)

### Crypto ceiling — `InMemorySink`, no disk

Sign + chain + canonicalise, no I/O. **This is where v0.2's added work is visible**, because nothing masks it.

| Payload | v0.1 | v0.2 | Delta |
| --- | --- | --- | --- |
| 256 B | 3 672 rec/sec &nbsp;[3 667..3 776] &nbsp;(272 µs) | 2 910 rec/sec &nbsp;[2 908..2 997] &nbsp;(344 µs) | **−21 %** |
| 2 KB | 2 755 rec/sec &nbsp;[2 716..2 767] &nbsp;(363 µs) | 1 873 rec/sec &nbsp;[1 858..1 889] &nbsp;(534 µs) | **−32 %** |
| 8 KB | 1 502 rec/sec &nbsp;[1 491..1 511] &nbsp;(666 µs) | 831 rec/sec &nbsp;[819..844] &nbsp;(1 203 µs) | **−45 %** |

**This is a real regression and it is not noise** — the spreads do not overlap, and it scales with payload size (−21 % at 256 B, −45 % at 8 KB). v0.2 walks the whole payload where v0.1 walked part of it:

- `normalize_for_canonical` inspects every user field to replace un-representable scalars with announced markers, rather than letting them vanish or be laundered;
- redaction now inspects **every scalar and every dict key** in its signed string form (v0.1: strings only) — that is what closed the type-bypass class;
- a per-record CSPRNG anti-forgery token is minted.

Payload-proportional work, payload-proportional cost. An 8 KB record pays ~540 µs more than under v0.1.

### Durable path — `LocalFileSink`, per-record `F_FULLFSYNC`

Everything above, plus JSONL append, manifest rewrite, and per-record platter sync.

| Payload | v0.1 | v0.2 | Delta |
| --- | --- | --- | --- |
| 256 B | 276 rec/sec &nbsp;[259..280] &nbsp;(3.62 ms) | 268 rec/sec &nbsp;[224..271] &nbsp;(3.73 ms) | −3 % *(within spread)* |
| 2 KB | 266 rec/sec &nbsp;[221..271] &nbsp;(3.76 ms) | 247 rec/sec &nbsp;[217..259] &nbsp;(4.05 ms) | −7 % *(within spread)* |
| 8 KB | 235 rec/sec &nbsp;[233..235] &nbsp;(4.26 ms) | 198 rec/sec &nbsp;[189..217] &nbsp;(5.05 ms) | **−16 %** |

Sustained throughput, 1 000-record bursts:

| Payload | v0.1 | v0.2 | Delta |
| --- | --- | --- | --- |
| 256 B | 262 rec/sec &nbsp;[259..279] | 253 rec/sec &nbsp;[221..270] | −4 % *(within spread)* |
| 2 KB | 268 rec/sec &nbsp;[259..277] | 236 rec/sec &nbsp;[209..248] | −12 % *(spreads touch)* |
| 8 KB | 215 rec/sec &nbsp;[209..240] | 208 rec/sec &nbsp;[190..210] | −4 % *(within spread)* |

**`fsync` hides most of the regression.** A platter sync costs ~3.5–4 ms; v0.2's extra 70–540 µs of crypto is a rounding error against that. Only the 8 KB durable row (−16 %) clearly clears the run-to-run spread. Honest reading: **on an fsync-bound sink the v0.2 cost is mostly invisible; on any sink that is not fsync-bound it is 21–45 %.** That matters for the planned `S3Sink`, which exists specifically to take `fsync` off the hot path — it will not have `fsync` to hide behind.

### Concurrency — 8 callers, one recorder

The v0.1 suite had no concurrency bench, so v0.2's `_ChainLock` shipped with nothing measuring the case it changes. It does now. 1 000 records per round, same total as the serial bench, so these read directly against the rows above.

**8 threads** (`record_sync` — the LangGraph `ToolNode` shape):

| Payload | v0.1 | v0.2 |
| --- | --- | --- |
| 256 B | **fails — see below** | 266 rec/sec &nbsp;[225..277] |
| 2 KB | **fails — see below** | 230 rec/sec &nbsp;[217..246] |
| 8 KB | **fails — see below** | 200 rec/sec &nbsp;[184..207] |

**8 coroutines** (`asyncio.gather` — the async `ToolNode` shape):

| Payload | v0.1 | v0.2 | Delta |
| --- | --- | --- | --- |
| 256 B | 271 rec/sec &nbsp;[230..282] | 264 rec/sec &nbsp;[227..273] | −3 % *(within spread)* |
| 2 KB | 259 rec/sec &nbsp;[251..266] | 240 rec/sec &nbsp;[209..248] | −8 % *(within spread)* |
| 8 KB | 243 rec/sec &nbsp;[240..249] | 196 rec/sec &nbsp;[188..206] | **−19 %** |

Two things to read here, and the second is the point.

**1. v0.2 gains nothing from concurrency.** 8 concurrent callers deliver 266 rec/sec at 256 B; one caller delivers 268. That is `_ChainLock` doing exactly what it says: the commit section is serialised, so **one recorder is one writer, and its concurrent ceiling is its serial ceiling**. Callers queue. Fanning out tool calls does not raise the audit write rate — to scale writes, use more recorders (one per chain) and parallelise by `chain_id`. This is a real limit and it is stated here rather than left for a user to discover under load.

**2. v0.1's threads column is not a number, because v0.1 does not survive that shape.** It is not "faster"; it is broken. Probing 8 threads × 25 records through one v0.1 recorder:

| | v0.1 (`f047806`) | v0.2 |
| --- | --- | --- |
| `record_sync` calls that raised | **144 / 200** (`SinkError`, manifest `tmp→rename` race) | **0** |
| `verify_log` outcome | **`CHAIN_BREAK`** | **`OK`** |
| `prev_hash` claimed by >1 record | **1 (forked chain)** | **0** |

Concurrent v0.1 threads collide on the single shared `manifest.json.tmp` path — one thread renames it away, the next gets `FileNotFoundError` — and the records that *do* land fork the chain. So there is no v0.1 threads baseline to regress from. **The serialisation is not a slower version of what v0.1 did; it is the reason the concurrent case exists at all.**

v0.1's *coroutine* column does produce valid numbers, and the reason is worth stating: `LocalFileSink.write` has no `await` points, so on a single event loop the commit section is accidentally atomic. v0.1 was correct there by luck, not by design — the luck runs out the moment a sink yields, which every remote sink on the roadmap will.

### Verifier

Pre-populated 10 000-record corpus.

| Path | v0.1 | v0.2 | Delta |
| --- | --- | --- | --- |
| `verify_record` (hash + sig, records already in memory) | 3 708 rec/sec &nbsp;[3 706..3 716] | 3 616 rec/sec &nbsp;[3 574..3 652] | −2 % *(within spread)* |
| `verify_tree` (end-to-end from disk) | *did not exist* | 2 535 rec/sec &nbsp;[2 470..2 563] | — |

Per-record verification is **unchanged** — v0.2 added nothing to the signature check.

`verify_tree` is the auditor-facing path and has no v0.1 counterpart: it loads and cross-checks the manifest, digests every file with a **second full streaming sha256 pass**, walks each chain, and reconstructs the canonical form — from disk. It is ~30 % below the in-memory per-record rate. That is not a regression; it is a set of checks v0.1 did not perform. `chiplog verify <dir>` runs this path, so this is the number an auditor's wall clock actually sees:

| Chain size | `verify_tree` wall time (M2 Max) |
| --- | --- |
| 100 K records | ~40 seconds |
| 1 M records | ~6.5 minutes |
| 10 M records (~6-month window) | **~66 minutes** |

Parallelising by `chain_id` — one process per chain — scales with cores.

---

## v0.1 reference — Hetzner CCX13 (historical, measured 2026-06-23)

Kept for provenance. **These are v0.1 numbers on a machine v0.2 was never measured on.** Do not read them as current.

### Per-record latency

| Payload | `InMemorySink` (crypto ceiling) | `LocalFileSink` (durable) |
| --- | --- | --- |
| 256 B | 208 µs / record &nbsp;(4 813 rec/sec) | 1.75 ms / record &nbsp;(570 rec/sec) |
| 2 KB  | 285 µs / record &nbsp;(3 512 rec/sec) | 1.73 ms / record &nbsp;(577 rec/sec) |
| 8 KB  | 575 µs / record &nbsp;(1 739 rec/sec) | 2.24 ms / record &nbsp;(446 rec/sec) |

### Sustained throughput

| Payload | Throughput |
| --- | --- |
| 256 B | 621 rec/sec |
| 2 KB  | 551 rec/sec |
| 8 KB  | 479 rec/sec |

### Verifier throughput

**6 627 records / second** (`verify_record`; `verify_tree` did not exist in v0.1).

### What the Hetzner column does and does not license

The M2 Max is **~2× slower than the CCX13 on the durable path** (v0.1: ~266 vs ~551 rec/sec at 2 KB) — expected, since `F_FULLFSYNC` is a true platter sync and Linux `fsync()` is not. Less expected: the M2 Max is also **~1.8× slower on the CPU-bound verifier** (v0.1: 3 708 vs 6 627 rec/sec), so `bench/README.md`'s claim that CPU-bound rows are "roughly comparable across platforms" does not hold at this precision. Either way, the machine gap is measured only for v0.1, and it is not a conversion factor.

What can be said honestly: **on the same machine, v0.2's durable throughput is within ~4–12 % of v0.1's, mostly inside run-to-run spread.** So the v0.1 Hetzner durable figures are unlikely to have moved much under v0.2 — but "unlikely to have moved much" is an inference, not a measurement, and no v0.2 Hetzner number is published here until someone runs `bench/run_hetzner.sh`.

---

## Reference points

Ballpark sanity from peer projects:

| System | Pattern | Reported throughput |
| --- | --- | --- |
| Sigstore Rekor | Signed transparency log, single-leaf append | ~1–3 K leaves/sec sustained |
| etcd WAL | Append + `fsync`, unsigned | ~10–30 K entries/sec single-node |
| Raw Ed25519 `sign()` (pure crypto, no chaining, no I/O) | — | ~30–60 K sigs/sec single core on commodity x86 |

The gap vs. the raw Ed25519 ceiling is Python orchestration, JCS canonicalisation, the v0.2 normalize/redact passes, and `fsync`; the gap vs. etcd is the per-record signature plus the JSON canonical form.

## Storage caveat

Both reference machines use **local** storage. Network-attached storage has dramatically higher `fsync()` latency:

- AWS gp3 EBS: typically 500–2 000 µs per `fsync()`
- GCS persistent disk (standard): similar order
- Azure managed disk (Premium SSD): typically 200–1 000 µs

On the `LocalFileSink` path, expect throughput to drop **5–10×** vs. the tables above on any of the above, and per-record latency to rise to roughly **5–20 ms / record**.

The planned `S3Sink` is designed to remove synchronous `fsync()` from the hot path: writes buffer to a local WAL, an async coroutine batches them to S3, and S3 Object Lock provides durability instead of disk `fsync()`. **It has not shipped and is not benchmarked here.** Note the interaction with the crypto-ceiling regression above: once `fsync` is off the hot path, v0.2's 21–45 % normalize/redact cost stops being masked and becomes the visible cost. This matrix gets an `S3Sink` column when there is an `S3Sink`.

## Reproducing

See [`bench/README.md`](bench/README.md). The Apple M2 Max column reproduces via `uv run pytest bench/`. The Hetzner column reproduces via `bench/run_hetzner.sh`, which creates a fresh CCX13, runs the suite, downloads the output, and deletes the server.
