# Dataset

All measurements were acquired on one Raspberry Pi 5 by native processes that execute real ML-KEM-768 key generation,
encapsulation and decapsulation on a pinned core; the MacBook only orchestrated the runs over SSH and analysed the results.
Only public metadata leaves the board: identifiers, timings, counters and hashes. No secret key material is stored anywhere
in this repository.

## Layout

```
dataset/
├── raw/          one folder per acquisition campaign (see the table below)
├── interim/      session-level frames derived by the notebooks from the raw traces
├── processed/    causal feature rows of notebook 02
├── splits/       session assignments and purged forward folds
└── provenance/   acquisition manifest of the external sources (URL, size, SHA-256, licence)
```

Each process of a campaign leaves three files: `<session>.stdout.csv` with one row per request (schedule, arrival, service
and response times, CPU cycles, hits, admissions, stage timers, arena occupancy, temperature, frequency, success flag),
`<session>.record.json` with the process-level metadata (complete request-phase thread CPU, peak RSS, retained mapping,
lifecycle counters, board state before and after) and `<session>.stderr.txt` with the native log. Every campaign folder
carries a `done.json` or `SHA256SUMS` file whose digests the notebooks verify before any analysis. Earlier campaigns
(`Development_v1`, `Baseline_development_v1`, `Modern_development_v1`) use the per-session naming of their harnesses.

## Raw campaigns

| Folder | Content | Files | MiB | Notebook |
|---|---|---:|---:|---|
| `Development_v1` | initial seed-only collection: 60 training and 30 development sessions, 90 000 decapsulations | 273 | 19.6 | 01, 02 |
| `Pilot_20261018` | feasibility pilot: three processes per build (portable, arithmetic-only, SHA3-only, optimised) | 25 | 1.3 | 01 |
| `Baseline_development_v1` | seven baseline cache policies × 30 development sessions and six microbenchmark sessions | 647 | 32.4 | 03 |
| `Modern_development_v1` | ten policies (incl. TinyLFU, LeCaR, adaptive TTL, RF, HGB) × 30 development sessions | 1205 | 45.9 | 04 |
| `CoreCalibration/calibration8_20261019` | eight calibration processes behind the frozen operation costs | 54 | 0.1 | 05 |
| `CoreControllerDevelopment/screen40_9e7b1dd9_3628019` | 40-process development screen of the compact-secret controller | 206 | 7.6 | 05 |
| `Development05/development_20261020` | development series: 15 settings × 60 sessions (900 processes) | 2703 | 189.2 | 05 |
| `Confirmation06/confirmation_20261020` | confirmation on reserved seeds: 6 policies × 120 sessions (720 processes) | 2163 | 138.1 | 06 |
| `Supplementary06/replication_20261020` | replication on a second set of reserved seeds (720 processes) | 2163 | 138.1 | 06 |
| `Supplementary06/frequency1500_20261020` | pinned 1.5 GHz (240 processes) | 723 | 46.7 | 06 |
| `Supplementary06/interference_20261020` | busy loops on the three other cores (240 processes) | 723 | 46.0 | 06 |
| `Supplementary06/realtime_20261020` | SCHED_FIFO responder, four secret-retaining policies (160 processes) | 483 | 31.1 | 06 |
| `MLKEM_TestVectors` | NIST ACVP and Wycheproof ML-KEM test vectors (public fixtures, verified by notebook 01) | 36 | 14.0 | 01 |

Workload families: uniform, Poisson, Zipf, bursty, periodic, nonstationary, abrupt, thrashing, hot-cold and varying
contexts; 64 contexts and 1 000 requests per session at a 500 µs base interval. Seed namespaces never overlap between
training (10⁵), development (2·10⁵ and 4.1·10⁶) and reserved test campaigns (7.0·10⁶–7.4·10⁶).

## IoT-23 context logs (not redistributed)

Notebook 01 uses eight IoT-23 connection logs only as external network-traffic context; they contain no ML-KEM key
accesses and do not enter any model. The upstream licence notices conflict with the catalogue licence, so the files are
not included. To restore that section, download the files below into `dataset/raw/IoT23/<path>` (the notebook verifies
their size and SHA-256 against `provenance/acquisition_manifest.tsv` and skips the section when they are absent).

| Path under `raw/` | URL | Bytes | SHA-256 |
|---|---|---:|---|
| `IoT23/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled` | https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled | 61,653 | `aebe40ea0e03b120…` |
| `IoT23/CTU-Honeypot-Capture-5-1/bro/conn.log.labeled` | https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-5-1/bro/conn.log.labeled | 182,147 | `f36db06e7d6ba736…` |
| `IoT23/CTU-Honeypot-Capture-7-1/Somfy-01/bro/conn.log.labeled` | https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-7-1/Somfy-01/bro/conn.log.labeled | 18,024 | `fb37fb38393c48b0…` |
| `IoT23/CTU-IoT-Malware-Capture-3-1/bro/conn.log.labeled` | https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/bro/conn.log.labeled | 24,383,537 | `9851009bbca03e15…` |
| `IoT23/CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled` | https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled | 1,431,000 | `4877ca8f0f01902f…` |
| `IoT23/CTU-IoT-Malware-Capture-20-1/bro/conn.log.labeled` | https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-20-1/bro/conn.log.labeled | 419,604 | `ef48ad72f65efd13…` |
| `IoT23/CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled` | https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled | 2,926,718 | `d69e49b2aae8c1bd…` |
| `IoT23/CTU-IoT-Malware-Capture-42-1/bro/conn.log.labeled` | https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-42-1/bro/conn.log.labeled | 585,829 | `269fa1b22d9a37e1…` |
