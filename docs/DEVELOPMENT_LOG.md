# OrbitLink Development Log

## 2026-11-22
### Decisions
- Do not reimplement BPv7: use the `bp7` 0.12.2 crate (dtn7 project) for bundles and its `bpsec` feature for RFC
  9173 BIB-HMAC-SHA2 / BCB-AES-GCM (APIs read in source: `bib::sign/verify`, `bcb::encrypt/decrypt`, `wrap_key`).
- Experimental PQ key transport: ML-KEM-768 ciphertext in extension block type 200, KEK = HKDF-SHA256(ss),
  CEK AES-key-wrapped as the RFC 9173 wrapped-key parameter.
- Contact plan from simplified Walker-delta geometry; CGR-style earliest-arrival routing (not ION CGR).

### What failed and was fixed
- `validate()` rejected unsecured bundles: RFC 9171 requires a primary-block CRC unless a BIB covers it (bp7
  enforces this). Bundles now carry CRC-32.
- Non-deterministic sizes: `CreationTimestamp::now()` and bp7's global sequence counter changed CBOR integer
  lengths between runs. Bundles now use a simulation epoch (2026-01-01) plus sim time and a per-run sequence number.

### Tested
13 integration tests (geometry, contact plan, all security modes round-trip, tamper/ciphertext/wrong-recipient
rejection, CGR on a hand-built plan, expiry, determinism, config validation). clippy `-D warnings` and fmt clean.

### Results
`results/20261122T114527Z/` (rerun after the key-wrap removal below), 144 runs. Zero crypto failures.

### Found after the run
- Svalbard (78.2 N) has 0 passes with a 53-degree shell (`examples/contacts.rs`). One third of bundles are
  undeliverable by construction. Documented in the paper draft; scenario redesign is TODO.
- FirstContact + ISL rings loop bundles until expiry (huge overhead). This is a property of the naive baseline.

### Incomplete
Polar shell, node failures, ML-DSA sender authentication, amortised KEM, ION comparison, more seeds.

## 2026-11-22 (later) - constant-time fix
- Source review found `aes-kw` 0.2.1 (used by bp7 for RFC 9173 key unwrap) compares its integrity value with `==`.
- Reviewed PHOENIX-PQ for reusable parts: adopted its ctgrind/dudect methodology as a next step and its warning
  that WSL2 timing is unreliable; nothing in it replaces key unwrap.
- Fix: no wrapped keys. BcbPq uses HKDF(ML-KEM ss) directly as the AES-GCM key; BcbPsk uses the PSK directly
  (random IVs, rotate well before 2^32 bundles). `accept()` refuses BCBs carrying a wrapped-key parameter.
  2 new tests (15 total); a mutation check shows the refusal guard is what rejects the forged bundle.
- Rerun: bundles are 44 bytes smaller in both BCB modes; delivery conclusions unchanged. The old results directory
  (20261122T103220Z, key-wrap format) was replaced. The laptop slept and throttled during the rerun, so CPU-time
  columns are very noisy; network metrics are deterministic and unaffected.

## 2026-11-22 (later) - polar shell, references
- Added `PlanConfig::shells` (several Walker shells) and `default_shells()`: the 53-degree shell plus a near-polar
  shell (3 x 8 at 560 km, 97.6 degrees, sun-synchronous by J2 calculation). Svalbard goes from 0 to 136 passes in
  12 h. New regression test (16 total).
- Rerun `results/20261122T153249Z/` (144 runs, zero crypto failures). CGR delivery rises from 0.31-0.40 to 0.67-0.78.
  Conclusions about PQ overhead hold (epidemic/high load: -18 to -25 % vs PSK). The previous results directory
  (53-degree shell only) was replaced.
- References verified (RFC 9171 private block range, RFC 9173 ids and optional wrapped key, SP 800-38D 2^32 bound).
  Found draft-ietf-dtn-bpsec-cose-19: possible overlap with the PQ key transport; must be read before any novelty claim.
