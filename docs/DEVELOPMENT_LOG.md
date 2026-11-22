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
`results/20261122T103220Z/`, 144 runs, about 30 min. Zero crypto failures.

### Found after the run
- Svalbard (78.2 N) has 0 passes with a 53-degree shell (`examples/contacts.rs`). One third of bundles are
  undeliverable by construction. Documented in the paper draft; scenario redesign is TODO.
- FirstContact + ISL rings loop bundles until expiry (huge overhead). This is a property of the naive baseline.

### Incomplete
Polar shell, node failures, ML-DSA sender authentication, amortised KEM, ION comparison, more seeds.
