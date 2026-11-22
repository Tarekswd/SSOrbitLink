# OrbitLink (SSOrbitLink)

A delay-tolerant networking (DTN) **simulator** for LEO satellite and ground-station networks. It uses real
**BPv7 bundles** (RFC 9171) and real **BPSec** (RFC 9172, with the RFC 9173 default security contexts), and it
studies an **experimental post-quantum key transport** for bundle confidentiality when there is no end-to-end path.

> **Simulation only.** No compatibility with flight hardware, ground-segment software or real ephemerides is
> claimed. All network metrics are simulated. Cryptographic CPU times are measured on the development machine.

## Standard vs experimental

| Component | Status | Source |
|---|---|---|
| Bundle encoding (primary, payload, hop-count blocks, CRC-32) | Standard BPv7 | [`bp7`](https://crates.io/crates/bp7) 0.12.2 crate (dtn7 project) |
| BIB-HMAC-SHA2 integrity, BCB-AES-GCM confidentiality (direct keys, no key wrap) | Standard BPSec / RFC 9173 | `bp7` (`bpsec` feature) |
| Bundle lifetime expiry, store-and-forward, custody-less transfer | BPv7 semantics, simplified | `src/sim.rs` |
| Per-bundle ML-KEM-768 key transport (`Mode::BcbPq`) | **Standards-track encoding, not novel**: BPSec COSE context (draft-ietf-dtn-bpsec-cose-19) + ML-KEM COSE recipient (draft-ietf-cose-pqc-kem-00), checked against the draft's Appendix A vector | `src/cose.rs` |
| Session-amortised ML-KEM key transport (`Mode::BcbPqSession`) | **Experimental, candidate research contribution** | `src/security.rs`, `src/sim.rs` |
| Contact-plan generator (Walker-delta LEO, elevation mask) | Ours, simplified physics | `src/contact.rs` |
| CGR-style earliest-arrival routing; epidemic and first-contact baselines | Ours (not ION's CGR) | `src/sim.rs` |

### Post-quantum key transport
`BcbPq` implements the IETF path: a BCB with COSE security context 3 holding an untagged COSE_Encrypt (result 96,
detached payload). Its single recipient uses ML-KEM-768 in Direct Key Agreement mode with
CEK = KMAC256(shared secret, COSE_KDF_Context). Tests reproduce the draft's Appendix A external_aad and AES-256-GCM
ciphertext byte for byte, and the NIST KMAC256 samples. Two codepoints are still unassigned in the drafts and use
placeholders: ML-KEM-768 "TBD2" and `ek` "TBD11 (assumed -4)". The mechanism is not novel.

`BcbPqSession` is the research question: one encapsulation per (source, destination, hour), with the KEM ciphertext
carried only by the first r bundles and COSE "direct" recipients after that. It trades bytes against the risk that
a delivered bundle never meets its session key. Results are in [docs/PAPER_DRAFT.md](docs/PAPER_DRAFT.md).

## Build, test, reproduce (Linux / WSL2)
```bash
cargo test --release                                   # 25 tests (incl. draft Appendix A and NIST KMAC vectors)
cargo run --release --bin orbitlink-sim -- 3 out.csv   # 3 seeds x 60 configurations (12 h simulated each)
bash experiments/run.sh 3                              # same, with environment capture and summary
```

## Scenario defaults
6 ground stations: Svalbard, Beirut, Nairobi, Singapore, Santiago, Fairbanks (rounded coordinates).
72 satellites: a 53-degree shell (6 planes x 8, 550 km) plus a near-polar shell (3 x 8, 560 km, 97.6 degrees) so that
Svalbard is reachable; 10 degree elevation mask. Inspect coverage with `cargo run --release --example contacts`.
Ground links 256 kbit/s; optional intra-plane ISLs at 1 Mbit/s. 2 KiB payloads, 3 h lifetime.
Satellite buffers 512 KiB. Load of 20 or 120 bundles per station per hour. The energy figure assumes
1e-7 J/bit: **an illustrative assumption, not a measured or sourced value.**

Documents: [docs/RESEARCH.md](docs/RESEARCH.md) | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
[docs/PAPER_DRAFT.md](docs/PAPER_DRAFT.md) | [docs/DEVELOPMENT_LOG.md](docs/DEVELOPMENT_LOG.md)

## License
Apache-2.0 OR MIT.
