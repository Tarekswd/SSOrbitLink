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
| Per-bundle ML-KEM-768 key transport (`Mode::BcbPq`, extension block type 200) | **Experimental, ours** | `src/security.rs` |
| Contact-plan generator (Walker-delta LEO, elevation mask) | Ours, simplified physics | `src/contact.rs` |
| CGR-style earliest-arrival routing; epidemic and first-contact baselines | Ours (not ION's CGR) | `src/sim.rs` |

### Experimental PQ key transport
The sender encapsulates to the destination's long-term ML-KEM-768 public key and uses
HKDF-SHA256(shared secret) directly as the per-bundle AES-256-GCM key for a standard BCB-AES-GCM block. No key
wrapping is used anywhere, because the key-wrap library's integrity check is not constant-time; see the threat model. The 1088-byte ML-KEM ciphertext travels in extension block type 200, which is
in RFC 9171's private/experimental range. The point is that no pre-shared secret and no interactive handshake
are needed, only the destination's public key. The limitation is that this gives **no sender authentication**;
see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Build, test, reproduce (Linux / WSL2)
```bash
cargo test --release                                   # 15 tests
cargo run --release --bin orbitlink-sim -- 3 out.csv   # 3 seeds x 48 configurations (12 h simulated each)
bash experiments/run.sh 3                              # same, with environment capture and summary
```

## Scenario defaults
6 ground stations: Svalbard, Beirut, Nairobi, Singapore, Santiago, Fairbanks (rounded coordinates).
48 satellites in 6 planes at 550 km and 53 degrees inclination, 10 degree elevation mask.
Ground links 256 kbit/s; optional intra-plane ISLs at 1 Mbit/s. 2 KiB payloads, 3 h lifetime.
Satellite buffers 512 KiB. Load of 20 or 120 bundles per station per hour. The energy figure assumes
1e-7 J/bit: **an illustrative assumption, not a measured or sourced value.**

Documents: [docs/RESEARCH.md](docs/RESEARCH.md) | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
[docs/PAPER_DRAFT.md](docs/PAPER_DRAFT.md) | [docs/DEVELOPMENT_LOG.md](docs/DEVELOPMENT_LOG.md)

## License
Apache-2.0 OR MIT.
