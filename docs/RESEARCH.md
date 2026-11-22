# OrbitLink - Research Position

## Existing implementations surveyed
- **dtn7-rs / `bp7` crate**: BPv7 and BPSec (RFC 9173 contexts) in Rust. **Used here** for all bundle encoding
  and standard security (version 0.12.2, source inspected during development).
- NASA ION, HDTN, µD3TN, DTN Marshal Enterprise: established BPv7 implementations; **not evaluated yet**.
  ION's Contact Graph Routing is the reference CGR. The `Cgr` strategy here is a simplified earliest-arrival
  search, not ION's algorithm.

## Research questions (brief) and v0 status
| # | Question | v0 status |
|---|---|---|
| 1 | Secure exchange without continuous connectivity | Non-interactive per-bundle key transport (BcbPq) vs PSK |
| 2 | Protection during long storage | AES-GCM payload confidentiality + integrity at rest in relays |
| 3 | Key management across intermittent links | Only public keys needed (BcbPq); directory distribution **open** |
| 4 | Contact-aware routing and delivery probability | CGR-style vs epidemic vs first-contact (simulated) |
| 5 | Limited storage and bandwidth | 512 KiB satellite buffers, 256 kbit/s ground links; refusals and expiry measured |
| 6 | Cost of PQ protection | Bundle bytes (measured CBOR) and CPU (measured) per mode |
| 7 | Expiry and node disappearance | Lifetime expiry implemented and tested; node failures **not yet** modelled |

## Novelty status (honest)
- BPSec and its default contexts are **standard**. Their use here contributes nothing new.
- KEM-based (HPKE-style) key transport is **established** in other protocols. Applying ML-KEM to BPSec key
  transport may already be proposed; **literature check needed** (search IETF DTN WG drafts for COSE/HPKE or
  PQ security contexts).
- **Candidate contribution (hypothesis):** quantify end-to-end delivery effects, not only per-bundle bytes, of
  carrying 1088-byte ML-KEM ciphertexts per bundle on capacity-limited, buffer-limited LEO contact plans, and
  compare that with amortised alternatives (per-session KEM keys cached at the destination).

## References verified during development
- RFC 9171, RFC 9172, RFC 9173: block types, security block numbers (11, 12) and context ids (1, 2) as
  implemented in `bp7` (checked in source). Text of the RFCs not re-read; section numbers in comments come from
  the `bp7` source.
