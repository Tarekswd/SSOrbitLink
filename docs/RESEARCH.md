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
- KEM-based (HPKE-style) key transport is **established** in other protocols. The IETF DTN WG's BPSec COSE context
  draft (draft-ietf-dtn-bpsec-cose-19) exists; whether it already enables ML-KEM key transport must be checked
  before any novelty claim.
- **Candidate contribution (hypothesis):** quantify end-to-end delivery effects, not only per-bundle bytes, of
  carrying 1088-byte ML-KEM ciphertexts per bundle on capacity-limited, buffer-limited LEO contact plans, and
  compare that with amortised alternatives (per-session KEM keys cached at the destination).

## References (verified 2026-11-22 against primary sources)
- RFC 9171, *Bundle Protocol Version 7* (Burleigh, Fall, Birrane): block type codes 192-255 are "Reserved for
  Private and/or Experimental Use". Our ML-KEM block uses type 200.
- RFC 9173, *Default Security Contexts for BPSec* (Birrane, White, Heiner): context ids BIB-HMAC-SHA2 = 1,
  BCB-AES-GCM = 2. The wrapped-key parameter is optional: "If this parameter is not present, then security
  verifiers and acceptors MUST determine the proper key as a function of their local BPSec policy and
  configuration". That is what OrbitLink does after removing key wrap.
- NIST SP 800-38D (GCM): with random IVs, "the total number of invocations of the authenticated encryption function
  shall not exceed 2^32 ... with the given key". This is the BcbPsk rotation bound.
- draft-ietf-dtn-bpsec-cose-19 (Sipos; active dtn WG draft, updated 2026-11-19): a COSE security context for BPSec.
  **Novelty impact:** a standard path for KEM/HPKE-style key transport in BPSec may already be under way. Whether
  it covers ML-KEM is NOT checked yet; read it before claiming anything about the PQ key transport.
- Sun-synchronous inclination at 550-560 km: 97.59-97.63 degrees, computed from the J2 nodal-precession condition
  (J2 = 1.08263e-3, R = 6378.137 km). This justifies the 97.6-degree polar shell.

## Input from PHOENIX-PQ (github.com/Tarekswd/PHOENIX-PQ, reviewed 2026-11-22)
- Adopted as next steps: its constant-time methodology. That means ctgrind (Valgrind memcheck with secret
  inputs marked undefined) and dudect fixed-vs-random tests with input preparation outside the timed region and
  a positive control. Its finding that WSL2 timing cannot detect the positive control means OrbitLink's
  protect/accept CPU times are wall-clock costs only, never side-channel evidence.
- Not applicable: PHX-Tri (X25519 + ML-KEM-768 + HQC-3 hybrid KEM) is C/liboqs/HQC. Its 10 KB ciphertext would
  make DTN bundle overhead about 9x worse than ML-KEM-768 alone. Recorded as a possible future comparison point only.
