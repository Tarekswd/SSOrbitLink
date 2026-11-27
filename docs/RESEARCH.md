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

## Novelty status (checked 2026-11-22)
- BPSec and its default contexts are **standard**. Their use here contributes nothing new.
- **Per-bundle ML-KEM key transport for BPSec is NOT novel.** draft-ietf-dtn-bpsec-cose-19 (Sipos, published
  2026-11-18) states: "For using a PQ key encapsulation mechanism (KEM) within BCB results, there are drafts for both
  direct ML-KEM use in a COSE recipient [I-D.ietf-cose-pqc-kem] and within Hybrid Public Key Encryption (HPKE)
  [I-D.ietf-cose-hpke] as both PQ-only and PQ/T hybrids [I-D.ietf-cose-hpke-pq-pqt]." draft-ietf-cose-pqc-kem
  describes ML-KEM as "a one-pass (store-and-forward) cryptographic mechanism" for sending keying material to a
  recipient. That is OrbitLink's construction and motivation. The COSE context also profiles ML-DSA signatures
  and certificate-based authentication of the security source, which addresses BcbPq's missing sender
  authentication.
- **Candidate contribution (2026-11-22):** the amortisation/decryptability trade-off of post-quantum key transport
  without end-to-end acknowledgements (`BcbPqSession`), measured per routing regime. Literature checked so far found no
  prior measurement of it: the IETF drafts above, draft-burleigh-dtnwg-dtka (Delay-Tolerant Key Administration),
  Menesidou et al., *Cryptographic Key Management in Delay Tolerant Networks: A Survey* (Future Internet 2017), and
  Rüsch et al., *Forward Secure Delay-Tolerant Networking* (CHANTS 2017). Rüsch et al. was read in full; it uses
  per-bundle puncturable encryption (pairing-based) with no amortisation and nothing post-quantum. This was a
  limited search (4 queries + 1 paper); a systematic search is needed before any novelty claim.
- **Periodic refresh (2026-11-25, results/20261125T102421Z):** r = 1 plus the ciphertext on every 8th bundle
  matches per-bundle decryptability under CGR at high load at 21 % of its bytes, but it barely fires at low load
  (PAPER_DRAFT.md section 4). Next: time- or contact-based refresh, and destination key acknowledgements.
- **Time-based refresh, 10 seeds (2026-11-26, results/20261125T141910Z, 1,080 runs):** r = 1 plus the ciphertext
  again once 900 s have passed since it was last carried is within 0.001 of per-bundle decryptability in all four
  CGR cells, at 22 % (high load) / 56 % (low load) of the per-bundle bytes, and is near the best variant in every
  routing regime. Under FirstContact at high load, every-4th-bundle refresh is still slightly better. The 3-seed
  findings hold at 10 seeds. Next: contact-aware refresh, a sweep over t, destination key acknowledgements.
- **Uplink-change refresh and t = 300/600 s (2026-11-27, results/20261126T200000Z, 1,440 runs):** carrying the
  ciphertext again whenever the source's uplink satellite changes (r1u) comes within 0.010 of per-bundle
  decryptability under FirstContact at both loads (38-76 % of bytes); t = 300 s does almost as well at the same cost.
  Under epidemic routing frequent refresh hurts (t = 600-900 s best). Refresh rule should follow the routing regime.
- Related work found 2026-11-25 (abstracts read, full texts not yet): Eichen et al., *Practical Post-Quantum
  Cryptography for Bandwidth Constrained or Non-Terrestrial Networks, and Power Constrained Devices*
  (arXiv 2607.23007). It replaces PQ certificates with shared secret keys: a KDC plus a PSK handshake plus ML-KEM,
  which is interactive and handshake-based. Dowling et al., *Key Establishment in the Space Environment*
  (arXiv 2503.06785): a survey of space key-establishment paradigms and gaps. Neither measures amortised
  non-interactive PQ key transport.
- Done: `BcbPq` now uses the COSE context encoding (src/cose.rs); the block-200 stand-in was removed.

## References (verified 2026-11-22 against primary sources)
- RFC 9171, *Bundle Protocol Version 7* (Burleigh, Fall, Birrane): block type codes 192-255 are "Reserved for
  Private and/or Experimental Use". Our ML-KEM block uses type 200.
- RFC 9173, *Default Security Contexts for BPSec* (Birrane, White, Heiner): context ids BIB-HMAC-SHA2 = 1,
  BCB-AES-GCM = 2. The wrapped-key parameter is optional: "If this parameter is not present, then security
  verifiers and acceptors MUST determine the proper key as a function of their local BPSec policy and
  configuration". That is what OrbitLink does after removing key wrap.
- NIST SP 800-38D (GCM): with random IVs, "the total number of invocations of the authenticated encryption function
  shall not exceed 2^32 ... with the given key". This is the BcbPsk rotation bound.
- draft-ietf-dtn-bpsec-cose-19 (Sipos, published 2026-11-18): COSE security context for BPSec. It supports
  COSE_Encrypt0/Encrypt, COSE_Mac0/Mac and COSE_Sign1/Sign; recipient key wrap and ECDH-ES; PKIX-certificate
  authentication of security sources; ML-DSA in its algorithm profile; and it points to the PQ KEM drafts below.
- draft-ietf-cose-pqc-kem, *Post-Quantum Key Encapsulation Mechanisms (PQ KEMs) for COSE*: ML-KEM as a COSE recipient.
- draft-ietf-cose-hpke-pq-pqt, *COSE HPKE PQ & PQ/T Algorithm Registrations*.
- Sun-synchronous inclination at 550-560 km: 97.59-97.63 degrees, computed from the J2 nodal-precession condition
  (J2 = 1.08263e-3, R = 6378.137 km). This justifies the 97.6-degree polar shell.

## Input from PHOENIX-PQ (github.com/Tarekswd/PHOENIX-PQ, reviewed 2026-11-22)
- Adopted as next steps: its constant-time methodology. That means ctgrind (Valgrind memcheck with secret
  inputs marked undefined) and dudect fixed-vs-random tests with input preparation outside the timed region and
  a positive control. Its finding that WSL2 timing cannot detect the positive control means OrbitLink's
  protect/accept CPU times are wall-clock costs only, never side-channel evidence.
- Not applicable: PHX-Tri (X25519 + ML-KEM-768 + HQC-3 hybrid KEM) is C/liboqs/HQC. Its 10 KB ciphertext would
  make DTN bundle overhead about 9x worse than ML-KEM-768 alone. Recorded as a possible future comparison point only.

## Systematic novelty search (2026-11-27)

Question: does prior work (a) reuse one KEM encapsulation / session key across several bundles without
acknowledgements, or (b) measure how often delivered bundles can be decrypted under different DTN routing?

Queries (Firecrawl research index = arXiv/PubMed/bioRxiv; web = general search):
1. research: "post-quantum key encapsulation ML-KEM Kyber delay-tolerant networking bundle protocol security"
2. research: "amortized key establishment session key reuse delay tolerant network without acknowledgements decryption failure"
3. research: "post-quantum cryptography LEO satellite constellation key exchange overhead routing simulation"
4. research: "delay tolerant network bundle encryption key availability at destination routing epidemic contact graph routing simulation security overhead"
5. web: "BPSec post-quantum key encapsulation bundle protocol DTN ML-KEM"
6. web: "delay tolerant network key management asynchronous key establishment no round trip bundle encryption session key reuse"
7. web: site:datatracker.ietf.org dtn bpsec key management post-quantum OR KEM
8. web: KEM encapsulation reuse across one-way messages / amortised post-quantum ciphertext overhead
9. web: "delay tolerant" "post-quantum" key encapsulation satellite simulation 2025/2026

Read (question-answering pass over the full text; verdict for (a) / (b)):
| work | what it does | (a) | (b) |
|---|---|---|---|
| Detke, Madoery, Cherini, Fraire, Finochietto, WiSEE 2026 (hal-05850001) | MILP minimising pre-provisioned symmetric key scopes for CGR routes; 20-node polar scenario | no | no (exposure and operation density only) |
| Würbs, Baumgärtner, Wallum, BPKD, SpaceOps 2025 | public-key distribution by keystore snapshots; derived long-lived symmetric keys; docker testbed | no per-session KEM | no |
| dos Santos, Reith, Koranek, ECCWS (survey) | ML-KEM in DTN: side channels, sizes; names key expiry in transit as open | no | no (no simulation) |
| Tanchev, STINT 2026 (slides) | per-bundle encapsulation to receiver epoch KEM keys, self-authenticating addresses | no | no |
| Kedrowitsch, VT dissertation 2025 | ML-KEM under intermittent computing; BPv7 module for ns-3 | no | no |
| draft-ietf-dtn-bpsec-default-sc | became RFC 9173 (already covered) | - | - |
Also surfaced, not DTN: De Zuane et al., arXiv 2605.28660 (quantum-safe IKE for satellites, interactive);
Burkhardt et al., arXiv 2206.00978 (Kyber key exchange with a nanosatellite); Herzinger et al., arXiv 2610.32356
(large PQ KEMs in IKEv2).

Verdict: no prior work found for (a) or (b). The candidate contribution stands. Not covered: paywalled IEEE/ACM
full texts beyond what the web index returned; non-English literature.
