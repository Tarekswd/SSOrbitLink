# Amortising Post-Quantum Key Transport in Delay-Tolerant Satellite Networks

*Working draft. Network metrics are SIMULATED and cryptographic CPU times are MEASURED
(`results/20261122T164252Z/`: 180 runs = 60 configurations x 3 seeds, 12 h simulated each). Sections marked
**[TODO]** are not done.*

## Abstract

Bundle Protocol Security is moving to COSE, and ML-KEM is the expected post-quantum key transport there
(draft-ietf-dtn-bpsec-cose-19 with draft-ietf-cose-pqc-kem-00). We implement that encoding: a BCB with security
context 3 carrying a COSE_Encrypt with one ML-KEM-768 recipient. Our AAD construction and AES-256-GCM output
reproduce the draft's Appendix A vector byte for byte, and KMAC256 matches the NIST SP 800-185 samples. Per bundle,
ML-KEM key transport adds 1,184 bytes. With no end-to-end acknowledgements, a sender cannot know when the destination
has learned a key, so amortisation is risky. We measure a simple amortisation: one encapsulation per
(source, destination, hour), with the KEM ciphertext carried only by the first r bundles of the session and a COSE
"direct" recipient in the others. In a simulated 72-satellite LEO DTN it cuts security bytes per bundle from
1,184 to 132-807, and the number of KEM-carrying bundles by 34-96 %. It changes the outcome in opposite directions
depending on routing. Under buffer-bound epidemic routing it **raises** decrypted delivery (0.283 to 0.323,
+14 %, at high load without ISLs). Under contact-graph routing it **lowers** it by up to 0.034 absolute. Under
first-contact (random-walk) routing it lowers it by up to 0.114 absolute: with r = 1 at high load, 41 % of
delivered bundles are never decrypted. The less predictable the routing, the less safe amortisation becomes,
because delivered bundles miss every key-carrying bundle of their session before they expire.

## 1. Contribution and novelty status

- **Not novel:** ML-KEM key transport in BPSec, which is the IETF path (bpsec-cose + cose-pqc-kem). We implement and
  measure it.
- **Candidate contribution:** the amortisation/decryptability trade-off of post-quantum key transport in
  acknowledgement-free DTNs, quantified per routing regime. A limited literature check found no prior
  measurement of this: the IETF drafts, the DTKA draft, the DTN key-management survey (Menesidou et al. 2017) and
  Rüsch et al. (CHANTS 2017, per-bundle puncturable encryption, no amortisation, not PQ). **[TODO]** A systematic
  literature search before submission.

## 2. Setup

Constellation, stations and traffic are as in README. Coverage: a 53-degree shell plus a 97.6-degree shell, so every
station has at least 104 passes in 12 h. Variants: None, BcbPsk (RFC 9173, PSK used directly), BcbPq (COSE,
ML-KEM per bundle), and BcbPqSession with r = 1 or 3 (session = one hour). A delivered session bundle counts as
decrypted only if a key-carrying bundle of its session reaches the destination before the bundle's 3 h lifetime
ends. Placeholder codepoints: ML-KEM-768 "TBD2" and `ek` "TBD11 (assumed -4)"; see src/cose.rs.

## 3. Results (mean +/- 95 % CI over 3 seeds; full table in summary.md)

### Bytes

| Variant | Added bytes per bundle (high load / low load) | KEM-carrying bundles (high load) |
|---|---|---|
| BcbPsk | 48 / 48 | 0 |
| BcbPq (COSE, per bundle) | 1,184 / 1,184 | 8,624 of 8,624 |
| BcbPqSession r=1 | 132 / 349 | 360 |
| BcbPqSession r=3 | 224 / 807 | 1,080 |

The COSE encoding costs 39 bytes per bundle more than our earlier ad-hoc stand-in (1,145 bytes).

### Decrypted delivery ratio (delivered and decrypted within lifetime / generated)

| ISL | load | routing | BcbPq | Session r=1 | Session r=3 | BcbPsk |
|---|---|---|---|---|---|---|
| off | 120 | CGR | 0.678 +/- 0.007 | 0.644 +/- 0.014 | 0.651 +/- 0.012 | 0.678 |
| off | 20 | CGR | 0.672 +/- 0.008 | 0.653 +/- 0.016 | 0.667 +/- 0.002 | 0.672 |
| on | 120 | CGR | 0.778 +/- 0.012 | 0.751 +/- 0.014 | 0.755 +/- 0.016 | 0.778 |
| on | 20 | CGR | 0.772 +/- 0.011 | 0.756 +/- 0.011 | 0.771 +/- 0.007 | 0.772 |
| off | 120 | Epidemic | 0.283 +/- 0.011 | 0.322 +/- 0.010 | 0.323 +/- 0.006 | 0.382 |
| off | 20 | Epidemic | 0.647 +/- 0.013 | 0.649 +/- 0.007 | 0.657 +/- 0.012 | 0.672 |
| on | 120 | Epidemic | 0.331 +/- 0.010 | 0.323 +/- 0.018 | 0.340 +/- 0.001 | 0.403 |
| on | 20 | Epidemic | 0.726 +/- 0.013 | 0.748 +/- 0.017 | 0.745 +/- 0.013 | 0.771 |

### Findings

1. **CGR: amortisation costs decryptability, not delivery.** Delivery is identical, but 3-5 % of delivered bundles
   stay undecryptable at high load. r = 3 recovers almost everything at low load (0.771 vs 0.772 with ISLs). At high
   load it barely helps (0.651 vs 0.644): with about 24 bundles per session per hour, the first r bundles are a
   small, time-clustered sample, and when they fail the later bundles cannot recover.
2. **Epidemic: amortisation helps when buffers bind.** Smaller bundles mean fewer refusals. Decrypted delivery rises
   by 0.039-0.040 at high load without ISLs, and the median time to plaintext falls from 8,024 s to 6,566 s. With ISLs
   at high load, r = 1 is not better than per-bundle (0.323 vs 0.331) but r = 3 is (0.340).
3. **Unpredictable routing punishes amortisation most.** Under FirstContact, delivery is unchanged, but decrypted
   delivery at high load drops from 0.226 to 0.130 (r = 1) or 0.176 (r = 3) without ISLs, and from 0.332 to 0.218 or
   0.266 with ISLs. Key-carrying bundles and later bundles take unrelated random paths.
4. **The gap to PSK remains.** Even the best PQ variant stays below BcbPsk under epidemic routing at high load
   (0.323-0.340 vs 0.382-0.403).

## 4. Periodic ciphertext refresh (results/20261125T102421Z)

Finding 1 suggests carrying the ciphertext *where it will be needed* rather than only first. We tested the
simplest form: r = 1 plus the ciphertext on every k-th bundle of a session (k = 4, 8; `refresh_every`). The other
cells of this run reproduce section 3 exactly (the simulator is deterministic per seed).

Decrypted delivery ratio, with added bytes per bundle in brackets (high load / low load):

| ISL | load | routing | BcbPq | r=1 | r=3 | r=1, k=4 | r=1, k=8 | BcbPsk |
|---|---|---|---|---|---|---|---|---|
| off | 120 | CGR | 0.678 | 0.644 | 0.651 | 0.678 | 0.678 | 0.678 |
| on | 120 | CGR | 0.778 | 0.751 | 0.755 | 0.778 | 0.778 | 0.778 |
| off | 20 | CGR | 0.672 | 0.653 | 0.667 | 0.664 | 0.653 | 0.672 |
| on | 20 | CGR | 0.772 | 0.756 | 0.771 | 0.766 | 0.758 | 0.772 |
| off | 120 | Epidemic | 0.283 | 0.322 | 0.323 | 0.348 | 0.362 | 0.382 |
| on | 120 | Epidemic | 0.331 | 0.323 | 0.340 | 0.372 | 0.373 | 0.403 |
| off | 120 | FirstContact | 0.226 | 0.130 | 0.176 | 0.214 | 0.201 | 0.222 |
| on | 120 | FirstContact | 0.332 | 0.218 | 0.266 | 0.320 | 0.304 | 0.327 |
| bytes | | | 1,184 / 1,184 | 132 / 349 | 224 / 807 | 378 / 457 | 243 / 353 | 48 / 48 |

5. **At high load, periodic refresh closes the CGR gap.** k = 8 matches per-bundle BcbPq (0.678, 0.778) at 21 %
   of its bytes (243 vs 1,184), and beats r = 3 on both decryptability and bytes. Refreshing spreads key-carrying
   bundles over the epoch, so one failed early burst no longer strands the rest of the session.
6. **At low load, refresh rarely fires.** Sessions hold only a few bundles per hour, so k = 8 is almost r = 1
   (360 vs 354 key-carrying bundles) and k = 4 sits between r = 1 and r = 3. Here r = 3 is better (0.667 vs 0.664)
   but costs 807 vs 457 bytes. A rule keyed to bundle count does not adapt to load; a time- or contact-based
   rule is the next variant.
7. **Under epidemic routing at high load, refresh is the best PQ variant.** k = 8 reaches 0.362 / 0.373, narrowing
   the gap to BcbPsk to 0.02-0.03 (from 0.06-0.08 for r = 1).
8. **Under FirstContact, refresh recovers most of the loss.** k = 4 recovers 0.214 of 0.226 and 0.320 of 0.332, at
   32 % of per-bundle bytes.

Not yet tested: contact-aware refresh (on a new first hop), and destination-generated key acknowledgements.
Every result here uses 3 seeds, so differences below about 0.015 are within the CIs (see summary.md).

## 5. Security trade-off

A session key protects up to one hour of bundles between a pair: compromising it exposes that epoch, whereas
per-bundle keys bound exposure to one bundle. The receiver caches a session key only after it authenticated a
bundle, so a forged KEM ciphertext cannot poison the cache (test `forged_kem_bundle_does_not_poison_session_cache`).
There is still no sender authentication (ML-DSA via the COSE context is future work).

## 6. Limitations

Simplified orbits; no inter-shell links; static rates; CGR without volume accounting; 3 seeds; one session length
(1 h); single network-wide PSK; placeholder COSE codepoints; the PartyU/V KDF detail differs between the two drafts.

## References (verified; see docs/RESEARCH.md)

RFC 9171, RFC 9172, RFC 9173; draft-ietf-dtn-bpsec-cose-19; draft-ietf-cose-pqc-kem-00; draft-ietf-cose-hpke-27;
NIST SP 800-38D; NIST SP 800-185 KMAC samples; FIPS 203; S. Rüsch et al., *Forward Secure Delay-Tolerant
Networking*, CHANTS 2017, doi:10.1145/3124087.3124094; S. A. Menesidou et al., *Cryptographic Key Management in
Delay Tolerant Networks: A Survey*, Future Internet 2017; draft-burleigh-dtnwg-dtka.
