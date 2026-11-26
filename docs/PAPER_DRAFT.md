# Amortising Post-Quantum Key Transport in Delay-Tolerant Satellite Networks

*Working draft. Network metrics are SIMULATED and cryptographic CPU times are MEASURED
(`results/20261125T141910Z/`: 1,080 runs = 108 configurations x 10 seeds, 12 h simulated each). Sections marked
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
depending on routing. Under buffer-bound epidemic routing it **raises** decrypted delivery (0.285 to 0.325,
+14 %, at high load without ISLs). Under contact-graph routing it **lowers** it by up to 0.031 absolute. Under
first-contact (random-walk) routing it lowers it by up to 0.121 absolute: with r = 1 at high load without ISLs, 42 % of
delivered bundles are never decrypted. The less predictable the routing, the less safe amortisation becomes,
because delivered bundles miss every key-carrying bundle of their session before they expire. Re-carrying the
ciphertext once 15 minutes have passed since it was last sent restores per-bundle decryptability under CGR at both
loads (within 0.001) for 22-56 % of the per-bundle bytes.

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

## 3. Results (mean +/- 95 % CI over 10 seeds; full table in summary.md)

### Bytes

| Variant | Added bytes per bundle (high load / low load) | KEM-carrying bundles (high load) |
|---|---|---|
| BcbPsk | 48 / 48 | 0 |
| BcbPq (COSE, per bundle) | 1,184 / 1,184 | 8,645 of 8,645 |
| BcbPqSession r=1 | 132 / 351 | 360 |
| BcbPqSession r=3 | 223 / 807 | 1,080 |

The COSE encoding costs 39 bytes per bundle more than our earlier ad-hoc stand-in (1,145 bytes).

### Decrypted delivery ratio (delivered and decrypted within lifetime / generated)

| ISL | load | routing | BcbPq | Session r=1 | Session r=3 | BcbPsk |
|---|---|---|---|---|---|---|
| off | 120 | CGR | 0.678 +/- 0.004 | 0.647 +/- 0.005 | 0.653 +/- 0.004 | 0.678 |
| off | 20 | CGR | 0.677 +/- 0.005 | 0.658 +/- 0.007 | 0.674 +/- 0.006 | 0.677 |
| on | 120 | CGR | 0.780 +/- 0.004 | 0.754 +/- 0.005 | 0.760 +/- 0.006 | 0.780 |
| on | 20 | CGR | 0.775 +/- 0.004 | 0.760 +/- 0.004 | 0.773 +/- 0.003 | 0.775 |
| off | 120 | Epidemic | 0.285 +/- 0.004 | 0.325 +/- 0.003 | 0.324 +/- 0.002 | 0.383 |
| off | 20 | Epidemic | 0.654 +/- 0.009 | 0.654 +/- 0.008 | 0.664 +/- 0.007 | 0.677 |
| on | 120 | Epidemic | 0.328 +/- 0.003 | 0.328 +/- 0.006 | 0.343 +/- 0.007 | 0.401 |
| on | 20 | Epidemic | 0.734 +/- 0.007 | 0.753 +/- 0.006 | 0.749 +/- 0.005 | 0.774 |

### Findings

1. **CGR: amortisation costs decryptability, not delivery.** Delivery is identical, but 3-5 % of delivered bundles
   stay undecryptable at high load. r = 3 recovers almost everything at low load (0.773 vs 0.775 with ISLs). At high
   load it barely helps (0.653 vs 0.647): with about 24 bundles per session per hour, the first r bundles are a
   small, time-clustered sample, and when they fail the later bundles cannot recover.
2. **Epidemic: amortisation helps when buffers bind.** Smaller bundles mean fewer refusals. Decrypted delivery rises
   by 0.039-0.040 at high load without ISLs, and the median time to plaintext falls from 8,033 s to 6,468 s. With ISLs
   at high load, r = 1 is not better than per-bundle (0.328 vs 0.328) but r = 3 is (0.343).
3. **Unpredictable routing punishes amortisation most.** Under FirstContact, delivery is unchanged, but decrypted
   delivery at high load drops from 0.227 to 0.130 (r = 1) or 0.173 (r = 3) without ISLs, and from 0.336 to 0.215 or
   0.267 with ISLs. Key-carrying bundles and later bundles take unrelated random paths.
4. **The gap to PSK remains.** Even the best of these PQ variants stays below BcbPsk under epidemic routing at high
   load (0.324-0.343 vs 0.383-0.401).

## 4. Ciphertext refresh: periodic and time-based (results/20261125T141910Z)

Finding 1 suggests carrying the ciphertext *where it will be needed* rather than only first. We tested two simple
rules on top of r = 1: the ciphertext on every k-th bundle of a session (k = 4, 8; `refresh_every`), and the
ciphertext on the first bundle sent once t seconds have passed since it was last carried (t = 900, 1800;
`refresh_s`). The simulator is deterministic per seed, so the section 3 cells are the same runs.

Decrypted delivery ratio (mean over 10 seeds), with added bytes per bundle in the last row (high load / low load):

| ISL | load | routing | BcbPq | r=1 | r=3 | r=1, k=4 | r=1, k=8 | r=1, t=900 s | r=1, t=1800 s | BcbPsk |
|---|---|---|---|---|---|---|---|---|---|---|
| off | 120 | CGR | 0.678 | 0.647 | 0.653 | 0.678 | 0.677 | 0.677 | 0.674 | 0.678 |
| on | 120 | CGR | 0.780 | 0.754 | 0.760 | 0.780 | 0.780 | 0.780 | 0.780 | 0.780 |
| off | 20 | CGR | 0.677 | 0.658 | 0.674 | 0.670 | 0.659 | 0.676 | 0.673 | 0.677 |
| on | 20 | CGR | 0.775 | 0.760 | 0.773 | 0.768 | 0.761 | 0.775 | 0.771 | 0.775 |
| off | 120 | Epidemic | 0.285 | 0.325 | 0.324 | 0.349 | 0.360 | 0.358 | 0.357 | 0.383 |
| on | 120 | Epidemic | 0.328 | 0.328 | 0.343 | 0.370 | 0.373 | 0.371 | 0.367 | 0.401 |
| off | 120 | FirstContact | 0.227 | 0.130 | 0.173 | 0.216 | 0.201 | 0.209 | 0.180 | 0.223 |
| on | 120 | FirstContact | 0.336 | 0.215 | 0.267 | 0.324 | 0.307 | 0.317 | 0.284 | 0.330 |
| off | 20 | FirstContact | 0.223 | 0.151 | 0.207 | 0.178 | 0.153 | 0.205 | 0.190 | 0.223 |
| on | 20 | FirstContact | 0.318 | 0.234 | 0.300 | 0.268 | 0.238 | 0.299 | 0.282 | 0.318 |
| bytes | | | 1,184 / 1,184 | 132 / 351 | 223 / 807 | 378 / 460 | 243 / 357 | 262 / 668 | 177 / 516 | 48 / 48 |

95 % CI half-widths are 0.002-0.007 at high load and up to 0.013 at low load (summary.md).

5. **At high load, periodic refresh closes the CGR gap.** k = 8 matches per-bundle BcbPq (0.677 vs 0.678; 0.780)
   at 21 % of its bytes (243 vs 1,184), and beats r = 3 on both decryptability and bytes. Refreshing spreads
   key-carrying bundles over the epoch, so one failed early burst no longer strands the rest of the session.
6. **At low load, a count-based rule rarely fires.** Sessions hold only a few bundles per hour, so k = 8 is almost
   r = 1 (362 vs 354 key-carrying bundles) and k = 4 sits between r = 1 and r = 3.
7. **A time-based rule works at both loads under CGR.** t = 900 s is within 0.001 of per-bundle BcbPq in all four
   CGR cells, at 22 % of its bytes at high load and 56 % at low load. At low load it matches or beats r = 3
   (0.676 vs 0.674; 0.775 vs 0.773) with 17 % fewer bytes (668 vs 807). The number of refreshes depends on elapsed
   time rather than on how many bundles a session holds, which fixes the weakness in finding 6. t = 1800 s is
   cheaper (177 / 516 bytes) and stays within 0.004 of per-bundle under CGR.
8. **Under epidemic routing at high load, refresh is the best PQ variant.** k = 8 (0.360 / 0.373) and t = 900 s
   (0.358 / 0.371) are tied within the CIs, narrowing the gap to BcbPsk to 0.02-0.03 (from 0.06-0.07 for r = 1).
9. **Under FirstContact, no single rule wins.** At high load k = 4 recovers the most (0.216 of 0.227, 0.324 of
   0.336, at 32 % of per-bundle bytes), with t = 900 s close behind. At low load, t = 900 s and r = 3 are tied
   (0.205 vs 0.207, 0.299 vs 0.300), with t = 900 s using fewer bytes; k = 4 and k = 8 fall behind because they
   rarely fire.

Overall, t = 900 s is the only setting tested here that stays near the best variant in every routing regime and
load. Not yet tested: contact-aware refresh (on a new first hop), other values of t, and destination-generated key
acknowledgements.

![Decrypted delivery ratio for all nine security variants, by routing and load, with ISLs off (left) and on (right)](../results/20261125T141910Z/decrypted.png)

*Figure 1. Bundles delivered and decrypted within their lifetime, over bundles generated (simulated; mean over 10
seeds). Under CGR, r1t900 reaches the per-bundle BcbPq bar at both loads; r1k4 and r1k8 do so only at 120/h, and
r1 and r3 stay below it at 120/h.*

## 5. Security trade-off

A session key protects up to one hour of bundles between a pair: compromising it exposes that epoch, whereas
per-bundle keys bound exposure to one bundle. The receiver caches a session key only after it authenticated a
bundle, so a forged KEM ciphertext cannot poison the cache (test `forged_kem_bundle_does_not_poison_session_cache`).
There is still no sender authentication (ML-DSA via the COSE context is future work).

## 6. Limitations

Simplified orbits; no inter-shell links; static rates; CGR without volume accounting; 10 seeds; one session length
(1 h); single network-wide PSK; placeholder COSE codepoints; the PartyU/V KDF detail differs between the two drafts.

## References (verified; see docs/RESEARCH.md)

RFC 9171, RFC 9172, RFC 9173; draft-ietf-dtn-bpsec-cose-19; draft-ietf-cose-pqc-kem-00; draft-ietf-cose-hpke-27;
NIST SP 800-38D; NIST SP 800-185 KMAC samples; FIPS 203; S. Rüsch et al., *Forward Secure Delay-Tolerant
Networking*, CHANTS 2017, doi:10.1145/3124087.3124094; S. A. Menesidou et al., *Cryptographic Key Management in
Delay Tolerant Networks: A Survey*, Future Internet 2017; draft-burleigh-dtnwg-dtka.
