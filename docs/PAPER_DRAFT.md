# What Does Post-Quantum Bundle Confidentiality Cost a LEO DTN? A Simulation Study with BPv7/BPSec

*Working draft. Network metrics are SIMULATED, cryptographic CPU times MEASURED, energy ESTIMATED
(`results/20261122T103220Z/`, 144 runs = 48 configurations x 3 seeds, 12 h simulated each). Sections marked
**[TODO]** are not done. No novelty is claimed until the literature check in docs/RESEARCH.md is complete.*

## Abstract
We simulate a 48-satellite LEO constellation (6 planes, 550 km, 53 degrees) serving 6 ground stations over
intermittent 256 kbit/s ground links, optionally with intra-plane ISLs. All traffic is real BPv7 bundles
protected with standard BPSec (RFC 9173 BIB-HMAC-SHA2, BCB-AES-GCM) or an experimental per-bundle ML-KEM-768 key
transport. The PQ mode adds 1,189 bytes per bundle, against 92 bytes for PSK-based BCB, and about 120-240 us of
CPU per bundle at each end on our machine. With CGR-style routing, this overhead changes **neither** delivery
ratio nor delay in any tested configuration. With epidemic routing under high load, where buffers are
constrained, PQ bundles lower delivery from 0.198 to 0.140 (no ISLs) and from 0.202 to 0.158 (ISLs).
The bigger bundles fill buffers and cause more refused transfers.

## 1. Setup
See README. Bundles: 2 KiB payload, 3 h lifetime, uniform random station pairs, 20 or 120 bundles per station
per hour. Satellite buffers 512 KiB.

**Coverage caveat (found after the run):** Svalbard (78.2 N) has **0 passes** with a 53-degree shell
(`cargo run --example contacts`). With uniform pairs, 1/3 of bundles have Svalbard as source or destination.
The best achievable delivery ratio is therefore 2/3 for every strategy. We report raw ratios; ratio / (2/3) gives
delivery among deliverable bundles. **[TODO]** Re-run with a polar shell, or exclude Svalbard.

## 2. Results

### Per-bundle cost (measured)
| Mode | Added bytes per bundle | Protect CPU (us, mean) | Accept CPU (us, mean) |
|---|---|---|---|
| None | 0 | ~2-3 | 0 |
| Bib (BIB-HMAC-SHA2) | 72 | ~9-30 | ~8-16 |
| BcbPsk (BCB-AES-GCM + AES-KW) | 92 | ~9-35 | ~5-12 |
| BcbPq (experimental, ML-KEM-768) | 1,189 | ~117-239 | ~128-215 |

CPU means vary noticeably between runs (wide CIs in the ISL rows). They are wall-clock times on a laptop under WSL2.

### Delivery (simulated, mean of 3 seeds; full table with CIs in summary.md)
| ISL | load/GS/h | CGR (all modes) | Epidemic None / Psk / Pq | FirstContact None / Pq |
|---|---|---|---|---|
| off | 20 | 0.312 | 0.312 / 0.312 / 0.312 | 0.145 / 0.145 |
| off | 120 | 0.320 | 0.204 / 0.198 / **0.140** | 0.148 / 0.153 |
| on | 20 | 0.397 | 0.397 / 0.397 / 0.390 | 0.219 / 0.219 |
| on | 120 | 0.401 | 0.207 / 0.202 / **0.158** | 0.232 / 0.240 |

- CGR is insensitive to the security mode. Its delivery is bounded by coverage and lifetime, not by capacity:
  roughly 3,500-4,000 expired copies at high load and no buffer refusals.
- Epidemic routing is buffer-bound at high load (mean satellite buffer use 0.47-0.86). There, PQ bundles cut
  delivery by 22-29 % relative to PSK (0.158/0.202 and 0.140/0.198).
- FirstContact with always-on ISLs shows a **baseline pathology**. Bundles circulate around the intra-plane ring
  until they expire, so transmitted bytes per delivered payload byte reach 55,000-98,000 and the energy estimate
  grows accordingly. This reflects the naive baseline, not the security modes.

## 3. Discussion
For contact-plan-aware routing, per-bundle PQ key transport looks affordable in bandwidth at these loads. Where
copies multiply (flooding), the about 1.1 KB overhead multiplies too. That argues for amortising KEM ciphertexts
(per-session keys cached at the destination) in flooding-based or buffer-constrained designs. **[TODO]** Implement
and measure amortisation.

## 4. Limitations
Simplified orbits (no SGP4, no J2); static rates; no link outages beyond geometry; CGR without volume accounting;
3 seeds; no node failures; no sender authentication in BcbPq; single network-wide PSK; coverage caveat above.

## 5. Future work
Polar shell; node failures and disappearance; ML-DSA BIB for sender authentication; amortised KEM keys;
comparison with ION CGR on the same contact plan; RFC 9171 bundle-age handling for nodes without clocks.
