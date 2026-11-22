# What Does Post-Quantum Bundle Confidentiality Cost a LEO DTN? A Simulation Study with BPv7/BPSec

*Working draft. Network metrics are SIMULATED, cryptographic CPU times MEASURED, energy ESTIMATED
(`results/20261122T153249Z/`, 144 runs = 48 configurations x 3 seeds, 12 h simulated each). Sections marked
**[TODO]** are not done. No novelty is claimed: the IETF DTN WG's BPSec COSE context draft must be read first
(docs/RESEARCH.md).*

## Abstract

We simulate a 72-satellite LEO constellation serving 6 ground stations over intermittent 256 kbit/s ground links,
optionally with intra-plane ISLs. The constellation has a 53-degree shell (48 satellites, 550 km) and a near-polar
shell (24 satellites, 560 km, 97.6 degrees). All traffic is real BPv7 bundles, protected with standard BPSec
(RFC 9173 BIB-HMAC-SHA2, BCB-AES-GCM) or an experimental per-bundle ML-KEM-768 key transport. The PQ mode adds
1,145 bytes per bundle, against 48 bytes for PSK-based BCB, and about 110-150 us of CPU per bundle at each end on
our machine. With CGR-style routing this overhead changes **neither** delivery ratio nor delay in any tested
configuration (delivery 0.67-0.78). With epidemic routing under high load, where buffers are constrained, PQ
bundles lower delivery from 0.382 to 0.287 (no ISLs) and from 0.403 to 0.331 (ISLs).

## 1. Setup

See README. Bundles carry a 2 KiB payload with a 3 h lifetime, between uniformly random station pairs, at 20 or
120 bundles per station per hour. Satellite buffers are 512 KiB.

**Coverage.** A first version used only the 53-degree shell. Svalbard (78.2 N) then had 0 passes, so 1/3 of all
bundles were undeliverable by construction. The near-polar shell fixes this: in 12 h, Svalbard has 136 passes and
every station has at least 104 (`cargo run --release --example contacts`). The regression test
`every_station_has_contacts_with_polar_shell` checks that every station has contacts. The 97.6-degree inclination
is sun-synchronous at 560 km (97.63 degrees from the J2 precession condition). No inter-shell links are modelled:
bundles change shells only through ground stations.

## 2. Results

### Per-bundle cost (measured; means over the 3-seed runs)

| Mode | Added bytes per bundle | Protect CPU (us) | Accept CPU (us) |
|---|---|---|---|
| None | 0 | ~2 | 0 |
| Bib (BIB-HMAC-SHA2) | 72 | ~10-22 | ~8-13 |
| BcbPsk (BCB-AES-GCM, PSK used directly) | 48 | ~6-22 | ~5-12 |
| BcbPq (experimental, ML-KEM-768, derived key used directly) | 1,145 | ~110-150 | ~130-146 |

Wall-clock times on a laptop under WSL2: orders of magnitude only, and **not** side-channel evidence (see
docs/RESEARCH.md, PHOENIX-PQ note). An earlier version wrapped a random content key with AES-KW (+44 bytes). That
path was removed because the aes-kw unwrap check is not constant-time (docs/THREAT_MODEL.md).

### Delivery (simulated, mean of 3 seeds; full table with CIs in summary.md)

| ISL | load/GS/h | CGR (all modes) | Epidemic None / Psk / Pq | FirstContact None / Pq |
|---|---|---|---|---|
| off | 20 | 0.672 | 0.672 / 0.672 / 0.650 | 0.223 / 0.223 |
| off | 120 | 0.678 | 0.388 / 0.382 / **0.287** | 0.222 / 0.226 |
| on | 20 | 0.772 | 0.772 / 0.771 / 0.727 | 0.314 / 0.314 |
| on | 120 | 0.778 | 0.408 / 0.403 / **0.331** | 0.327 / 0.332 |

- **CGR is insensitive to the security mode.** Delivery and median delay are identical across modes in every
  configuration: about 4,030 s without ISLs and 508-546 s with ISLs. CGR is bounded by contact opportunities within
  the 3 h lifetime, not by capacity: no buffer refusals and mean satellite buffer use of at most 0.032.
- **Epidemic routing is buffer-bound at high load** (mean satellite buffer use 0.49-0.88). There, PQ bundles cut
  delivery by 18-25 % relative to PSK (0.331/0.403 and 0.287/0.382). Even at low load with ISLs, PQ raises the
  median delay from 711 s to 1,836 s.
- **FirstContact with always-on ISLs shows a baseline pathology.** Bundles circulate around the intra-plane ring
  until they expire, so transmitted bytes per delivered payload byte reach about 43,000-76,000. This reflects the
  naive baseline, not the security modes.

## 3. Discussion

For contact-plan-aware routing, per-bundle PQ key transport looks affordable in bandwidth at these loads. Where
copies multiply, as in flooding, the 1.1 KB overhead multiplies too. That argues for amortising KEM ciphertexts in
flooding-based or buffer-constrained designs, for example with per-session keys cached at the destination.
**[TODO]** Implement and measure amortisation.

## 4. Limitations

Simplified orbits (no SGP4/J2 propagation of the orbits themselves); no inter-shell links; static rates; no link
outages beyond geometry; CGR without volume accounting; 3 seeds; no node failures; no sender authentication in
BcbPq; single network-wide PSK.

## 5. Future work

Inter-shell ISLs; node failures and disappearance; ML-DSA BIB for sender authentication; amortised KEM keys;
comparison with ION CGR on the same contact plan; comparison with the BPSec COSE context
(draft-ietf-dtn-bpsec-cose).

## References (verified; see docs/RESEARCH.md)

RFC 9171 (BPv7), RFC 9172 (BPSec), RFC 9173 (default security contexts), NIST SP 800-38D (GCM),
FIPS 203 (ML-KEM), draft-ietf-dtn-bpsec-cose-19.
