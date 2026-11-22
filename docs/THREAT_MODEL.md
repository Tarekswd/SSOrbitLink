# OrbitLink - Threat Model

## Setting
Bundles sit in satellite buffers for minutes to hours. There is usually no simultaneous end-to-end path, so
interactive key agreement (TLS-style handshakes) is not available.

## Adversary
- Passive: records bundles at any relay or on any link, including a future CRQC (harvest-now-decrypt-later).
- Active: modifies, injects, or replays bundles at a compromised relay.

## What each mode provides

| Mode | Confidentiality | Integrity | Sender authentication | PQ confidentiality | Key distribution needed |
|---|---|---|---|---|---|
| `None` | no | CRC only (not security) | no | no | none |
| `Bib` (RFC 9173 BIB-HMAC-SHA2, PSK) | no | yes, for PSK holders | yes, among PSK holders | n/a | shared secret at every endpoint |
| `BcbPsk` (RFC 9173 BCB-AES-GCM + AES-KW, PSK KEK) | yes | yes (GCM) | among PSK holders | yes, if the PSK is never sent over a classical channel | shared secret at every endpoint |
| `BcbPq` (**experimental**: ML-KEM-768 to destination) | yes | yes (GCM) | **no**: anyone can encapsulate | yes (ML-KEM-768 assumption) | destination public keys only |

The simulator uses one network-wide PSK. That is the weakest configuration, and it is the key-distribution
problem `BcbPq` is meant to remove. Per-pair PSKs would change only the bookkeeping, not the measured sizes.

## Tested
| Property | Test |
|---|---|
| All modes round-trip through real CBOR encoding and `validate()` | `every_mode_roundtrips_and_validates` |
| A modified payload is rejected (Bib, BcbPsk, BcbPq) | `tampered_payload_rejected` |
| A modified ML-KEM ciphertext is rejected | `tampered_kem_ciphertext_rejected` |
| Only the intended destination can decrypt in PQ mode | `wrong_recipient_cannot_decrypt_pq` |
| A missing security block is reported as malformed, not accepted | `missing_security_block_is_malformed` |
| Zero crypto failures across a full simulated run | `simulation_delivers_with_zero_crypto_failures` |

## Known limitations
1. **No sender authentication in BcbPq.** It needs a PQ signature (e.g. ML-DSA) in a BIB, or a PQ-authenticated
   key directory. Not implemented.
2. **Replay:** a replayed bundle is a valid bundle. Duplicate suppression by bundle id happens at the
   destination (`duplicates` metric), but that is not a cryptographic replay defence.
3. **Key directory distribution and revocation over intermittent links** are assumed out of band. This is the
   hardest open problem here and is not solved.
4. Security is applied only at source and destination. Relays do not verify (no hop-by-hop BIBs), so a compromised
   relay can waste resources with garbage bundles that are dropped only at the destination.
5. `bp7` and `ml-kem` are third-party crates whose audit status has not been reviewed here.
6. **Timing side channels (source review, 2026-11-22; no timing measurements done):**
   - BIB-HMAC-SHA2 verification in `bp7` uses `hmac` `verify_slice` (constant-time `ct_eq`).
   - BCB-AES-GCM tag check in `aes-gcm` 0.11 uses `ct_eq`.
   - ML-KEM-768 decapsulation uses constant-time select for implicit rejection (`ml-kem` 0.3.4).
   - **Gap:** `aes-kw` 0.2.1 (pulled in by `bp7` for key unwrap) checks the RFC 3394 integrity value with a
     plain `==` on 8 bytes (`aes-kw-0.2.1/src/lib.rs`, unwrap). That comparison is not constant-time. The
     practical impact has not been analysed. A fix belongs upstream (aes-kw / bp7), or the KEK could be used
     directly as the BCB key without wrapping. Until then, do not treat the BCB modes as side-channel hardened.
