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
| `BcbPsk` (RFC 9173 BCB-AES-GCM, PSK used directly as the key) | yes | yes (GCM) | among PSK holders | yes, if the PSK is never sent over a classical channel | shared secret at every endpoint |
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
   - **Fixed gap (2026-11-22):** `aes-kw` 0.2.1, pulled in by `bp7` for RFC 9173 key unwrap, checks the
     RFC 3394 integrity value with a plain `==` (`aes-kw-0.2.1/src/lib.rs`, unwrap), which is not constant-time.
     OrbitLink no longer uses wrapped keys. BcbPq keys AES-GCM directly with HKDF(ML-KEM shared secret), and
     BcbPsk keys it directly with the PSK. `accept()` **refuses** any BCB that carries a wrapped-key parameter
     before bp7 can unwrap it, so attacker-supplied bundles cannot reach that comparison either. Tests:
     `no_mode_uses_aes_key_wrap`, `wrapped_key_bcb_is_refused_before_unwrap`. A mutation check (guard removed)
     confirms the second test fails without the guard.
   - New cost of the fix: BcbPsk uses one key with random 96-bit IVs for every bundle. Stay well below 2^32
     bundles per PSK (NIST SP 800-38D random-IV limit) and rotate. BcbPq is unaffected: one fresh key per bundle.
   - **Not done:** ctgrind (Valgrind with secrets marked undefined) or dudect timing tests of the Rust binaries.
     The sibling project PHOENIX-PQ found that dudect could not detect even its positive control under WSL2,
     because CPU boost could not be disabled. Timing tests must run on quiet bare-metal Linux to mean anything.
