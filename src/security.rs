//! Bundle security modes.
//!
//! STANDARD (RFC 9172 BPSec with RFC 9173 default contexts, implemented by the `bp7` crate):
//!   Bib    - BIB-HMAC-SHA2 over the payload, pre-shared HMAC key. Integrity only.
//!   BcbPsk - BCB-AES-GCM on the payload, keyed directly with a pre-shared 256-bit key and a fresh
//!            random 96-bit IV per bundle (no wrapped-key parameter). Confidentiality + integrity for
//!            key holders. Random IVs bound the use of one key: stay well below 2^32 bundles per key
//!            (NIST SP 800-38D random-IV limit) and rotate the PSK before that.
//! No mode uses the RFC 9173 wrapped-key parameter: unwrapping goes through `aes-kw` 0.2.1, whose
//! integrity check is a non-constant-time `==` (see docs/THREAT_MODEL.md), so that path is never reached.
//! EXPERIMENTAL (this project; not in any RFC):
//!   BcbPq  - as BcbPsk, but the AES-GCM key is derived per bundle as HKDF-SHA256(ML-KEM-768 shared secret)
//!            from an encapsulation to the DESTINATION's long-term ML-KEM key. The ML-KEM ciphertext
//!            travels in extension block type 200 (block types 192-255 are reserved for private /
//!            experimental use in RFC 9171). No pre-shared secret is needed between endpoints, only
//!            the destination's public key - the point for networks with no end-to-end path.
//!            It provides NO sender authentication: anyone can encapsulate to a public key.

use bp7::bpsec::rfc9173::{bcb, bib};
use bp7::bpsec::{BIB_HMAC_SHA2_ID, BcbSecurityContextParameter, BibSecurityContextParameter};
use bp7::{Bundle, CanonicalData, EndpointID, canonical::new_canonical_block, crc::CRC_NO};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit};
use ml_kem::{MlKem768, ml_kem_768};
use sha2::Sha256;

pub const PQ_KEM_BLOCK_TYPE: u64 = 200;
const PAYLOAD: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    None,
    Bib,
    BcbPsk,
    BcbPq,
}

impl Mode {
    pub const ALL: [Mode; 4] = [Mode::None, Mode::Bib, Mode::BcbPsk, Mode::BcbPq];
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SecError {
    #[error("bpsec: {0}")]
    Bpsec(String),
    #[error("integrity check failed")]
    Integrity,
    #[error("missing or malformed security block")]
    Malformed,
}

fn bp(e: impl std::fmt::Debug) -> SecError {
    SecError::Bpsec(format!("{e:?}"))
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    b
}

/// Per-node key material. Pre-shared keys are network-wide (shortcut: one PSK for all pairs, which
/// is exactly the key-distribution weakness the PQ mode is meant to remove; per-pair PSKs would only
/// change the bookkeeping, not the measured sizes or costs).
pub struct Keys {
    pub hmac_psk: [u8; 32],
    pub bcb_psk: [u8; 32],
    dk: Vec<ml_kem_768::DecapsulationKey>,
    pub ek: Vec<Vec<u8>>,
}

impl Keys {
    pub fn generate(nodes: usize) -> Self {
        let (mut dk, mut ek) = (Vec::new(), Vec::new());
        for _ in 0..nodes {
            let (d, e) = MlKem768::generate_keypair();
            ek.push(e.to_bytes().to_vec());
            dk.push(d);
        }
        Keys {
            hmac_psk: random(),
            bcb_psk: random(),
            dk,
            ek,
        }
    }
}

fn source_eid(node: usize) -> EndpointID {
    EndpointID::with_ipn(node as u64 + 1, 0).expect("valid ipn")
}

/// Per-bundle AES-256-GCM key from the ML-KEM shared secret. Every bundle has a fresh encapsulation,
/// so every bundle has a fresh key ("v1": v0 wrapped a random content key under this value).
fn pq_key(ss: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, ss)
        .expand(b"orbitlink v1 bcb key", &mut key)
        .expect("32 bytes");
    key
}

/// Apply the security mode to a freshly built bundle created at `src` for destination `dst`.
pub fn protect(
    b: &mut Bundle,
    mode: Mode,
    keys: &Keys,
    src: usize,
    dst: usize,
) -> Result<(), SecError> {
    let eid = source_eid(src);
    match mode {
        Mode::None => {}
        Mode::Bib => {
            bib::sign(
                b,
                &[PAYLOAD],
                &keys.hmac_psk,
                eid,
                BibSecurityContextParameter::default(),
            )
            .map_err(bp)?;
        }
        Mode::BcbPsk | Mode::BcbPq => {
            let key = if mode == Mode::BcbPsk {
                keys.bcb_psk
            } else {
                let ek = ml_kem_768::EncapsulationKey::new_from_slice(&keys.ek[dst])
                    .map_err(|_| SecError::Malformed)?;
                let (ct, ss) = ek.encapsulate();
                let n = b
                    .canonicals
                    .iter()
                    .map(|c| c.block_number)
                    .max()
                    .unwrap_or(1)
                    + 1;
                b.add_canonical_block(new_canonical_block(
                    PQ_KEM_BLOCK_TYPE,
                    n,
                    0,
                    CanonicalData::Unknown(ct.to_vec()),
                ));
                pq_key(&ss)
            };
            // No wrapped key: `key` is the content-encryption key itself (RFC 9173 allows either).
            let params = BcbSecurityContextParameter::default();
            bcb::encrypt(b, PAYLOAD, &key, &random::<12>(), eid, params).map_err(bp)?;
        }
    }
    Ok(())
}

/// Verify / decrypt at the destination. On success the payload is plaintext again.
pub fn accept(b: &mut Bundle, mode: Mode, keys: &Keys, dst: usize) -> Result<(), SecError> {
    let block_of = |b: &Bundle, t: u64| {
        b.canonicals
            .iter()
            .find(|c| c.block_type == t)
            .map(|c| c.block_number)
    };
    match mode {
        Mode::None => Ok(()),
        Mode::Bib => {
            let n = block_of(b, bp7::bpsec::INTEGRITY_BLOCK).ok_or(SecError::Malformed)?;
            debug_assert_eq!(
                b.decode_bibs().first().map(|x| x.security_context_id),
                Some(BIB_HMAC_SHA2_ID)
            );
            if bib::verify(b, n, &keys.hmac_psk).map_err(bp)? {
                Ok(())
            } else {
                Err(SecError::Integrity)
            }
        }
        Mode::BcbPsk | Mode::BcbPq => {
            // Refuse any BCB that carries a wrapped key: bp7 would unwrap it with aes-kw, whose
            // integrity check is not constant-time, on attacker-chosen input.
            let bcbs = b.decode_bcbs();
            let [bcb_block] = bcbs.as_slice() else {
                return Err(SecError::Malformed);
            };
            let params: Option<BcbSecurityContextParameter> =
                bcb_block.parameters().map_err(|_| SecError::Malformed)?;
            if params.is_some_and(|p| p.wrapped_key.is_some()) {
                return Err(SecError::Malformed);
            }
            let key = if mode == Mode::BcbPsk {
                keys.bcb_psk
            } else {
                let ext = b
                    .canonicals
                    .iter()
                    .find(|c| c.block_type == PQ_KEM_BLOCK_TYPE)
                    .ok_or(SecError::Malformed)?;
                let CanonicalData::Unknown(ct) = ext.data() else {
                    return Err(SecError::Malformed);
                };
                let ss = keys.dk[dst]
                    .decapsulate_slice(ct)
                    .map_err(|_| SecError::Malformed)?;
                pq_key(&ss)
            };
            let n = block_of(b, bp7::bpsec::CONFIDENTIALITY_BLOCK).ok_or(SecError::Malformed)?;
            bcb::decrypt(b, n, &key, CRC_NO).map_err(|_| SecError::Integrity)
        }
    }
}
