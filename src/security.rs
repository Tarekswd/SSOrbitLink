//! Bundle security modes.
//!
//! STANDARD (RFC 9172 BPSec with RFC 9173 default contexts, implemented by the `bp7` crate):
//!   Bib    - BIB-HMAC-SHA2 over the payload, pre-shared HMAC key. Integrity only.
//!   BcbPsk - BCB-AES-GCM on the payload; a fresh content key per bundle is AES-key-wrapped under a
//!            pre-shared key-encryption key (KEK). Confidentiality + integrity for key holders.
//! EXPERIMENTAL (this project; not in any RFC):
//!   BcbPq  - as BcbPsk, but the KEK is derived per bundle as HKDF-SHA256(ML-KEM-768 shared secret)
//!            from an encapsulation to the DESTINATION's long-term ML-KEM key. The ML-KEM ciphertext
//!            travels in extension block type 200 (block types 192-255 are reserved for private /
//!            experimental use in RFC 9171). No pre-shared secret is needed between endpoints, only
//!            the destination's public key - the point for networks with no end-to-end path.
//!            It provides NO sender authentication: anyone can encapsulate to a public key.

use bp7::bpsec::rfc9173::{bcb, bib};
use bp7::bpsec::{
    BIB_HMAC_SHA2_ID, BcbSecurityContextParameter, BibSecurityContextParameter, wrap_key,
};
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
    pub kek_psk: [u8; 32],
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
            kek_psk: random(),
            dk,
            ek,
        }
    }
}

fn source_eid(node: usize) -> EndpointID {
    EndpointID::with_ipn(node as u64 + 1, 0).expect("valid ipn")
}

fn pq_kek(ss: &[u8]) -> [u8; 32] {
    let mut kek = [0u8; 32];
    Hkdf::<Sha256>::new(None, ss)
        .expand(b"orbitlink v0 bcb kek", &mut kek)
        .expect("32 bytes");
    kek
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
            let kek = if mode == Mode::BcbPsk {
                keys.kek_psk
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
                pq_kek(&ss)
            };
            let cek: [u8; 32] = random();
            let params = BcbSecurityContextParameter {
                wrapped_key: Some(wrap_key(&kek, &cek).map_err(bp)?),
                ..Default::default()
            };
            bcb::encrypt(b, PAYLOAD, &kek, &random::<12>(), eid, params).map_err(bp)?;
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
            let kek = if mode == Mode::BcbPsk {
                keys.kek_psk
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
                pq_kek(&ss)
            };
            let n = block_of(b, bp7::bpsec::CONFIDENTIALITY_BLOCK).ok_or(SecError::Malformed)?;
            bcb::decrypt(b, n, &kek, CRC_NO).map_err(|_| SecError::Integrity)
        }
    }
}
