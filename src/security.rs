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
//! POST-QUANTUM (standards-track encoding, see src/cose.rs):
//!   BcbPq        - BPSec COSE context (draft-ietf-dtn-bpsec-cose-19) COSE_Encrypt with one ML-KEM-768
//!                  recipient (draft-ietf-cose-pqc-kem-00, Direct Key Agreement): a fresh encapsulation to
//!                  the DESTINATION's long-term key for every bundle. No sender authentication.
//!   BcbPqSession - EXPERIMENTAL (research question of this project): one encapsulation per
//!                  (source, destination, epoch); the KEM ciphertext is carried only by the first
//!                  `redundancy` bundles of the epoch, later bundles use a COSE "direct" (-6) recipient
//!                  naming the session key by kid. Bundles that arrive before any key-carrying bundle are
//!                  undecryptable until one arrives (see sim.rs). Session-key compromise exposes one epoch.

use crate::cose::{self, Recipient};
use bp7::bpsec::rfc9173::{bcb, bib};
use bp7::bpsec::{BIB_HMAC_SHA2_ID, BcbSecurityContextParameter, BibSecurityContextParameter};
use bp7::{Bundle, EndpointID, crc::CRC_NO};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit};
use ml_kem::{MlKem768, ml_kem_768};
use std::collections::HashMap;

const PAYLOAD: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    None,
    Bib,
    BcbPsk,
    BcbPq,
    BcbPqSession,
}

impl Mode {
    pub const ALL: [Mode; 5] = [
        Mode::None,
        Mode::Bib,
        Mode::BcbPsk,
        Mode::BcbPq,
        Mode::BcbPqSession,
    ];
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

fn kid_for(dst: usize) -> Vec<u8> {
    format!("ipn:{}.0/mlkem768", dst + 1).into_bytes()
}

fn encapsulate(keys: &Keys, dst: usize) -> Result<(Vec<u8>, Vec<u8>), SecError> {
    let ek = ml_kem_768::EncapsulationKey::new_from_slice(&keys.ek[dst])
        .map_err(|_| SecError::Malformed)?;
    let (ct, ss) = ek.encapsulate();
    Ok((ct.to_vec(), ss.to_vec()))
}

fn cose_err(e: cose::CoseError) -> SecError {
    match e {
        cose::CoseError::Auth => SecError::Integrity,
        cose::CoseError::Malformed(_) => SecError::Malformed,
    }
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
        Mode::BcbPsk => {
            // No wrapped key: the PSK is the content-encryption key itself (RFC 9173 allows either).
            let params = BcbSecurityContextParameter::default();
            bcb::encrypt(b, PAYLOAD, &keys.bcb_psk, &random::<12>(), eid, params).map_err(bp)?;
        }
        Mode::BcbPq => {
            let (kem_ct, ss) = encapsulate(keys, dst)?;
            let cek = cose::derive_cek(
                &ss,
                &cose::protected_alg(cose::ALG_MLKEM768_PLACEHOLDER),
                &eid,
            );
            let kid = kid_for(dst);
            cose::seal_payload(
                b,
                &eid,
                &cek,
                &random::<12>(),
                Recipient::MlKem {
                    kem_ct: &kem_ct,
                    kid: &kid,
                },
            )
            .map_err(cose_err)?;
        }
        Mode::BcbPqSession => return Err(SecError::Bpsec("use SenderSessions::protect".into())),
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
        Mode::BcbPsk => {
            // Refuse any BCB that carries a wrapped key: bp7 would unwrap it with aes-kw, whose
            // integrity check is not constant-time, on attacker-chosen input.
            let bcbs = b.decode_bcbs();
            let [bcb_block] = bcbs.as_slice() else {
                return Err(SecError::Malformed);
            };
            if bcb_block.security_context_id != bp7::bpsec::BCB_AES_GCM_ID {
                return Err(SecError::Malformed);
            }
            let params: Option<BcbSecurityContextParameter> =
                bcb_block.parameters().map_err(|_| SecError::Malformed)?;
            if params.is_some_and(|p| p.wrapped_key.is_some()) {
                return Err(SecError::Malformed);
            }
            let n = block_of(b, bp7::bpsec::CONFIDENTIALITY_BLOCK).ok_or(SecError::Malformed)?;
            bcb::decrypt(b, n, &keys.bcb_psk, CRC_NO).map_err(|_| SecError::Integrity)
        }
        Mode::BcbPq => {
            let o = cose::open(b).map_err(cose_err)?;
            let ct = o.kem_ct.as_ref().ok_or(SecError::Malformed)?;
            let ss = keys.dk[dst]
                .decapsulate_slice(ct)
                .map_err(|_| SecError::Malformed)?;
            let cek = cose::derive_cek(&ss, &o.recipient_protected, &o.source);
            cose::unseal_payload(b, &o, &cek).map_err(cose_err)
        }
        Mode::BcbPqSession => Err(SecError::Bpsec("use ReceiverSessions::accept".into())),
    }
}

/// Sender-side state for `Mode::BcbPqSession`.
pub struct SenderSessions {
    pub epoch_s: f64,
    pub redundancy: u32,
    /// Also carry the ciphertext on every `refresh_every`-th bundle of a session (0 = never).
    pub refresh_every: u32,
    /// Also carry the ciphertext once `refresh_s` seconds have passed since it was last carried (0 = never).
    pub refresh_s: f64,
    sessions: HashMap<(usize, usize, u64), Session>,
}

struct Session {
    kid: Vec<u8>,
    kem_ct: Vec<u8>,
    cek: [u8; 32],
    carried: u32,
    sent: u32,
    last_ct_t: f64,
}

impl SenderSessions {
    pub fn new(epoch_s: f64, redundancy: u32, refresh_every: u32) -> Self {
        assert!(
            epoch_s > 0.0 && redundancy >= 1,
            "epoch > 0, redundancy >= 1"
        );
        SenderSessions {
            epoch_s,
            redundancy,
            refresh_every,
            refresh_s: 0.0,
            sessions: HashMap::new(),
        }
    }

    /// Protect a bundle created at time `t`. Returns true if it carries the KEM ciphertext.
    pub fn protect(
        &mut self,
        b: &mut Bundle,
        keys: &Keys,
        src: usize,
        dst: usize,
        t: f64,
    ) -> Result<bool, SecError> {
        let eid = source_eid(src);
        let epoch = (t / self.epoch_s) as u64;
        let s = match self.sessions.entry((src, dst, epoch)) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                let (kem_ct, ss) = encapsulate(keys, dst)?;
                let cek = cose::derive_cek(
                    &ss,
                    &cose::protected_alg(cose::ALG_MLKEM768_PLACEHOLDER),
                    &eid,
                );
                let mut kid = random::<12>().to_vec(); // per-session identifier, not secret
                kid.extend((dst as u32).to_be_bytes());
                v.insert(Session {
                    kid,
                    kem_ct,
                    cek,
                    carried: 0,
                    sent: 0,
                    last_ct_t: t,
                })
            }
        };
        let with_ct = s.carried < self.redundancy
            || (self.refresh_every > 0 && s.sent % self.refresh_every == 0)
            || (self.refresh_s > 0.0 && t - s.last_ct_t >= self.refresh_s);
        s.sent += 1;
        let r = if with_ct {
            s.carried += 1;
            s.last_ct_t = t;
            Recipient::MlKem {
                kem_ct: &s.kem_ct,
                kid: &s.kid,
            }
        } else {
            Recipient::Direct { kid: &s.kid }
        };
        cose::seal_payload(b, &eid, &s.cek, &random::<12>(), r).map_err(cose_err)?;
        Ok(with_ct)
    }
}

/// Destination-side key cache for `Mode::BcbPqSession`.
#[derive(Default)]
pub struct ReceiverSessions {
    keys: HashMap<(usize, Vec<u8>), [u8; 32]>,
}

#[derive(Debug, PartialEq)]
pub enum SessionAccept {
    /// Decrypted. `learned` = this bundle carried the KEM ciphertext and taught a new session key.
    Ok { learned: Option<Vec<u8>> },
    /// Valid structure, but the session key named by `kid` is not known yet.
    KeyUnavailable { kid: Vec<u8> },
}

impl ReceiverSessions {
    pub fn accept(
        &mut self,
        b: &mut Bundle,
        keys: &Keys,
        dst: usize,
    ) -> Result<SessionAccept, SecError> {
        let o = cose::open(b).map_err(cose_err)?;
        let slot = (dst, o.kid.clone());
        let (cek, learned) = match (&o.kem_ct, self.keys.get(&slot)) {
            (Some(ct), known) => {
                let ss = keys.dk[dst]
                    .decapsulate_slice(ct)
                    .map_err(|_| SecError::Malformed)?;
                let cek = cose::derive_cek(
                    &ss,
                    &cose::protected_alg(cose::ALG_MLKEM768_PLACEHOLDER),
                    &o.source,
                );
                (
                    cek,
                    if known.is_none() {
                        Some(o.kid.clone())
                    } else {
                        None
                    },
                )
            }
            (None, Some(k)) => (*k, None),
            (None, None) => return Ok(SessionAccept::KeyUnavailable { kid: o.kid }),
        };
        cose::unseal_payload(b, &o, &cek).map_err(cose_err)?;
        // Only cache a key after it authenticated a bundle: a forged KEM ciphertext cannot poison the cache.
        if let Some(k) = &learned {
            self.keys.insert((dst, k.clone()), cek);
        }
        Ok(SessionAccept::Ok { learned })
    }
}
