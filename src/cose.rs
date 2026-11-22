//! BPSec COSE context BCB (draft-ietf-dtn-bpsec-cose-19) carrying a COSE_Encrypt whose single recipient
//! uses ML-KEM-768 in Direct Key Agreement mode (draft-ietf-cose-pqc-kem-00).
//!
//! Implemented from the draft texts (both downloaded and read 2026-11-22):
//! - security context id 3; confidentiality result id 96 = untagged encoded COSE_Encrypt with detached
//!   (null) payload; target BTSD replaced by the ciphertext (bpsec-cose s.2.3, Table 5).
//! - external_aad = CBOR sequence [security source, AAD-scope, AAD blocks..., additional-protected]
//!   with the default AAD-scope {0:1, -1:1, -2:1} (bpsec-cose s.2.2, s.2.5.1).
//! - CEK = KMAC256(K = ML-KEM shared secret, X = COSE_KDF_Context without PartyU/PartyV, L = 256,
//!   S = "") (pqc-kem s.5.1); SuppPubInfo "other" = CBOR sequence ["BPSec", source, additional-protected]
//!   (bpsec-cose s.2.5.2). NOTE: bpsec-cose says PartyU/V items are "the null value" while pqc-kem says
//!   they are excluded; we follow pqc-kem (it defines the algorithm). Interop of this detail is unresolved.
//!
//! PLACEHOLDER CODEPOINTS (not interoperable until IANA assigns them):
//! - ML-KEM-768 COSE algorithm: "TBD2" in pqc-kem-00 -> ALG_MLKEM768_PLACEHOLDER.
//! - "ek" header parameter: "TBD11 (Assumed: -4)" in draft-ietf-cose-hpke-27 -> -4.
//!
//! The decoder refuses everything except exactly this structure (in particular any key-wrap recipient),
//! so attacker-supplied messages cannot reach a key-unwrap path.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use bp7::bpsec::{AbstractSecurityBlock, CONFIDENTIALITY_BLOCK, new_confidentiality_block};
use bp7::flags::BlockControlFlags;
use bp7::{Bundle, CanonicalData, EndpointID};
use serde_cbor::Value;
use std::collections::BTreeMap;
use tiny_keccak::{Hasher, Kmac};

pub const COSE_CONTEXT_ID: i16 = 3;
pub const RESULT_COSE_ENCRYPT: u64 = 96;
pub const ALG_A256GCM: i128 = 3;
/// Placeholder for pqc-kem-00 "TBD2" (ML-KEM-768, direct). Arbitrary value outside the assigned range.
pub const ALG_MLKEM768_PLACEHOLDER: i128 = -65793;
pub const HDR_ALG: i128 = 1;
pub const HDR_KID: i128 = 4;
pub const HDR_IV: i128 = 5;
pub const HDR_EK: i128 = -4;
const PAYLOAD_BLOCK: u64 = 1;
const MLKEM768_CT_LEN: usize = 1088;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CoseError {
    #[error("malformed or unsupported COSE/BPSec structure: {0}")]
    Malformed(&'static str),
    #[error("authentication failed")]
    Auth,
}

// ------------------------------------------------------------------ CBOR helpers

/// Deterministic encoding of a CBOR integer (RFC 8949 s.4.2.1: shortest form).
pub fn cbor_int(v: i128) -> Vec<u8> {
    let (major, n) = if v >= 0 {
        (0u8, v as u64)
    } else {
        (1u8, (-1 - v) as u64)
    };
    head(major, n)
}

fn head(major: u8, n: u64) -> Vec<u8> {
    let m = major << 5;
    match n {
        0..=23 => vec![m | n as u8],
        24..=0xff => vec![m | 24, n as u8],
        0x100..=0xffff => [vec![m | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![m | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![m | 27], n.to_be_bytes().to_vec()].concat(),
    }
}

pub fn cbor_bstr(b: &[u8]) -> Vec<u8> {
    [head(2, b.len() as u64), b.to_vec()].concat()
}

fn cbor_tstr(s: &str) -> Vec<u8> {
    [head(3, s.len() as u64), s.as_bytes().to_vec()].concat()
}

/// {1: alg} as an encoded protected header (single entry, so deterministic).
pub fn protected_alg(alg: i128) -> Vec<u8> {
    [vec![0xa1], cbor_int(HDR_ALG), cbor_int(alg)].concat()
}

pub fn eid_cbor(eid: &EndpointID) -> Vec<u8> {
    serde_cbor::to_vec(eid).expect("EID encodes")
}

// ------------------------------------------------------------------ AAD (bpsec-cose s.2.5.1)

pub const AAD_METADATA: u8 = 0b01;
pub const AAD_BTSD: u8 = 0b10;
pub const DEFAULT_SCOPE: [(i64, u8); 3] =
    [(0, AAD_METADATA), (-1, AAD_METADATA), (-2, AAD_METADATA)];

/// Security block identity needed for AAD key -2 (the block may not exist yet when encrypting).
#[derive(Clone, Copy)]
pub struct SecBlockMeta {
    pub number: u64,
    pub flags: u64,
}

/// Build the external_aad CBOR sequence for `scope` (entries in any order).
pub fn external_aad(
    b: &Bundle,
    source: &EndpointID,
    target: u64,
    sec: Option<SecBlockMeta>,
    scope: &[(i64, u8)],
) -> Result<Vec<u8>, CoseError> {
    // deterministic map: non-negative keys ascending, then negative keys "descending" (-1, -2, ...)
    let mut keys: Vec<(i64, u8)> = scope.to_vec();
    keys.sort_by_key(|(k, _)| if *k >= 0 { (0, *k) } else { (1, -*k) });
    let mut out = eid_cbor(source);
    out.extend(head(5, keys.len() as u64));
    for (k, v) in &keys {
        out.extend(cbor_int(*k as i128));
        out.extend(cbor_int(*v as i128));
    }
    for (k, v) in &keys {
        if v & AAD_METADATA != 0 {
            match *k {
                0 => out.extend(
                    serde_cbor::to_vec(&b.primary).map_err(|_| CoseError::Malformed("primary"))?,
                ),
                -2 => {
                    let s = sec.ok_or(CoseError::Malformed("no security block for AAD"))?;
                    out.extend(cbor_int(CONFIDENTIALITY_BLOCK as i128));
                    out.extend(cbor_int(s.number as i128));
                    out.extend(cbor_int(s.flags as i128));
                }
                n => {
                    let num = if n == -1 {
                        target
                    } else if n > 0 {
                        n as u64
                    } else {
                        return Err(CoseError::Malformed("unsupported AAD special key"));
                    };
                    let blk = b
                        .canonicals
                        .iter()
                        .find(|c| c.block_number == num)
                        .ok_or(CoseError::Malformed("AAD block missing"))?;
                    out.extend(cbor_int(blk.block_type as i128));
                    out.extend(cbor_int(blk.block_number as i128));
                    out.extend(cbor_int(blk.block_control_flags as i128));
                }
            }
        }
        if v & AAD_BTSD != 0 && *k > 0 {
            let blk = b
                .canonicals
                .iter()
                .find(|c| c.block_number == *k as u64)
                .ok_or(CoseError::Malformed("AAD block missing"))?;
            let (CanonicalData::Data(d) | CanonicalData::Unknown(d)) = blk.data() else {
                return Err(CoseError::Malformed("AAD btsd"));
            };
            out.extend(cbor_bstr(d));
        }
    }
    out.extend(cbor_bstr(b"")); // additional-protected default
    Ok(out)
}

/// Encoded Enc_structure = [context, protected, external_aad] (RFC 9052).
pub fn enc_structure(context: &str, protected: &[u8], external_aad: &[u8]) -> Vec<u8> {
    [
        vec![0x83],
        cbor_tstr(context),
        cbor_bstr(protected),
        cbor_bstr(external_aad),
    ]
    .concat()
}

// ------------------------------------------------------------------ KDF (pqc-kem s.5.1)

pub fn kmac256(key: &[u8], data: &[u8], out_len: usize, custom: &[u8]) -> Vec<u8> {
    let mut k = Kmac::v256(key, custom);
    k.update(data);
    let mut out = vec![0u8; out_len];
    k.finalize(&mut out);
    out
}

/// COSE_KDF_Context without PartyUInfo/PartyVInfo: [AlgorithmID, [keyDataLength, protected, other]].
pub fn kdf_context(
    alg_id: i128,
    key_bits: u64,
    recipient_protected: &[u8],
    source: &EndpointID,
) -> Vec<u8> {
    let other = [cbor_tstr("BPSec"), eid_cbor(source), cbor_bstr(b"")].concat();
    [
        vec![0x82],
        cbor_int(alg_id),
        vec![0x83],
        cbor_int(key_bits as i128),
        cbor_bstr(recipient_protected),
        cbor_bstr(&other),
    ]
    .concat()
}

pub fn derive_cek(ss: &[u8], recipient_protected: &[u8], source: &EndpointID) -> [u8; 32] {
    let k = kmac256(
        ss,
        &kdf_context(ALG_A256GCM, 256, recipient_protected, source),
        32,
        b"",
    );
    k.try_into().expect("32 bytes")
}

pub fn aes256gcm_encrypt(key: &[u8; 32], iv: &[u8; 12], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(key.into())
        .encrypt(Nonce::from_slice(iv), Payload { msg: pt, aad })
        .expect("AES-GCM encrypt")
}

pub fn aes256gcm_decrypt(
    key: &[u8; 32],
    iv: &[u8],
    ct: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CoseError> {
    if iv.len() != 12 {
        return Err(CoseError::Malformed("iv length"));
    }
    Aes256Gcm::new(key.into())
        .decrypt(Nonce::from_slice(iv), Payload { msg: ct, aad })
        .map_err(|_| CoseError::Auth)
}

// ------------------------------------------------------------------ BCB construction

fn bcb_meta(number: u64) -> SecBlockMeta {
    let flags =
        new_confidentiality_block(number, BlockControlFlags::empty(), vec![]).block_control_flags;
    SecBlockMeta {
        number,
        flags: flags.into(),
    }
}

fn payload_mut(b: &mut Bundle) -> Result<&mut bp7::canonical::CanonicalBlock, CoseError> {
    b.canonicals
        .iter_mut()
        .find(|c| c.block_number == PAYLOAD_BLOCK)
        .ok_or(CoseError::Malformed("no payload block"))
}

/// What travels in the recipient layer.
pub enum Recipient<'a> {
    /// Full ML-KEM recipient: KEM ciphertext in "ek".
    MlKem { kem_ct: &'a [u8], kid: &'a [u8] },
    /// COSE "direct" (-6) recipient: the CEK is a previously shared key identified by kid.
    Direct { kid: &'a [u8] },
}

/// Encrypt the payload with `cek` and attach a BPSec COSE-context BCB with the given recipient.
pub fn seal_payload(
    b: &mut Bundle,
    source: &EndpointID,
    cek: &[u8; 32],
    iv: &[u8; 12],
    r: Recipient,
) -> Result<u64, CoseError> {
    b.calculate_crc(); // the primary block (with its CRC) is part of the AAD; fix it before computing it
    let num = b
        .canonicals
        .iter()
        .map(|c| c.block_number)
        .max()
        .unwrap_or(1)
        + 1;
    let meta = bcb_meta(num);
    let aad = external_aad(b, source, PAYLOAD_BLOCK, Some(meta), &DEFAULT_SCOPE)?;
    let prot = protected_alg(ALG_A256GCM);
    let pb = payload_mut(b)?;
    let CanonicalData::Data(pt) = pb.data().clone() else {
        return Err(CoseError::Malformed("payload"));
    };
    let ct = aes256gcm_encrypt(cek, iv, &pt, &enc_structure("Encrypt", &prot, &aad));
    pb.set_data(CanonicalData::Data(ct));

    let (rprot, mut runprot) = match r {
        Recipient::MlKem { kem_ct, kid } => (
            protected_alg(ALG_MLKEM768_PLACEHOLDER),
            BTreeMap::from([
                (Value::Integer(HDR_EK), Value::Bytes(kem_ct.to_vec())),
                (Value::Integer(HDR_KID), Value::Bytes(kid.to_vec())),
            ]),
        ),
        Recipient::Direct { kid } => (
            protected_alg(-6),
            BTreeMap::from([(Value::Integer(HDR_KID), Value::Bytes(kid.to_vec()))]),
        ),
    };
    let recipient = Value::Array(vec![
        Value::Bytes(rprot),
        Value::Map(std::mem::take(&mut runprot)),
        Value::Bytes(vec![]),
    ]);
    let cose = Value::Array(vec![
        Value::Bytes(prot),
        Value::Map(BTreeMap::from([(
            Value::Integer(HDR_IV),
            Value::Bytes(iv.to_vec()),
        )])),
        Value::Null,
        Value::Array(vec![recipient]),
    ]);
    let asb = AbstractSecurityBlock {
        security_targets: vec![PAYLOAD_BLOCK],
        security_context_id: COSE_CONTEXT_ID,
        security_source: source.clone(),
        security_context_parameters: None,
        security_results: vec![vec![(
            RESULT_COSE_ENCRYPT,
            Value::Bytes(serde_cbor::to_vec(&cose).expect("cose")),
        )]],
    };
    b.canonicals.push(new_confidentiality_block(
        num,
        BlockControlFlags::empty(),
        asb.to_cbor(),
    ));
    b.sort_canonicals();
    Ok(num)
}

/// Parsed, validated recipient information of a COSE-context BCB.
pub struct Opened {
    pub bcb_number: u64,
    pub source: EndpointID,
    pub iv: Vec<u8>,
    pub recipient_protected: Vec<u8>,
    pub kem_ct: Option<Vec<u8>>,
    pub kid: Vec<u8>,
}

fn int_key(m: &BTreeMap<Value, Value>, k: i128) -> Option<&Value> {
    m.get(&Value::Integer(k))
}

/// Parse and strictly validate the single COSE-context BCB targeting the payload.
pub fn open(b: &Bundle) -> Result<Opened, CoseError> {
    let bcbs: Vec<_> = b
        .canonicals
        .iter()
        .filter(|c| c.block_type == CONFIDENTIALITY_BLOCK)
        .collect();
    let [blk] = bcbs.as_slice() else {
        return Err(CoseError::Malformed("expected exactly one BCB"));
    };
    let (CanonicalData::Unknown(data) | CanonicalData::Data(data)) = blk.data() else {
        return Err(CoseError::Malformed("BCB data"));
    };
    let asb = AbstractSecurityBlock::from_cbor(data).map_err(|_| CoseError::Malformed("ASB"))?;
    if asb.security_context_id != COSE_CONTEXT_ID || asb.security_targets != [PAYLOAD_BLOCK] {
        return Err(CoseError::Malformed("context/target"));
    }
    if asb.security_context_parameters.is_some() {
        return Err(CoseError::Malformed(
            "only the default AAD scope is supported",
        ));
    }
    let [(RESULT_COSE_ENCRYPT, Value::Bytes(enc))] = asb
        .security_results
        .first()
        .map(Vec::as_slice)
        .unwrap_or(&[])
    else {
        return Err(CoseError::Malformed("result"));
    };
    let Value::Array(msg) =
        serde_cbor::from_slice(enc).map_err(|_| CoseError::Malformed("COSE_Encrypt"))?
    else {
        return Err(CoseError::Malformed("COSE_Encrypt"));
    };
    let [
        Value::Bytes(prot),
        Value::Map(unprot),
        Value::Null,
        Value::Array(recips),
    ] = msg.as_slice()
    else {
        return Err(CoseError::Malformed(
            "COSE_Encrypt shape / payload not detached",
        ));
    };
    if *prot != protected_alg(ALG_A256GCM) {
        return Err(CoseError::Malformed("content alg must be A256GCM"));
    }
    let Some(Value::Bytes(iv)) = int_key(unprot, HDR_IV) else {
        return Err(CoseError::Malformed("iv"));
    };
    let [Value::Array(r)] = recips.as_slice() else {
        return Err(CoseError::Malformed("exactly one recipient"));
    };
    let [Value::Bytes(rprot), Value::Map(runprot), Value::Bytes(rct)] = r.as_slice() else {
        return Err(CoseError::Malformed("recipient shape"));
    };
    if !rct.is_empty() {
        return Err(CoseError::Malformed(
            "recipient ciphertext must be empty (no key wrap)",
        ));
    }
    let Some(Value::Bytes(kid)) = int_key(runprot, HDR_KID) else {
        return Err(CoseError::Malformed("kid"));
    };
    let kem_ct = if *rprot == protected_alg(ALG_MLKEM768_PLACEHOLDER) {
        let Some(Value::Bytes(ek)) = int_key(runprot, HDR_EK) else {
            return Err(CoseError::Malformed("ek"));
        };
        if ek.len() != MLKEM768_CT_LEN {
            return Err(CoseError::Malformed("ek length"));
        }
        Some(ek.clone())
    } else if *rprot == protected_alg(-6) {
        None
    } else {
        return Err(CoseError::Malformed("unsupported recipient algorithm"));
    };
    Ok(Opened {
        bcb_number: blk.block_number,
        source: asb.security_source,
        iv: iv.clone(),
        recipient_protected: rprot.clone(),
        kem_ct,
        kid: kid.clone(),
    })
}

/// Decrypt the payload in place with `cek` and remove the BCB. Leaves the bundle unchanged on failure.
pub fn unseal_payload(b: &mut Bundle, o: &Opened, cek: &[u8; 32]) -> Result<(), CoseError> {
    let meta = SecBlockMeta {
        number: o.bcb_number,
        flags: b
            .canonicals
            .iter()
            .find(|c| c.block_number == o.bcb_number)
            .map(|c| u64::from(c.block_control_flags))
            .unwrap_or(0),
    };
    let aad = external_aad(b, &o.source, PAYLOAD_BLOCK, Some(meta), &DEFAULT_SCOPE)?;
    let prot = protected_alg(ALG_A256GCM);
    let pb = payload_mut(b)?;
    let CanonicalData::Data(ct) = pb.data().clone() else {
        return Err(CoseError::Malformed("payload"));
    };
    let pt = aes256gcm_decrypt(cek, &o.iv, &ct, &enc_structure("Encrypt", &prot, &aad))?;
    pb.set_data(CanonicalData::Data(pt));
    b.canonicals.retain(|c| c.block_number != o.bcb_number);
    Ok(())
}
