//! COSE-context BCB tests. Interop vectors: draft-ietf-dtn-bpsec-cose-19 Appendix A (Figures 10-28) and
//! NIST SP 800-185 KMAC samples (KMAC_samples.pdf, csrc.nist.gov).

use bp7::{Bundle, CanonicalData};
use orbitlink::cose::*;
use orbitlink::security::{
    self, Keys, Mode, ReceiverSessions, SecError, SenderSessions, SessionAccept,
};
use orbitlink::sim::build_bundle;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const DRAFT_BUNDLE: &str = "9f890700028201692f2f6473742f7376638201692f2f7372632f7376638201662f2f\
7372632f821b000000bd51281400001a000f42404482a081c9860101000246656865\
6c6c6f444ec359d2ff";
const DRAFT_AAD: &str = "8201662f2f7372632fa200012001890700028201692f2f6473742f7376638201\
692f2f7372632f7376638201662f2f7372632f821b000000bd51281400001a000f42\
404482a081c901010040";

#[test]
fn external_aad_matches_draft_appendix_a() {
    let b = Bundle::try_from(unhex(DRAFT_BUNDLE).as_slice()).unwrap();
    let src: bp7::EndpointID = "dtn://src/".try_into().unwrap();
    let aad = external_aad(&b, &src, 1, None, &[(0, AAD_METADATA), (-1, AAD_METADATA)]).unwrap();
    assert_eq!(aad, unhex(DRAFT_AAD));
}

#[test]
fn a256gcm_enc_structure_matches_draft_figure_28() {
    // Figure 25 key; IV = base IV with the partial IV h'484a' in its low bytes.
    let key: [u8; 32] = unhex("13bf9cead057c0aca2c9e52471ca4b19ddfaf4c0784e3f3e8e3999dbae4ce45c")
        .try_into()
        .unwrap();
    let iv: [u8; 12] = unhex("6f3093eba5d85143c3dc484a").try_into().unwrap();
    let aad = enc_structure("Encrypt0", &unhex("a10103"), &unhex(DRAFT_AAD));
    let ct = aes256gcm_encrypt(&key, &iv, b"ehello", &aad); // Figure 11 BTSD h'6568656c6c6f'
    assert_eq!(ct, unhex("1fd25f64a2eee2ff1a1ab29812ba221874380974c13b"));
}

#[test]
fn kmac256_matches_nist_samples() {
    let key: Vec<u8> = (0x40u8..=0x5f).collect();
    let s4 = kmac256(&key, &[0, 1, 2, 3], 64, b"My Tagged Application");
    assert_eq!(
        s4,
        unhex(
            "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"
        )
    );
    let data: Vec<u8> = (0u8..=0xc7).collect();
    let s5 = kmac256(&key, &data, 64, b"");
    assert_eq!(
        s5,
        unhex(
            "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"
        )
    );
}

fn bundle() -> Bundle {
    build_bundle(0, 1, b"telemetry frame".to_vec(), 600.0, 0.0, 1)
}

fn reencode(b: &mut Bundle) -> Bundle {
    Bundle::try_from(b.to_cbor().as_slice()).unwrap()
}

#[test]
fn per_bundle_pq_roundtrip_uses_cose_context() {
    let keys = Keys::generate(3);
    let mut b = bundle();
    security::protect(&mut b, Mode::BcbPq, &keys, 0, 1).unwrap();
    let mut r = reencode(&mut b);
    assert!(r.validate().is_ok());
    let o = open(&r).unwrap();
    assert!(o.kem_ct.is_some());
    assert_ne!(r.payload().unwrap(), b"telemetry frame");
    security::accept(&mut r, Mode::BcbPq, &keys, 1).unwrap();
    assert_eq!(r.payload().unwrap(), b"telemetry frame");
    assert!(
        r.canonicals
            .iter()
            .all(|c| c.block_type != bp7::bpsec::CONFIDENTIALITY_BLOCK)
    );
}

fn with_cose<F: FnOnce(&mut Vec<serde_cbor::Value>)>(b: &mut Bundle, f: F) {
    let blk = b
        .canonicals
        .iter_mut()
        .find(|c| c.block_type == bp7::bpsec::CONFIDENTIALITY_BLOCK)
        .unwrap();
    let CanonicalData::Unknown(d) = blk.data().clone() else {
        panic!()
    };
    let mut asb = bp7::bpsec::AbstractSecurityBlock::from_cbor(&d).unwrap();
    let serde_cbor::Value::Bytes(enc) = asb.security_results[0][0].1.clone() else {
        panic!()
    };
    let serde_cbor::Value::Array(mut msg) = serde_cbor::from_slice(&enc).unwrap() else {
        panic!()
    };
    f(&mut msg);
    asb.security_results[0][0].1 =
        serde_cbor::Value::Bytes(serde_cbor::to_vec(&serde_cbor::Value::Array(msg)).unwrap());
    blk.set_data(CanonicalData::Unknown(asb.to_cbor()));
}

fn recipient_map(
    msg: &mut [serde_cbor::Value],
) -> &mut std::collections::BTreeMap<serde_cbor::Value, serde_cbor::Value> {
    let serde_cbor::Value::Array(rs) = &mut msg[3] else {
        panic!()
    };
    let serde_cbor::Value::Array(r) = &mut rs[0] else {
        panic!()
    };
    let serde_cbor::Value::Map(m) = &mut r[1] else {
        panic!()
    };
    m
}

#[test]
fn tampered_payload_ek_or_iv_rejected() {
    let keys = Keys::generate(3);
    let fresh = || {
        let mut b = bundle();
        security::protect(&mut b, Mode::BcbPq, &keys, 0, 1).unwrap();
        reencode(&mut b)
    };
    let mut b = fresh();
    let p = b
        .canonicals
        .iter_mut()
        .find(|c| c.block_number == 1)
        .unwrap();
    let CanonicalData::Data(mut d) = p.data().clone() else {
        panic!()
    };
    d[0] ^= 1;
    p.set_data(CanonicalData::Data(d));
    assert_eq!(
        security::accept(&mut b, Mode::BcbPq, &keys, 1),
        Err(SecError::Integrity)
    );

    let mut b = fresh();
    with_cose(&mut b, |m| {
        let r = recipient_map(m);
        let serde_cbor::Value::Bytes(ek) = r.get_mut(&serde_cbor::Value::Integer(HDR_EK)).unwrap()
        else {
            panic!()
        };
        ek[5] ^= 1; // ML-KEM implicit rejection -> different CEK -> GCM failure
    });
    assert_eq!(
        security::accept(&mut b, Mode::BcbPq, &keys, 1),
        Err(SecError::Integrity)
    );

    let mut b = fresh();
    with_cose(&mut b, |m| {
        let serde_cbor::Value::Map(u) = &mut m[1] else {
            panic!()
        };
        u.insert(
            serde_cbor::Value::Integer(HDR_IV),
            serde_cbor::Value::Bytes(vec![0; 12]),
        );
    });
    assert_eq!(
        security::accept(&mut b, Mode::BcbPq, &keys, 1),
        Err(SecError::Integrity)
    );
}

#[test]
fn key_wrap_and_unknown_recipients_refused() {
    let keys = Keys::generate(3);
    let mut b = bundle();
    security::protect(&mut b, Mode::BcbPq, &keys, 0, 1).unwrap();
    let mut b = reencode(&mut b);
    with_cose(&mut b, |m| {
        let serde_cbor::Value::Array(rs) = &mut m[3] else {
            panic!()
        };
        let serde_cbor::Value::Array(r) = &mut rs[0] else {
            panic!()
        };
        r[2] = serde_cbor::Value::Bytes(vec![1; 40]); // a wrapped CEK
    });
    assert_eq!(
        security::accept(&mut b, Mode::BcbPq, &keys, 1),
        Err(SecError::Malformed)
    );

    let mut b = bundle();
    security::protect(&mut b, Mode::BcbPq, &keys, 0, 1).unwrap();
    let mut b = reencode(&mut b);
    with_cose(&mut b, |m| {
        let serde_cbor::Value::Array(rs) = &mut m[3] else {
            panic!()
        };
        let serde_cbor::Value::Array(r) = &mut rs[0] else {
            panic!()
        };
        r[0] = serde_cbor::Value::Bytes(protected_alg(-3)); // A256KW recipient
    });
    assert_eq!(
        security::accept(&mut b, Mode::BcbPq, &keys, 1),
        Err(SecError::Malformed)
    );
}

#[test]
fn wrong_recipient_cannot_decrypt() {
    let keys = Keys::generate(3);
    let mut b = bundle();
    security::protect(&mut b, Mode::BcbPq, &keys, 0, 1).unwrap();
    let mut b = reencode(&mut b);
    assert!(security::accept(&mut b, Mode::BcbPq, &keys, 2).is_err());
}

#[test]
fn session_mode_carries_kem_only_in_first_r_bundles() {
    let keys = Keys::generate(3);
    let mut tx = SenderSessions::new(3600.0, 2, 0);
    let mut rx = ReceiverSessions::default();
    let mut sizes = vec![];
    let mut bundles = vec![];
    for i in 0..4 {
        let mut b = build_bundle(0, 1, b"telemetry frame".to_vec(), 600.0, i as f64, i);
        let carried = tx.protect(&mut b, &keys, 0, 1, i as f64).unwrap();
        assert_eq!(carried, i < 2);
        sizes.push(b.to_cbor().len());
        bundles.push(reencode(&mut b));
    }
    assert!(sizes[0] > sizes[2] + 1000, "{sizes:?}");
    // a direct-recipient bundle arriving first cannot be decrypted yet
    let mut late = bundles[3].clone();
    assert!(matches!(
        rx.accept(&mut late, &keys, 1).unwrap(),
        SessionAccept::KeyUnavailable { .. }
    ));
    // the key-carrying bundle teaches the key; then the direct bundle decrypts
    assert!(matches!(
        rx.accept(&mut bundles[0], &keys, 1).unwrap(),
        SessionAccept::Ok { learned: Some(_) }
    ));
    assert_eq!(
        rx.accept(&mut bundles[3], &keys, 1).unwrap(),
        SessionAccept::Ok { learned: None }
    );
    assert_eq!(bundles[3].payload().unwrap(), b"telemetry frame");
    // new epoch -> new session -> KEM ciphertext again
    let mut b = build_bundle(0, 1, b"x".to_vec(), 600.0, 3600.0, 9);
    assert!(tx.protect(&mut b, &keys, 0, 1, 3600.0).unwrap());
}

#[test]
fn forged_kem_bundle_does_not_poison_session_cache() {
    let keys = Keys::generate(3);
    let mut tx = SenderSessions::new(3600.0, 1, 0);
    let mut rx = ReceiverSessions::default();
    let mut good = build_bundle(0, 1, b"a".to_vec(), 600.0, 0.0, 1);
    tx.protect(&mut good, &keys, 0, 1, 0.0).unwrap();
    let mut good = reencode(&mut good);
    let mut forged = good.clone();
    with_cose(&mut forged, |m| {
        let r = recipient_map(m);
        let serde_cbor::Value::Bytes(ek) = r.get_mut(&serde_cbor::Value::Integer(HDR_EK)).unwrap()
        else {
            panic!()
        };
        ek[0] ^= 1;
    });
    assert_eq!(rx.accept(&mut forged, &keys, 1), Err(SecError::Integrity));
    // the genuine bundle still teaches the right key
    assert!(matches!(
        rx.accept(&mut good, &keys, 1).unwrap(),
        SessionAccept::Ok { learned: Some(_) }
    ));
}

#[test]
fn periodic_refresh_recarries_ciphertext_every_k_bundles() {
    let keys = Keys::generate(3);
    let mut tx = SenderSessions::new(3600.0, 1, 4);
    let carried: Vec<bool> = (0..9)
        .map(|i| {
            let mut b = build_bundle(0, 1, b"x".to_vec(), 600.0, i as f64, i);
            tx.protect(&mut b, &keys, 0, 1, i as f64).unwrap()
        })
        .collect();
    assert_eq!(
        carried,
        [true, false, false, false, true, false, false, false, true]
    );
}

#[test]
fn time_refresh_recarries_ciphertext_after_interval() {
    let keys = Keys::generate(3);
    let mut tx = SenderSessions::new(3600.0, 1, 0);
    tx.refresh_s = 900.0;
    // bundles at 0, 300, 600, 900 (refresh due), 1000, 1900 (due again: 1000 s since 900)
    let carried: Vec<bool> = [0.0, 300.0, 600.0, 900.0, 1000.0, 1900.0]
        .iter()
        .enumerate()
        .map(|(i, &t)| {
            let mut b = build_bundle(0, 1, b"x".to_vec(), 600.0, t, i as u64);
            tx.protect(&mut b, &keys, 0, 1, t).unwrap()
        })
        .collect();
    assert_eq!(carried, [true, false, false, true, false, true]);
}
