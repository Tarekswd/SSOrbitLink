use bp7::{Bundle, CanonicalData};
use orbitlink::contact::*;
use orbitlink::security::{self, Keys, Mode, PQ_KEM_BLOCK_TYPE, SecError};
use orbitlink::sim::{Routing, SimConfig, build_bundle, cgr_next, run};

fn plan_cfg(hours: f64, isl: bool) -> PlanConfig {
    PlanConfig {
        constellation: Constellation {
            planes: 6,
            per_plane: 8,
            altitude_km: 550.0,
            inclination_deg: 53.0,
            phasing: 1,
        },
        stations: default_ground_stations(),
        horizon_s: hours * 3600.0,
        step_s: 10.0,
        min_elevation_deg: 10.0,
        ground_rate_bps: 256_000.0,
        isl_rate_bps: isl.then_some(1_000_000.0),
    }
}

fn sim_cfg(routing: Routing, mode: Mode, hours: f64) -> SimConfig {
    SimConfig {
        plan: plan_cfg(hours, true),
        routing,
        mode,
        seed: 3,
        bundles_per_gs_hour: 60.0,
        payload_bytes: 1024,
        lifetime_s: 3600.0,
        sat_buffer_bytes: 512 * 1024,
        gs_buffer_bytes: 64 << 20,
        dt_s: 1.0,
        joules_per_bit: 1e-7,
    }
}

#[test]
fn elevation_geometry() {
    let gs = [6371.0, 0.0, 0.0];
    assert!((elevation_deg(gs, [6921.0, 0.0, 0.0]) - 90.0).abs() < 1e-9);
    assert!(elevation_deg(gs, [-6921.0, 0.0, 0.0]) < 0.0);
}

#[test]
fn contact_plan_is_consistent() {
    let p = generate(&plan_cfg(6.0, false));
    assert!(!p.contacts.is_empty());
    for c in &p.contacts {
        assert!(c.start < c.end);
        // a 550 km LEO pass above 10 deg lasts minutes, never more than ~15 min
        assert!(c.end - c.start <= 900.0, "{c:?}");
        // without ISLs every contact is ground <-> satellite
        assert!((c.from < p.ground) != (c.to < p.ground));
        assert!(
            p.contacts
                .iter()
                .any(|d| d.from == c.to && d.to == c.from && d.start == c.start)
        );
    }
    let with_isl = generate(&plan_cfg(6.0, true));
    assert_eq!(with_isl.contacts.len(), p.contacts.len() + 2 * 48);
}

fn bundle(mode: Mode, keys: &Keys) -> Bundle {
    let mut b = build_bundle(0, 1, b"telemetry frame".to_vec(), 600.0, 0.0, 1);
    security::protect(&mut b, mode, keys, 0, 1).unwrap();
    Bundle::try_from(b.to_cbor().as_slice()).unwrap()
}

#[test]
fn every_mode_roundtrips_and_validates() {
    let keys = Keys::generate(3);
    for mode in Mode::ALL {
        let mut b = bundle(mode, &keys);
        assert!(b.validate().is_ok(), "{mode:?}");
        security::accept(&mut b, mode, &keys, 1).unwrap();
        assert_eq!(b.payload().unwrap(), b"telemetry frame", "{mode:?}");
    }
}

fn tamper_payload(b: &mut Bundle) {
    let p = b
        .canonicals
        .iter_mut()
        .find(|c| c.block_type == bp7::canonical::PAYLOAD_BLOCK)
        .unwrap();
    let CanonicalData::Data(d) = p.data().clone() else {
        panic!("payload")
    };
    let mut d = d;
    d[0] ^= 1;
    p.set_data(CanonicalData::Data(d));
}

#[test]
fn tampered_payload_rejected() {
    let keys = Keys::generate(3);
    for mode in [Mode::Bib, Mode::BcbPsk, Mode::BcbPq] {
        let mut b = bundle(mode, &keys);
        tamper_payload(&mut b);
        assert_eq!(
            security::accept(&mut b, mode, &keys, 1),
            Err(SecError::Integrity),
            "{mode:?}"
        );
    }
}

#[test]
fn tampered_kem_ciphertext_rejected() {
    let keys = Keys::generate(3);
    let mut b = bundle(Mode::BcbPq, &keys);
    let ext = b
        .canonicals
        .iter_mut()
        .find(|c| c.block_type == PQ_KEM_BLOCK_TYPE)
        .unwrap();
    let CanonicalData::Unknown(ct) = ext.data().clone() else {
        panic!("ext")
    };
    let mut ct = ct;
    ct[10] ^= 1; // ML-KEM implicit rejection -> wrong KEK -> key unwrap / GCM fails
    ext.set_data(CanonicalData::Unknown(ct));
    assert_eq!(
        security::accept(&mut b, Mode::BcbPq, &keys, 1),
        Err(SecError::Integrity)
    );
}

#[test]
fn wrong_recipient_cannot_decrypt_pq() {
    let keys = Keys::generate(3);
    let mut b = bundle(Mode::BcbPq, &keys);
    assert!(security::accept(&mut b, Mode::BcbPq, &keys, 2).is_err());
}

#[test]
fn missing_security_block_is_malformed() {
    let keys = Keys::generate(3);
    let mut b = bundle(Mode::None, &keys);
    assert_eq!(
        security::accept(&mut b, Mode::BcbPsk, &keys, 1),
        Err(SecError::Malformed)
    );
}

#[test]
fn pq_mode_costs_at_least_one_kem_ciphertext() {
    let keys = Keys::generate(3);
    let psk = bundle(Mode::BcbPsk, &keys).to_cbor().len();
    let pq = bundle(Mode::BcbPq, &keys).to_cbor().len();
    assert!(pq >= psk + 1088, "psk={psk} pq={pq}");
}

#[test]
fn cgr_picks_earliest_arrival_and_respects_contact_end() {
    // 0 = source ground station, 1 = destination ground station, 2,3 = satellites
    let c = |from, to, start, end| Contact {
        from,
        to,
        start,
        end,
        rate_bps: 8000.0,
    };
    let plan = Plan {
        nodes: 4,
        ground: 2,
        contacts: vec![
            c(0, 2, 0.0, 100.0),
            c(2, 1, 500.0, 600.0),
            c(0, 3, 10.0, 100.0),
            c(3, 1, 50.0, 100.0),
        ],
    };
    let mut by_from = vec![vec![]; 4];
    for (i, x) in plan.contacts.iter().enumerate() {
        by_from[x.from].push(i);
    }
    // 1000 bytes = 1 s per hop: via sat 3 arrives at ~51 s, via sat 2 at ~501 s
    assert_eq!(cgr_next(&plan, &by_from, 0, 1, 0.0, 8000.0, 1e9), Some(2));
    // a bundle too large for the 3->1 window (50 s) must take the later route
    assert_eq!(
        cgr_next(&plan, &by_from, 0, 1, 0.0, 8000.0 * 60.0, 1e9),
        Some(0)
    );
    // deadline before any arrival: no route
    assert_eq!(cgr_next(&plan, &by_from, 0, 1, 0.0, 8000.0, 30.0), None);
}

#[test]
fn simulation_delivers_with_zero_crypto_failures() {
    let m = run(&sim_cfg(Routing::Cgr, Mode::BcbPq, 2.0)).unwrap();
    assert!(m.generated > 50);
    assert!(m.delivered > 0);
    assert_eq!(m.crypto_failures, 0);
    assert!(m.delivered + m.duplicates <= m.generated + m.duplicates);
}

#[test]
fn short_lifetime_expires_bundles() {
    let mut cfg = sim_cfg(Routing::FirstContact, Mode::None, 1.0);
    cfg.lifetime_s = 5.0;
    let m = run(&cfg).unwrap();
    assert!(m.expired_copies > 0);
    assert!(m.delivered < m.generated / 10);
}

#[test]
fn deterministic_for_seed() {
    let a = run(&sim_cfg(Routing::Cgr, Mode::BcbPsk, 1.0)).unwrap();
    let b = run(&sim_cfg(Routing::Cgr, Mode::BcbPsk, 1.0)).unwrap();
    assert_eq!(
        (a.generated, a.delivered, a.bytes_tx, a.delays_s.clone()),
        (b.generated, b.delivered, b.bytes_tx, b.delays_s)
    );
}

#[test]
fn invalid_config_rejected() {
    let mut cfg = sim_cfg(Routing::Cgr, Mode::None, 1.0);
    cfg.dt_s = 0.0;
    assert!(run(&cfg).is_err());
}
