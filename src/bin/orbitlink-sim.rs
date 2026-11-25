//! Experiment driver.
//!   orbitlink-sim <seeds> <out.csv> [--quick]
//! Grid: routing {Cgr, Epidemic, FirstContact} x security {None, BcbPsk, BcbPq, BcbPqSession r=1, r=3,
//! r=1 with refresh every 4th / 8th bundle, r=1 with refresh after 900 s / 1800 s}
//! x ISL {off, on}
//! x load {low, high}, repeated for each seed. All network metrics are SIMULATED; protect/accept
//! times are MEASURED CPU wall time of the real bp7/ml-kem operations on this machine.

use orbitlink::contact::{PlanConfig, default_ground_stations, default_shells};
use orbitlink::security::Mode;
use orbitlink::sim::{Routing, SimConfig, run};
use std::io::Write;

fn pct(v: &[f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    let mut s = v.to_vec();
    s.sort_by(f64::total_cmp);
    s[((s.len() - 1) as f64 * p).round() as usize]
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() {
        f64::NAN
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        return Err("usage: orbitlink-sim <seeds> <out.csv> [--quick]".into());
    }
    let seeds: u64 = a[1].parse()?;
    let quick = a.iter().any(|x| x == "--quick");
    let horizon = if quick { 2.0 * 3600.0 } else { 12.0 * 3600.0 };
    const HEADER: &str = "seed,routing,mode,isl,load_per_gs_hour,contacts,generated,delivered,delivery_ratio,delay_median_s,delay_p95_s,expired_copies,refused_buffer_full,source_drops,aborted_transfers,bytes_tx,overhead_tx_per_delivered_payload,mean_bundle_bytes,mean_plain_bundle_bytes,security_overhead_bytes,protect_us_mean,accept_us_mean,crypto_failures,route_computations,sat_buffer_util_mean,sat_buffer_util_max,energy_j_estimate,session_redundancy,decrypted_ratio,plaintext_delay_median_s,plaintext_delay_p95_s,kem_carrying,session_refresh_every,session_refresh_s";
    // Resume: keep complete rows of an existing file (a killed run may leave a truncated last line), skip their configs.
    let ncols = HEADER.split(',').count();
    let old = std::fs::read_to_string(&a[2]).unwrap_or_default();
    let rows: Vec<&str> = old
        .split_inclusive('\n')
        .skip(1)
        .filter(|l| l.ends_with('\n') && l.trim_end().split(',').count() == ncols)
        .collect();
    let key = |f: &[&str]| format!("{}|{}|{}|{}", f[..5].join(","), f[27], f[32], f[33]);
    let done: std::collections::HashSet<String> = rows
        .iter()
        .map(|l| key(&l.trim_end().split(',').collect::<Vec<_>>()))
        .collect();
    let mut out = std::fs::File::create(&a[2])?;
    writeln!(out, "{HEADER}")?;
    out.write_all(rows.concat().as_bytes())?;
    if !done.is_empty() {
        eprintln!("resuming: {} rows kept", done.len());
    }
    for seed in 1..=seeds {
        for isl in [false, true] {
            for load in [20.0, 120.0] {
                for routing in [Routing::Cgr, Routing::Epidemic, Routing::FirstContact] {
                    for (mode, redundancy, refresh, refresh_s) in [
                        (Mode::None, 0, 0, 0.0),
                        (Mode::BcbPsk, 0, 0, 0.0),
                        (Mode::BcbPq, 0, 0, 0.0),
                        (Mode::BcbPqSession, 1, 0, 0.0),
                        (Mode::BcbPqSession, 3, 0, 0.0),
                        (Mode::BcbPqSession, 1, 4, 0.0),
                        (Mode::BcbPqSession, 1, 8, 0.0),
                        (Mode::BcbPqSession, 1, 0, 900.0),
                        (Mode::BcbPqSession, 1, 0, 1800.0),
                    ] {
                        let k = format!("{seed},{routing:?},{mode:?},{isl},{load}|{redundancy}|{refresh}|{refresh_s}");
                        if done.contains(&k) {
                            continue;
                        }
                        let cfg = SimConfig {
                            plan: PlanConfig {
                                shells: default_shells(),
                                stations: default_ground_stations(),
                                horizon_s: horizon,
                                step_s: 10.0,
                                min_elevation_deg: 10.0,
                                ground_rate_bps: 256_000.0,
                                isl_rate_bps: isl.then_some(1_000_000.0),
                            },
                            routing,
                            mode,
                            seed,
                            bundles_per_gs_hour: load,
                            payload_bytes: 2048,
                            lifetime_s: 3.0 * 3600.0,
                            sat_buffer_bytes: 512 * 1024,
                            gs_buffer_bytes: 64 * 1024 * 1024,
                            dt_s: 1.0,
                            joules_per_bit: 1e-7,
                            pq_session_epoch_s: 3600.0,
                            pq_session_redundancy: redundancy.max(1),
                            pq_session_refresh_every: refresh,
                            pq_session_refresh_s: refresh_s,
                        };
                        let m = run(&cfg)?;
                        let delivered_payload = (m.delivered * cfg.payload_bytes).max(1) as f64;
                        writeln!(
                            out,
                            "{seed},{routing:?},{mode:?},{isl},{load},{},{},{},{:.4},{:.1},{:.1},{},{},{},{},{},{:.3},{:.1},{:.1},{:.1},{:.1},{:.1},{},{},{:.4},{:.4},{:.3},{redundancy},{:.4},{:.1},{:.1},{},{refresh},{refresh_s}",
                            m.contacts,
                            m.generated,
                            m.delivered,
                            m.delivered as f64 / m.generated.max(1) as f64,
                            pct(&m.delays_s, 0.5),
                            pct(&m.delays_s, 0.95),
                            m.expired_copies,
                            m.refused_buffer_full,
                            m.source_drops,
                            m.aborted_transfers,
                            m.bytes_tx,
                            m.bytes_tx as f64 / delivered_payload,
                            m.mean_bundle_bytes,
                            m.mean_plain_bundle_bytes,
                            m.mean_bundle_bytes - m.mean_plain_bundle_bytes,
                            mean(&m.protect_us),
                            mean(&m.accept_us),
                            m.crypto_failures,
                            m.route_computations,
                            m.sat_buffer_util_mean,
                            m.sat_buffer_util_max,
                            m.energy_j_estimate,
                            m.decrypted as f64 / m.generated.max(1) as f64,
                            pct(&m.plaintext_delays_s, 0.5),
                            pct(&m.plaintext_delays_s, 0.95),
                            m.kem_carrying
                        )?;
                        eprintln!(
                            "seed={seed} isl={isl} load={load} {routing:?} {mode:?} r={redundancy} k={refresh}: delivered {}/{} decrypted {}",
                            m.delivered, m.generated, m.decrypted
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
