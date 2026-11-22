//! Time-stepped store-and-forward simulation over a contact plan.
//!
//! Every generated message is a real BPv7 bundle (bp7 crate) with the chosen security mode applied;
//! its CBOR length is what gets transmitted, and the destination really verifies/decrypts it.
//! Routing:
//!   Cgr          - CGR-style earliest-arrival search over the contact graph (Dijkstra on contacts,
//!                  using the full contact plan). Simplified: no contact-volume reservation, no
//!                  queue-aware arrival estimates, no route lists. Not the ION/RFC CGR implementation.
//!   Epidemic     - copy to every contact peer that has not seen the bundle.
//!   FirstContact - hand the single copy to the first available peer other than the previous hop.

use crate::contact::{Contact, Plan, PlanConfig, generate};
use crate::rng::SplitMix64;
use crate::security::{self, Keys, Mode, ReceiverSessions, SenderSessions, SessionAccept};
use bp7::{
    Bundle, EndpointID, canonical, crc, flags::BlockControlFlags, primary::PrimaryBlockBuilder,
};
use std::collections::{BinaryHeap, HashSet};
use std::time::Instant;

/// Delivered-but-undecryptable bundles per (destination, session kid): [(bundle id, expiry)].
type Pending = std::collections::HashMap<(usize, Vec<u8>), Vec<(usize, f64)>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Routing {
    Cgr,
    Epidemic,
    FirstContact,
}

#[derive(Clone, Debug)]
pub struct SimConfig {
    pub plan: PlanConfig,
    pub routing: Routing,
    pub mode: Mode,
    pub seed: u64,
    /// Mean bundles generated per ground station per hour (Bernoulli per step approximation of Poisson).
    pub bundles_per_gs_hour: f64,
    pub payload_bytes: usize,
    pub lifetime_s: f64,
    pub sat_buffer_bytes: usize,
    pub gs_buffer_bytes: usize,
    pub dt_s: f64,
    /// ILLUSTRATIVE energy assumption (J per transmitted bit); not a measured or sourced value.
    pub joules_per_bit: f64,
    /// `Mode::BcbPqSession` only: session epoch length and number of bundles per session that carry
    /// the ML-KEM ciphertext.
    pub pq_session_epoch_s: f64,
    pub pq_session_redundancy: u32,
}

impl SimConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.dt_s <= 0.0 || self.lifetime_s <= 0.0 || self.payload_bytes == 0 {
            return Err("dt, lifetime and payload must be positive".into());
        }
        if self.bundles_per_gs_hour * self.dt_s / 3600.0 > 0.5 {
            return Err("generation rate too high for the per-step Bernoulli approximation".into());
        }
        if self.plan.stations.len() < 2 {
            return Err("need at least two ground stations".into());
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct Metrics {
    pub contacts: usize,
    pub generated: usize,
    pub delivered: usize,
    pub duplicates: usize,
    pub delays_s: Vec<f64>,
    pub expired_copies: usize,
    pub refused_buffer_full: usize,
    pub source_drops: usize,
    pub aborted_transfers: usize,
    pub bytes_tx: u64,
    pub mean_bundle_bytes: f64,
    pub mean_plain_bundle_bytes: f64,
    pub protect_us: Vec<f64>,
    pub accept_us: Vec<f64>,
    pub crypto_failures: usize,
    /// Delivered bundles whose payload was decrypted before the bundle lifetime ended.
    pub decrypted: usize,
    /// Creation-to-plaintext delays (s) for decrypted bundles (>= delivery delay in session mode).
    pub plaintext_delays_s: Vec<f64>,
    /// Bundles generated carrying an ML-KEM ciphertext.
    pub kem_carrying: usize,
    pub route_computations: usize,
    pub sat_buffer_util_mean: f64,
    pub sat_buffer_util_max: f64,
    pub energy_j_estimate: f64,
}

struct Msg {
    dst: usize,
    created: f64,
    expires: f64,
    size: usize,
    cbor: Vec<u8>,
}

#[derive(Clone)]
struct Copy {
    id: usize,
    prev: Option<usize>,
    next_contact: Option<usize>,
}

fn eid(node: usize) -> EndpointID {
    EndpointID::with_ipn(node as u64 + 1, 1).expect("valid ipn")
}

/// DTN time (ms since 2000-01-01) of 2026-01-01T00:00:00Z: simulation epoch, so bundles do not
/// depend on the wall clock and runs are reproducible.
pub const SIM_EPOCH_DTN_MS: u64 = 820_540_800_000;

/// Build a standard BPv7 bundle created at simulation time `t_s` with sequence number `seq`.
/// CRC-32 is set on all blocks; RFC 9171 requires a primary-block CRC unless a BIB protects it.
pub fn build_bundle(
    src: usize,
    dst: usize,
    payload: Vec<u8>,
    lifetime_s: f64,
    t_s: f64,
    seq: u64,
) -> Bundle {
    let flags = bp7::flags::BundleControlFlags::BUNDLE_MUST_NOT_FRAGMENTED;
    let primary = PrimaryBlockBuilder::default()
        .bundle_control_flags(flags.bits())
        .destination(eid(dst))
        .source(eid(src))
        .report_to(eid(src))
        .creation_timestamp(bp7::CreationTimestamp::with_time_and_seq(
            SIM_EPOCH_DTN_MS + (t_s * 1000.0) as u64,
            seq,
        ))
        .lifetime(std::time::Duration::from_secs_f64(lifetime_s))
        .build()
        .expect("valid primary block");
    let mut b = Bundle::new(
        primary,
        vec![
            canonical::new_payload_block(BlockControlFlags::empty(), payload),
            canonical::new_hop_count_block(2, BlockControlFlags::empty(), 32),
        ],
    );
    b.set_crc(crc::CRC_32);
    b.sort_canonicals();
    b
}

#[derive(PartialEq)]
struct Entry(f64, usize);
impl Eq for Entry {}
impl Ord for Entry {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        o.0.total_cmp(&self.0) // min-heap on time
    }
}
impl PartialOrd for Entry {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

/// Earliest-arrival search. Returns the index of the first contact to use from `from`, or None.
pub fn cgr_next(
    plan: &Plan,
    by_from: &[Vec<usize>],
    from: usize,
    dst: usize,
    t: f64,
    bits: f64,
    deadline: f64,
) -> Option<usize> {
    let mut arr = vec![f64::INFINITY; plan.nodes];
    let mut first: Vec<Option<usize>> = vec![None; plan.nodes];
    arr[from] = t;
    let mut heap = BinaryHeap::from([Entry(t, from)]);
    while let Some(Entry(at, x)) = heap.pop() {
        if at > arr[x] {
            continue;
        }
        if x == dst {
            return first[x];
        }
        // ground stations other than the source do not relay (they are endpoints, not routers)
        if x != from && x < plan.ground {
            continue;
        }
        for &ci in &by_from[x] {
            let c: &Contact = &plan.contacts[ci];
            if c.end <= at {
                continue;
            }
            let arrive = at.max(c.start) + bits / c.rate_bps;
            if arrive <= c.end && arrive <= deadline && arrive < arr[c.to] {
                arr[c.to] = arrive;
                first[c.to] = if x == from { Some(ci) } else { first[x] };
                heap.push(Entry(arrive, c.to));
            }
        }
    }
    None
}

pub fn run(cfg: &SimConfig) -> Result<Metrics, String> {
    cfg.validate()?;
    let plan = generate(&cfg.plan);
    let keys = Keys::generate(plan.nodes);
    let mut tx_sessions = SenderSessions::new(
        cfg.pq_session_epoch_s.max(1.0),
        cfg.pq_session_redundancy.max(1),
    );
    let mut rx_sessions = ReceiverSessions::default();
    // delivered-but-undecryptable bundles waiting for their session key: (dst, kid) -> [(id, expires)]
    let mut pending: Pending = Default::default();
    let mut rng = SplitMix64::new(cfg.seed);
    let mut by_from = vec![Vec::new(); plan.nodes];
    for (i, c) in plan.contacts.iter().enumerate() {
        by_from[c.from].push(i);
    }
    let cap = |n: usize| {
        if n < plan.ground {
            cfg.gs_buffer_bytes
        } else {
            cfg.sat_buffer_bytes
        }
    };

    let mut m = Metrics {
        contacts: plan.contacts.len(),
        ..Default::default()
    };
    let mut msgs: Vec<Msg> = Vec::new();
    let mut buf: Vec<Vec<Copy>> = vec![Vec::new(); plan.nodes];
    let mut used = vec![0usize; plan.nodes];
    let mut seen: Vec<HashSet<usize>> = vec![HashSet::new(); plan.nodes];
    let mut delivered: HashSet<usize> = HashSet::new();
    let mut inflight: Vec<Option<(usize, f64)>> = vec![None; plan.contacts.len()]; // (copy id, bytes left)
    let mut util_sum = 0.0;
    let mut util_n = 0usize;
    let p_gen = cfg.bundles_per_gs_hour * cfg.dt_s / 3600.0;

    let steps = (cfg.plan.horizon_s / cfg.dt_s) as usize;
    let mut next_contact = 0usize;
    let mut active: Vec<usize> = Vec::new();
    for k in 0..steps {
        let t = k as f64 * cfg.dt_s;

        // 1. traffic generation at ground stations
        for src in 0..plan.ground {
            if rng.next_f64() >= p_gen {
                continue;
            }
            let mut dst = rng.below(plan.ground - 1);
            if dst >= src {
                dst += 1;
            }
            let payload: Vec<u8> = (0..cfg.payload_bytes)
                .map(|_| rng.next_u64() as u8)
                .collect();
            let seq = msgs.len() as u64;
            let mut plain = build_bundle(src, dst, payload.clone(), cfg.lifetime_s, t, seq);
            let plain_len = plain.to_cbor().len();
            let mut b = build_bundle(src, dst, payload, cfg.lifetime_s, t, seq);
            let t0 = Instant::now();
            if cfg.mode == Mode::BcbPqSession {
                m.kem_carrying += tx_sessions
                    .protect(&mut b, &keys, src, dst, t)
                    .map_err(|e| e.to_string())? as usize;
            } else {
                security::protect(&mut b, cfg.mode, &keys, src, dst).map_err(|e| e.to_string())?;
                m.kem_carrying += (cfg.mode == Mode::BcbPq) as usize;
            }
            let cbor = b.to_cbor();
            m.protect_us.push(t0.elapsed().as_secs_f64() * 1e6);
            m.mean_plain_bundle_bytes += plain_len as f64;
            m.mean_bundle_bytes += cbor.len() as f64;
            let id = msgs.len();
            msgs.push(Msg {
                dst,
                created: t,
                expires: t + cfg.lifetime_s,
                size: cbor.len(),
                cbor,
            });
            m.generated += 1;
            if used[src] + msgs[id].size > cap(src) {
                m.source_drops += 1;
                continue;
            }
            used[src] += msgs[id].size;
            seen[src].insert(id);
            buf[src].push(Copy {
                id,
                prev: None,
                next_contact: None,
            });
        }

        // 2. expiry (bundle lifetime, RFC 9171 4.2.2): delete expired copies everywhere
        for (n, b) in buf.iter_mut().enumerate() {
            b.retain(|c| {
                let keep = msgs[c.id].expires > t;
                if !keep {
                    used[n] -= msgs[c.id].size;
                    m.expired_copies += 1;
                }
                keep
            });
        }

        // 3. contact bookkeeping
        while next_contact < plan.contacts.len() && plan.contacts[next_contact].start <= t {
            active.push(next_contact);
            next_contact += 1;
        }
        active.retain(|&ci| {
            let live = plan.contacts[ci].end > t;
            if !live && inflight[ci].take().is_some() {
                m.aborted_transfers += 1;
            }
            live
        });

        // 4. transmissions
        for &ci in &active {
            let c = plan.contacts[ci];
            let mut budget = c.rate_bps / 8.0 * cfg.dt_s;
            while budget > 0.0 {
                if inflight[ci].is_none() {
                    let pick = buf[c.from].iter().position(|cp| {
                        let msg = &msgs[cp.id];
                        if delivered.contains(&cp.id) && cfg.routing != Routing::Epidemic {
                            return false;
                        }
                        match cfg.routing {
                            Routing::Epidemic => {
                                !seen[c.to].contains(&cp.id)
                                    && (c.to >= plan.ground || c.to == msg.dst)
                            }
                            Routing::FirstContact => {
                                cp.prev != Some(c.to) && (c.to >= plan.ground || c.to == msg.dst)
                            }
                            Routing::Cgr => cp.next_contact == Some(ci),
                        }
                    });
                    match pick {
                        Some(i) => {
                            inflight[ci] =
                                Some((buf[c.from][i].id, msgs[buf[c.from][i].id].size as f64))
                        }
                        None => break,
                    }
                }
                let (id, left) = inflight[ci].expect("set above");
                let sent = left.min(budget);
                budget -= sent;
                m.bytes_tx += sent as u64;
                if sent < left {
                    inflight[ci] = Some((id, left - sent));
                    break;
                }
                inflight[ci] = None;
                let Some(pos) = buf[c.from].iter().position(|cp| cp.id == id) else {
                    continue;
                }; // expired mid-transfer
                let msg = &msgs[id];
                let moves = cfg.routing != Routing::Epidemic;
                if c.to == msg.dst {
                    if delivered.insert(id) {
                        let mut b =
                            Bundle::try_from(msg.cbor.as_slice()).map_err(|e| format!("{e:?}"))?;
                        let t0 = Instant::now();
                        let now = t + cfg.dt_s;
                        if cfg.mode == Mode::BcbPqSession {
                            match rx_sessions.accept(&mut b, &keys, msg.dst) {
                                Ok(SessionAccept::Ok { learned }) => {
                                    m.accept_us.push(t0.elapsed().as_secs_f64() * 1e6);
                                    m.decrypted += 1;
                                    m.plaintext_delays_s.push(now - msg.created);
                                    // a newly learned key unlocks bundles waiting for it (if not yet expired)
                                    if let Some(kid) = learned {
                                        for (pid, exp) in
                                            pending.remove(&(msg.dst, kid)).unwrap_or_default()
                                        {
                                            let mut pb =
                                                Bundle::try_from(msgs[pid].cbor.as_slice())
                                                    .map_err(|e| format!("{e:?}"))?;
                                            if exp > now {
                                                match rx_sessions.accept(&mut pb, &keys, msg.dst) {
                                                    Ok(SessionAccept::Ok { .. }) => {
                                                        m.decrypted += 1;
                                                        m.plaintext_delays_s
                                                            .push(now - msgs[pid].created);
                                                    }
                                                    _ => m.crypto_failures += 1,
                                                }
                                            }
                                        }
                                    }
                                }
                                Ok(SessionAccept::KeyUnavailable { kid }) => {
                                    pending
                                        .entry((msg.dst, kid))
                                        .or_default()
                                        .push((id, msg.expires));
                                }
                                Err(_) => m.crypto_failures += 1,
                            }
                        } else {
                            match security::accept(&mut b, cfg.mode, &keys, msg.dst) {
                                Ok(()) => {
                                    m.accept_us.push(t0.elapsed().as_secs_f64() * 1e6);
                                    m.decrypted += 1;
                                    m.plaintext_delays_s.push(now - msg.created);
                                }
                                Err(_) => m.crypto_failures += 1,
                            }
                        }
                        m.delivered += 1;
                        m.delays_s.push(now - msg.created);
                    } else {
                        m.duplicates += 1;
                    }
                    seen[c.to].insert(id);
                } else if used[c.to] + msg.size > cap(c.to) {
                    m.refused_buffer_full += 1;
                    continue; // sender keeps its copy
                } else {
                    used[c.to] += msg.size;
                    seen[c.to].insert(id);
                    buf[c.to].push(Copy {
                        id,
                        prev: Some(c.from),
                        next_contact: None,
                    });
                }
                if moves {
                    let cp = buf[c.from].remove(pos);
                    used[c.from] -= msgs[cp.id].size;
                }
            }
        }

        // 5. CGR: (re)compute routes for copies without a live planned contact
        if cfg.routing == Routing::Cgr {
            for (n, node_buf) in buf.iter_mut().enumerate() {
                for cp in node_buf.iter_mut() {
                    let stale = cp.next_contact.is_none_or(|ci| plan.contacts[ci].end <= t);
                    if stale && !delivered.contains(&cp.id) {
                        let msg = &msgs[cp.id];
                        m.route_computations += 1;
                        cp.next_contact = cgr_next(
                            &plan,
                            &by_from,
                            n,
                            msg.dst,
                            t,
                            msg.size as f64 * 8.0,
                            msg.expires,
                        );
                    }
                }
            }
        }

        if k % (60.0 / cfg.dt_s).max(1.0) as usize == 0 {
            for &bytes in &used[plan.ground..] {
                let u = bytes as f64 / cfg.sat_buffer_bytes as f64;
                util_sum += u;
                util_n += 1;
                m.sat_buffer_util_max = m.sat_buffer_util_max.max(u);
            }
        }
    }
    if m.generated > 0 {
        m.mean_bundle_bytes /= m.generated as f64;
        m.mean_plain_bundle_bytes /= m.generated as f64;
    }
    m.sat_buffer_util_mean = if util_n > 0 {
        util_sum / util_n as f64
    } else {
        0.0
    };
    m.energy_j_estimate = m.bytes_tx as f64 * 8.0 * cfg.joules_per_bit;
    Ok(m)
}
