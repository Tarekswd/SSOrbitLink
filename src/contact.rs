//! Contact-plan generator from simplified orbital geometry.
//!
//! Model (SIMULATED, deliberately simple): spherical Earth, circular two-body orbits in a Walker-delta
//! constellation, Earth rotation for ground stations, no J2/drag/atmosphere/antenna patterns.
//! A ground-satellite contact exists while elevation >= `min_elevation_deg`. Optional intra-plane
//! inter-satellite links (ISLs) to the next satellite in the same plane are always up.
//! Not validated against real ephemerides (e.g. SGP4/TLEs); do not use for mission planning.

use std::f64::consts::PI;

const R_EARTH_KM: f64 = 6371.0;
const MU_KM3_S2: f64 = 398_600.441_8;
const OMEGA_EARTH: f64 = 7.292_115_9e-5;

#[derive(Clone, Debug)]
pub struct Constellation {
    pub planes: usize,
    pub per_plane: usize,
    pub altitude_km: f64,
    pub inclination_deg: f64,
    /// Walker phasing factor F.
    pub phasing: usize,
}

#[derive(Clone, Debug)]
pub struct GroundStation {
    pub name: &'static str,
    pub lat_deg: f64,
    pub lon_deg: f64,
}

/// A few geographically spread sites (coordinates rounded; illustrative only).
pub fn default_ground_stations() -> Vec<GroundStation> {
    vec![
        GroundStation {
            name: "Svalbard",
            lat_deg: 78.2,
            lon_deg: 15.4,
        },
        GroundStation {
            name: "Beirut",
            lat_deg: 33.9,
            lon_deg: 35.5,
        },
        GroundStation {
            name: "Nairobi",
            lat_deg: -1.3,
            lon_deg: 36.8,
        },
        GroundStation {
            name: "Singapore",
            lat_deg: 1.35,
            lon_deg: 103.8,
        },
        GroundStation {
            name: "Santiago",
            lat_deg: -33.4,
            lon_deg: -70.7,
        },
        GroundStation {
            name: "Fairbanks",
            lat_deg: 64.8,
            lon_deg: -147.7,
        },
    ]
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Contact {
    pub from: usize,
    pub to: usize,
    pub start: f64,
    pub end: f64,
    pub rate_bps: f64,
}

#[derive(Clone, Debug)]
pub struct PlanConfig {
    pub constellation: Constellation,
    pub stations: Vec<GroundStation>,
    pub horizon_s: f64,
    pub step_s: f64,
    pub min_elevation_deg: f64,
    pub ground_rate_bps: f64,
    pub isl_rate_bps: Option<f64>,
}

/// Node numbering: ground stations 0..G, then satellites G..G+P*S.
pub struct Plan {
    pub nodes: usize,
    pub ground: usize,
    pub contacts: Vec<Contact>,
}

fn sat_eci(c: &Constellation, idx: usize, t: f64) -> [f64; 3] {
    let (p, s) = (idx / c.per_plane, idx % c.per_plane);
    let r = R_EARTH_KM + c.altitude_km;
    let n = (MU_KM3_S2 / r.powi(3)).sqrt();
    let raan = 2.0 * PI * p as f64 / c.planes as f64;
    let total = (c.planes * c.per_plane) as f64;
    let u = 2.0 * PI * s as f64 / c.per_plane as f64
        + 2.0 * PI * c.phasing as f64 * p as f64 / total
        + n * t;
    let i = c.inclination_deg.to_radians();
    [
        r * (raan.cos() * u.cos() - raan.sin() * u.sin() * i.cos()),
        r * (raan.sin() * u.cos() + raan.cos() * u.sin() * i.cos()),
        r * (u.sin() * i.sin()),
    ]
}

fn gs_eci(g: &GroundStation, t: f64) -> [f64; 3] {
    let lat = g.lat_deg.to_radians();
    let lon = g.lon_deg.to_radians() + OMEGA_EARTH * t;
    [
        R_EARTH_KM * lat.cos() * lon.cos(),
        R_EARTH_KM * lat.cos() * lon.sin(),
        R_EARTH_KM * lat.sin(),
    ]
}

/// Elevation angle (degrees) of `sat` seen from `gs` (both ECI, km).
pub fn elevation_deg(gs: [f64; 3], sat: [f64; 3]) -> f64 {
    let d = [sat[0] - gs[0], sat[1] - gs[1], sat[2] - gs[2]];
    let dn = (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt();
    let gn = (gs[0] * gs[0] + gs[1] * gs[1] + gs[2] * gs[2]).sqrt();
    let sin_el = (d[0] * gs[0] + d[1] * gs[1] + d[2] * gs[2]) / (dn * gn);
    sin_el.clamp(-1.0, 1.0).asin().to_degrees()
}

pub fn generate(cfg: &PlanConfig) -> Plan {
    let c = &cfg.constellation;
    let g = cfg.stations.len();
    let sats = c.planes * c.per_plane;
    let mut contacts = Vec::new();
    let mut open: Vec<Option<f64>> = vec![None; g * sats];
    let steps = (cfg.horizon_s / cfg.step_s).ceil() as usize;
    for k in 0..=steps {
        let t = (k as f64 * cfg.step_s).min(cfg.horizon_s);
        for (gi, st) in cfg.stations.iter().enumerate() {
            let gp = gs_eci(st, t);
            for si in 0..sats {
                let up = k < steps && elevation_deg(gp, sat_eci(c, si, t)) >= cfg.min_elevation_deg;
                let slot = &mut open[gi * sats + si];
                match (up, *slot) {
                    (true, None) => *slot = Some(t),
                    (false, Some(start)) => {
                        for (a, b) in [(gi, g + si), (g + si, gi)] {
                            contacts.push(Contact {
                                from: a,
                                to: b,
                                start,
                                end: t,
                                rate_bps: cfg.ground_rate_bps,
                            });
                        }
                        *slot = None;
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(rate) = cfg.isl_rate_bps {
        for p in 0..c.planes {
            for s in 0..c.per_plane {
                let a = g + p * c.per_plane + s;
                let b = g + p * c.per_plane + (s + 1) % c.per_plane;
                for (x, y) in [(a, b), (b, a)] {
                    contacts.push(Contact {
                        from: x,
                        to: y,
                        start: 0.0,
                        end: cfg.horizon_s,
                        rate_bps: rate,
                    });
                }
            }
        }
    }
    contacts.sort_by(|x, y| x.start.total_cmp(&y.start));
    Plan {
        nodes: g + sats,
        ground: g,
        contacts,
    }
}
