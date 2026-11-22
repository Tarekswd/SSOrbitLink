//! Contact-plan inspection: per-ground-station pass count and total contact time.
//!   cargo run --release --example contacts [hours=12]
use orbitlink::contact::{PlanConfig, default_ground_stations, default_shells, generate};

fn main() {
    let hours: f64 = std::env::args()
        .nth(1)
        .and_then(|h| h.parse().ok())
        .unwrap_or(12.0);
    let stations = default_ground_stations();
    let plan = generate(&PlanConfig {
        shells: default_shells(),
        stations: stations.clone(),
        horizon_s: hours * 3600.0,
        step_s: 10.0,
        min_elevation_deg: 10.0,
        ground_rate_bps: 256_000.0,
        isl_rate_bps: None,
    });
    println!("{} contacts over {hours} h", plan.contacts.len());
    for (g, st) in stations.iter().enumerate() {
        let passes: Vec<_> = plan.contacts.iter().filter(|c| c.from == g).collect();
        let secs: f64 = passes.iter().map(|c| c.end - c.start).sum();
        println!(
            "{:10} lat {:6.1}: {:4} passes, {:7.0} s in contact ({:.1} % of time, counting overlaps)",
            st.name,
            st.lat_deg,
            passes.len(),
            secs,
            100.0 * secs / (hours * 3600.0)
        );
    }
}
