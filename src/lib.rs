//! OrbitLink: delay-tolerant satellite networking research simulator.
//!
//! Standard parts come from existing implementations: BPv7 bundles and BPSec/RFC 9173 security
//! contexts from the `bp7` crate, ML-KEM-768 from `ml-kem`. Research parts are the contact-plan
//! generator (contact.rs), the routing comparison (sim.rs) and the experimental PQ key transport
//! (security.rs, `Mode::BcbPq`). SIMULATION ONLY: no claim of compatibility with flight hardware.

pub mod contact;
pub mod cose;
pub mod rng;
pub mod security;
pub mod sim;
