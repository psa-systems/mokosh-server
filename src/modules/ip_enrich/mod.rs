//! Admin IP enrichment (BUNYIP-475): an advisory ASN / VPN lookup that consumes
//! the shared `dunite-ipenrich` crate.
//!
//! BUNYIP-437 put the enrichment ingestion in one shared crate precisely so a
//! second product (mokosh, after bunyip) can consume the same signal without a
//! second implementation that would drift. This module is that consumer: it
//! opens an IP2Proxy PX `.BIN` at `IP2PROXY_DB_PATH` (built in `main.rs`,
//! mirroring the geoip service) and exposes a narrow admin endpoint that maps an
//! address to its ASN, owning organization, network category and VPN/proxy
//! likelihood.
//!
//! Advisory only: the signal is context for a human reviewing an IP (e.g. an
//! actor IP in the audit log), never an automatic abuse verdict. A VPN must not
//! auto-classify a request, per BUNYIP-437.

pub mod routes;

pub use routes::ip_enrich_routes;
