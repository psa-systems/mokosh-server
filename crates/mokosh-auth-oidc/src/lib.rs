//! Mokosh auth: OpenID Connect provider engine.
//!
//! Pure protocol logic. Receives constructor-injected repositories, key
//! sets, clock and config; never opens a TCP socket, reads env vars, or
//! issues SQL directly.
