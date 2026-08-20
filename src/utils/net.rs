//! Network address classification shared across modules.
//!
//! PMS-805 lifted [`is_non_public_ip`] out of `AuthService`, where it had been a
//! private helper for the login-location check (PMS-657). The website probe
//! needs the same predicate as its SSRF guard, and two copies of "which
//! addresses are not on the public internet" would drift the first time one of
//! them learned about a new reserved range.

use std::net::IpAddr;

/// True for addresses that can never be a public internet peer: loopback,
/// RFC1918 / unique-local, link-local, unspecified, broadcast.
///
/// Two callers, two reasons. `AuthService` skips these so a request arriving
/// without a real client IP does not register as a country change. The website
/// probe refuses to connect to them at all, so an authenticated user cannot
/// point the server at `127.0.0.1` or `10.0.0.5` and read back a status code.
pub fn is_non_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_public_ip_detection() {
        let non_public = [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.10.10",
            "0.0.0.0",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
        ];
        for ip in non_public {
            assert!(
                is_non_public_ip(&ip.parse().unwrap()),
                "{ip} should be treated as non-public"
            );
        }

        let public = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"];
        for ip in public {
            assert!(
                !is_non_public_ip(&ip.parse().unwrap()),
                "{ip} should be treated as public"
            );
        }
    }
}
