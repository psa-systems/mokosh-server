//! Real client IP extraction behind a trusted reverse proxy (PMS-587).
//!
//! Mokosh runs behind Traefik, so the socket peer address is the proxy, not
//! the client. Reading the peer alone recorded the proxy IP (or NULL when no
//! peer was threaded through), so the audit log showed `-`. The real client
//! address must come from the `X-Forwarded-For` header, but only when the peer
//! is a trusted proxy - otherwise a direct client could spoof the header and
//! poison the recorded IP. This mirrors Bunyip's `extract_client_ip` +
//! `TRUSTED_PROXY_CIDR` handling.

use std::net::IpAddr;
use std::sync::OnceLock;

use axum::http::HeaderMap;
use ipnetwork::IpNetwork;

/// Trusted-proxy CIDRs used when `TRUSTED_PROXY_CIDR` is unset: loopback plus
/// the RFC1918 / RFC4193 (ULA) / link-local private ranges. Mokosh sits behind
/// Traefik on a private Docker/LAN network, so the proxy's peer address always
/// falls in one of these, while a public client never does - so out of the box
/// the forwarded header is honored for real proxied traffic and ignored for a
/// direct public client. Operators tighten this to the exact proxy subnet via
/// the `TRUSTED_PROXY_CIDR` env var.
const DEFAULT_TRUSTED_PROXY_CIDRS: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

static TRUSTED_PROXIES: OnceLock<Vec<IpNetwork>> = OnceLock::new();

/// Parse `TRUSTED_PROXY_CIDR` (comma-separated CIDRs) once and cache it,
/// falling back to [`DEFAULT_TRUSTED_PROXY_CIDRS`]. An unparseable entry is
/// skipped with a warning rather than aborting boot, so a single typo cannot
/// take the server down; if every configured entry is invalid the list is
/// empty and the forwarded header is trusted from no one (peer address wins).
pub fn trusted_proxies() -> &'static [IpNetwork] {
    TRUSTED_PROXIES.get_or_init(|| match std::env::var("TRUSTED_PROXY_CIDR") {
        Ok(raw) if !raw.trim().is_empty() => raw
            .split(',')
            .filter_map(|entry| {
                let entry = entry.trim();
                if entry.is_empty() {
                    return None;
                }
                match entry.parse::<IpNetwork>() {
                    Ok(net) => Some(net),
                    Err(e) => {
                        tracing::warn!("ignoring invalid TRUSTED_PROXY_CIDR entry {entry:?}: {e}");
                        None
                    }
                }
            })
            .collect(),
        _ => DEFAULT_TRUSTED_PROXY_CIDRS
            .iter()
            .map(|cidr| cidr.parse().expect("built-in default CIDR is valid"))
            .collect(),
    })
}

/// True when `ip` sits inside any trusted-proxy CIDR.
fn is_trusted(ip: IpAddr, trusted: &[IpNetwork]) -> bool {
    trusted.iter().any(|net| net.contains(ip))
}

/// Parse one `X-Forwarded-For` element into an [`IpAddr`], tolerating an
/// accidental `:port` suffix or `[ipv6]:port` bracket form. Returns `None`
/// for anything that is not a recognisable address (garbled header), so the
/// caller skips it rather than panicking.
fn parse_forwarded_ip(element: &str) -> Option<IpAddr> {
    // Bare address first: covers IPv4 and bracketless IPv6 (which contains
    // colons, so it must be tried before the `host:port` split below).
    if let Ok(ip) = element.parse::<IpAddr>() {
        return Some(ip);
    }
    // `[::1]` or `[::1]:8080`
    if let Some(rest) = element.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            if let Ok(ip) = rest[..end].parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    // `1.2.3.4:5678`
    if let Some((host, _port)) = element.rsplit_once(':') {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

/// Resolve the real client IP for a request.
///
/// `peer` is the socket peer address (from `ConnectInfo`). When `peer` is a
/// trusted proxy we walk `X-Forwarded-For` right-to-left, skipping further
/// trusted proxies, and return the first (right-most) untrusted address - the
/// client as seen by the outermost trusted hop. A spoofed left-most entry is
/// ignored because we stop at the first untrusted address from the right. When
/// `peer` is NOT trusted (a direct client, possibly spoofing the header) the
/// header is ignored entirely and `peer` is returned. Never panics on a
/// missing or garbled header.
pub fn extract_client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNetwork]) -> IpAddr {
    if !is_trusted(peer, trusted) {
        return peer;
    }
    // Peer is a trusted proxy: trust the forwarded chain, but only up to the
    // first untrusted hop from the right. Multiple `X-Forwarded-For` headers
    // are treated as one concatenated list, so iterate the headers in reverse
    // and each header's elements right-to-left to walk the whole chain from
    // the right.
    for value in headers.get_all("x-forwarded-for").iter().rev() {
        let Ok(list) = value.to_str() else { continue };
        for element in list.rsplit(',') {
            let Some(ip) = parse_forwarded_ip(element.trim()) else {
                continue;
            };
            if !is_trusted(ip, trusted) {
                return ip;
            }
        }
    }
    // No untrusted address in the chain (chain is all proxies, or the header
    // is absent / garbled): the proxy itself is the closest thing to a client
    // we can attribute the request to.
    peer
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn nets(cidrs: &[&str]) -> Vec<IpNetwork> {
        cidrs.iter().map(|c| c.parse().unwrap()).collect()
    }

    fn default_nets() -> Vec<IpNetwork> {
        DEFAULT_TRUSTED_PROXY_CIDRS
            .iter()
            .map(|c| c.parse().unwrap())
            .collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn direct_client_no_header_uses_peer() {
        // AC4: direct request records the peer and never panics.
        let peer = ip("203.0.113.7");
        assert_eq!(
            extract_client_ip(peer, &HeaderMap::new(), &default_nets()),
            peer
        );
    }

    #[test]
    fn direct_client_spoofed_header_is_ignored() {
        // AC2: an untrusted peer's forwarded header cannot poison the IP.
        let peer = ip("203.0.113.7");
        assert_eq!(
            extract_client_ip(peer, &xff("1.2.3.4"), &default_nets()),
            peer
        );
    }

    #[test]
    fn trusted_proxy_returns_forwarded_client() {
        // AC1: behind a trusted proxy the client IP comes from the header.
        let peer = ip("10.0.0.1");
        assert_eq!(
            extract_client_ip(peer, &xff("203.0.113.7"), &default_nets()),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn trusted_proxy_takes_rightmost_untrusted_over_spoof() {
        // AC2: client at 203.0.113.7 spoofs a left-most 1.2.3.4; the proxy
        // appends the real peer, so the right-most untrusted address wins.
        let peer = ip("10.0.0.1");
        assert_eq!(
            extract_client_ip(peer, &xff("1.2.3.4, 203.0.113.7"), &default_nets()),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn trusted_proxy_skips_trailing_trusted_hops() {
        // A chain of internal proxies is skipped down to the real client.
        let peer = ip("10.0.0.1");
        assert_eq!(
            extract_client_ip(
                peer,
                &xff("203.0.113.7, 10.0.0.9, 10.0.0.1"),
                &default_nets()
            ),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn trusted_proxy_all_internal_chain_falls_back_to_peer() {
        // Chain is entirely trusted: no client to attribute, use the peer.
        let peer = ip("10.0.0.1");
        assert_eq!(
            extract_client_ip(peer, &xff("10.0.0.9, 10.0.0.1"), &default_nets()),
            peer
        );
    }

    #[test]
    fn trusted_proxy_garbled_header_falls_back_to_peer() {
        // AC4: a garbled header does not panic and yields a sensible value.
        let peer = ip("10.0.0.1");
        assert_eq!(
            extract_client_ip(peer, &xff("not-an-ip, still/garbage"), &default_nets()),
            peer
        );
    }

    #[test]
    fn forwarded_element_with_port_and_brackets() {
        assert_eq!(parse_forwarded_ip("1.2.3.4"), Some(ip("1.2.3.4")));
        assert_eq!(parse_forwarded_ip("1.2.3.4:5678"), Some(ip("1.2.3.4")));
        assert_eq!(parse_forwarded_ip("2001:db8::1"), Some(ip("2001:db8::1")));
        assert_eq!(
            parse_forwarded_ip("[2001:db8::1]:443"),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(parse_forwarded_ip("garbage"), None);
    }

    #[test]
    fn custom_trusted_cidr_narrows_the_allowlist() {
        // Only 192.168.1.0/24 is trusted: a 10.x peer is treated as a direct
        // client and its forwarded header is ignored.
        let trusted = nets(&["192.168.1.0/24"]);
        assert_eq!(
            extract_client_ip(ip("10.0.0.1"), &xff("203.0.113.7"), &trusted),
            ip("10.0.0.1")
        );
        assert_eq!(
            extract_client_ip(ip("192.168.1.5"), &xff("203.0.113.7"), &trusted),
            ip("203.0.113.7")
        );
    }
}
