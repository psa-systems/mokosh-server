//! Network address classification and the shared outbound-URL SSRF guard.
//!
//! PMS-805 lifted [`is_non_public_ip`] out of `AuthService`, where it had been a
//! private helper for the login-location check (PMS-657). The website probe
//! needs the same predicate as its SSRF guard, and two copies of "which
//! addresses are not on the public internet" would drift the first time one of
//! them learned about a new reserved range.
//!
//! PMS-809 promoted the probe's whole resolve-then-screen gate here as
//! [`guard_outbound_url`], because the probe was not the only place the server
//! fetches a URL it did not hardcode: the ticket-automation `webhook` action
//! and the Tactical RMM provider both connect to tenant-supplied URLs. The
//! invariant is one sentence: every outbound fetch whose URL originates in a
//! request or in tenant-editable configuration screens its resolved addresses
//! before connecting, and re-screens every redirect hop.
//!
//! [`PrivateTargetAllowlist`] is the operator's escape hatch: an on-premise RMM
//! really does live on a private network, so `OUTBOUND_PRIVATE_ALLOWLIST` names
//! the hosts and CIDRs that are reachable on purpose. Shipping the block
//! without it would break self-hosted deployments.

use std::net::IpAddr;
use std::sync::OnceLock;

use async_trait::async_trait;
use ipnetwork::IpNetwork;
use url::Url;

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

/// Ports an http(s) fetch may use when the caller pins them. The website probe
/// does: a company website answers on 80 or 443 and nothing else. Tenant
/// integrations legitimately run on their own ports, so they pass `None`.
pub const WEB_PORTS: [u16; 2] = [80, 443];

/// Env var naming the hosts and networks an operator has declared reachable
/// even though they sit off the public internet.
const ALLOWLIST_VAR: &str = "OUTBOUND_PRIVATE_ALLOWLIST";

/// Resolve a host to its addresses. Injected so [`guard_outbound_url`] can be
/// unit tested without DNS and without a socket.
#[async_trait]
pub trait HostResolver: Send + Sync {
    /// The error is the resolution failure itself; the caller logs it before
    /// folding it into whatever its own callers see.
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String>;
}

/// The real resolver: the system stub, via tokio.
pub struct SystemResolver;

#[async_trait]
impl HostResolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        // A bracketed IPv6 literal reaches us with the brackets stripped by
        // `Url::host_str`, so it parses directly and needs no resolver.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| e.to_string())?;
        Ok(addresses.map(|a| a.ip()).collect())
    }
}

/// Why [`guard_outbound_url`] refused a URL. Every variant carries what the
/// caller needs to log: the port it rejected, the DNS failure, or the exact
/// address that failed the screen.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UrlGuardError {
    #[error("scheme {0:?} is not http or https")]
    Scheme(String),
    #[error("port {0} is not allowed")]
    Port(u16),
    #[error("the URL has no host")]
    NoHost,
    #[error("the host could not be resolved: {0}")]
    Dns(String),
    #[error("the host resolves to {0}, which is not on the public internet")]
    Blocked(IpAddr),
}

/// Hosts and networks an operator has declared reachable even though
/// [`is_non_public_ip`] rejects them: the on-premise RMM case.
///
/// An entry that parses as an address or a CIDR (`10.20.0.0/16`, `192.168.1.5`)
/// exempts matching resolved addresses. Anything else is treated as a hostname
/// and exempts that host outright, which is what an operator writes when they
/// do not control what the name resolves to.
#[derive(Debug, Default, Clone)]
pub struct PrivateTargetAllowlist {
    hosts: Vec<String>,
    networks: Vec<IpNetwork>,
}

impl PrivateTargetAllowlist {
    /// Parse a comma-separated list. An empty list allows nothing, which is the
    /// fail-closed default: the guard behaves exactly as PMS-805 wrote it.
    pub fn parse(raw: &str) -> Self {
        let mut hosts = Vec::new();
        let mut networks = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            match entry.parse::<IpNetwork>() {
                Ok(net) => networks.push(net),
                Err(_) => hosts.push(entry.to_ascii_lowercase()),
            }
        }
        Self { hosts, networks }
    }

    /// True when the operator named this host outright.
    pub fn allows_host(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.hosts.contains(&host)
    }

    /// True when the operator named a network containing this address.
    pub fn allows_address(&self, ip: &IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(*ip))
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.networks.is_empty()
    }
}

static PRIVATE_TARGETS: OnceLock<PrivateTargetAllowlist> = OnceLock::new();

/// Parse `OUTBOUND_PRIVATE_ALLOWLIST` once and cache it. Unset or empty means
/// no exemption at all, so a deployment that never configures it gets the
/// strict guard.
pub fn private_target_allowlist() -> &'static PrivateTargetAllowlist {
    PRIVATE_TARGETS.get_or_init(|| {
        let raw = match std::env::var(ALLOWLIST_VAR) {
            Ok(raw) => raw,
            Err(std::env::VarError::NotPresent) => String::new(),
            // A value that is set but unreadable is not the same as unset: the
            // operator configured an exemption that is about to be ignored.
            Err(e) => {
                tracing::error!(error = %e, "{ALLOWLIST_VAR} is set but unreadable; no target is exempt");
                String::new()
            }
        };
        let allowlist = PrivateTargetAllowlist::parse(&raw);
        if !allowlist.is_empty() {
            tracing::info!(
                hosts = allowlist.hosts.len(),
                networks = allowlist.networks.len(),
                "{ALLOWLIST_VAR} exempts private outbound targets"
            );
        }
        allowlist
    })
}

/// The SSRF gate every outbound fetch of a caller-supplied URL runs through,
/// before the first connect and again for every redirect hop.
///
/// `allowed_ports` pins the port set when the caller has one (the website probe
/// pins [`WEB_PORTS`]); `None` screens the address only. ANY non-public
/// resolved address refuses the URL: a name resolving to both a public and a
/// private address is exactly the shape an SSRF attempt takes.
///
/// The residual is the same one PMS-805 stated: a DNS rebinding attack that
/// changes the answer between this check and the connect is not covered without
/// an IP-pinned connector.
pub async fn guard_outbound_url<R: HostResolver + ?Sized>(
    resolver: &R,
    url: &Url,
    allowed_ports: Option<&[u16]>,
    allowlist: &PrivateTargetAllowlist,
) -> Result<(), UrlGuardError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(UrlGuardError::Scheme(url.scheme().to_string()));
    }
    let port = url.port_or_known_default().unwrap_or(0);
    if let Some(ports) = allowed_ports {
        if !ports.contains(&port) {
            return Err(UrlGuardError::Port(port));
        }
    }
    let Some(host) = url.host_str().filter(|h| !h.is_empty()) else {
        return Err(UrlGuardError::NoHost);
    };

    // An operator naming the host itself exempts whatever it resolves to,
    // because that is the case where they do not control the answer.
    if allowlist.allows_host(host) {
        return Ok(());
    }

    let addresses = resolver
        .resolve(host, port)
        .await
        .map_err(UrlGuardError::Dns)?;
    if addresses.is_empty() {
        return Err(UrlGuardError::Dns(format!(
            "{host} resolved to no addresses"
        )));
    }
    if let Some(blocked) = addresses
        .iter()
        .find(|ip| is_non_public_ip(ip) && !allowlist.allows_address(ip))
    {
        return Err(UrlGuardError::Blocked(*blocked));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PMS-805 lifted the predicate here precisely so a second copy could not
    /// drift from the first, and PMS-809 lifted the whole resolve-and-screen
    /// gate for the same reason. A prose note would not have held, so the
    /// "exactly one definition" half of that is enforced here: re-adding a
    /// private copy of either to any module fails this test.
    #[test]
    fn exactly_one_definition_in_the_crate() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for name in ["is_non_public_ip", "guard_outbound_url"] {
            // Assembled at runtime so this test's own source does not match it.
            let needle = format!("fn {name}");
            let mut definitions = Vec::new();
            let mut pending = vec![src.clone()];
            while let Some(dir) = pending.pop() {
                for entry in std::fs::read_dir(&dir).expect("read source directory") {
                    let path = entry.expect("read directory entry").path();
                    if path.is_dir() {
                        pending.push(path);
                    } else if path.extension().is_some_and(|e| e == "rs") {
                        let source = std::fs::read_to_string(&path).expect("read source file");
                        if source.contains(&needle) {
                            definitions.push(path);
                        }
                    }
                }
            }
            // `read_dir` order is filesystem-dependent; sort so a failure names
            // the same list every run.
            definitions.sort();
            assert_eq!(
                definitions,
                vec![src.join("utils").join("net.rs")],
                "{name} must have exactly one definition, in utils/net.rs; \
                 call it, do not copy it"
            );
        }
    }

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

    // ---- guard_outbound_url (no DNS, no socket) ----

    /// Scripted resolver: the test declares every answer, so nothing here
    /// resolves a real name or opens a connection.
    struct FakeResolver(Result<Vec<IpAddr>, String>);

    impl FakeResolver {
        fn answering(ips: &[&str]) -> Self {
            Self(Ok(ips
                .iter()
                .map(|ip| ip.parse().expect("test IP parses"))
                .collect()))
        }

        fn failing() -> Self {
            Self(Err("no such host".to_string()))
        }
    }

    #[async_trait]
    impl HostResolver for FakeResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
            self.0.clone()
        }
    }

    fn url(s: &str) -> Url {
        Url::parse(s).expect("test URL parses")
    }

    async fn guard(resolver: &FakeResolver, target: &str) -> Result<(), UrlGuardError> {
        guard_outbound_url(
            resolver,
            &url(target),
            None,
            &PrivateTargetAllowlist::default(),
        )
        .await
    }

    #[tokio::test]
    async fn guard_allows_a_public_target() {
        let resolver = FakeResolver::answering(&["93.184.216.34"]);
        assert_eq!(
            guard(&resolver, "https://hooks.example.com/t").await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn guard_refuses_a_loopback_target() {
        let resolver = FakeResolver::answering(&["127.0.0.1"]);
        assert_eq!(
            guard(&resolver, "http://hook.internal/t").await,
            Err(UrlGuardError::Blocked("127.0.0.1".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn guard_refuses_an_rfc1918_target() {
        let resolver = FakeResolver::answering(&["10.1.2.3"]);
        assert_eq!(
            guard(&resolver, "http://rmm.internal:8000/api").await,
            Err(UrlGuardError::Blocked("10.1.2.3".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn guard_refuses_a_name_resolving_to_both_public_and_private() {
        let resolver = FakeResolver::answering(&["93.184.216.34", "169.254.169.254"]);
        assert_eq!(
            guard(&resolver, "http://metadata.example.com/").await,
            Err(UrlGuardError::Blocked("169.254.169.254".parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn guard_allows_an_allowlisted_private_network() {
        let resolver = FakeResolver::answering(&["10.20.30.40"]);
        let allowlist = PrivateTargetAllowlist::parse("10.20.0.0/16, 192.168.5.7");
        assert_eq!(
            guard_outbound_url(
                &resolver,
                &url("https://rmm.internal:8443/api"),
                None,
                &allowlist
            )
            .await,
            Ok(())
        );
        assert!(allowlist.allows_address(&"192.168.5.7".parse().unwrap()));
        assert!(!allowlist.allows_address(&"10.99.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn guard_allows_an_allowlisted_host_without_resolving_it() {
        // The resolver would fail; an allowlisted host never reaches it, which
        // is what an operator wants when they do not control the DNS answer.
        let resolver = FakeResolver::failing();
        let allowlist = PrivateTargetAllowlist::parse("RMM.Internal");
        assert_eq!(
            guard_outbound_url(
                &resolver,
                &url("https://rmm.internal/api"),
                None,
                &allowlist
            )
            .await,
            Ok(())
        );
        // A host the operator did not name is still screened.
        assert!(matches!(
            guard_outbound_url(&resolver, &url("https://other.internal/"), None, &allowlist).await,
            Err(UrlGuardError::Dns(_))
        ));
    }

    #[tokio::test]
    async fn guard_enforces_the_port_set_when_the_caller_pins_one() {
        let resolver = FakeResolver::answering(&["93.184.216.34"]);
        assert_eq!(
            guard_outbound_url(
                &resolver,
                &url("https://example.com:8443/"),
                Some(&WEB_PORTS),
                &PrivateTargetAllowlist::default()
            )
            .await,
            Err(UrlGuardError::Port(8443))
        );
        // The same URL passes when the caller does not pin ports, because a
        // tenant integration legitimately runs on its own port.
        assert_eq!(guard(&resolver, "https://example.com:8443/").await, Ok(()));
    }

    #[tokio::test]
    async fn guard_refuses_a_non_http_scheme_and_a_hostless_url() {
        let resolver = FakeResolver::answering(&["93.184.216.34"]);
        assert_eq!(
            guard(&resolver, "ftp://example.com/x").await,
            Err(UrlGuardError::Scheme("ftp".to_string()))
        );
        assert_eq!(
            guard(&resolver, "file:///etc/passwd").await,
            Err(UrlGuardError::Scheme("file".to_string()))
        );
    }

    #[tokio::test]
    async fn guard_reports_a_resolution_failure_as_dns() {
        let resolver = FakeResolver::failing();
        assert!(matches!(
            guard(&resolver, "https://nx.example.com/").await,
            Err(UrlGuardError::Dns(_))
        ));
        let empty = FakeResolver::answering(&[]);
        assert!(matches!(
            guard(&empty, "https://nx.example.com/").await,
            Err(UrlGuardError::Dns(_))
        ));
    }

    #[test]
    fn allowlist_parse_separates_hosts_from_networks_and_ignores_blanks() {
        let allowlist = PrivateTargetAllowlist::parse(" 10.0.0.0/8 , , rmm.internal ,fd00::/8 ");
        assert!(allowlist.allows_address(&"10.1.1.1".parse().unwrap()));
        assert!(allowlist.allows_address(&"fd00::1".parse().unwrap()));
        assert!(allowlist.allows_host("RMM.INTERNAL"));
        assert!(!allowlist.allows_host("rmm.example.com"));
        assert!(PrivateTargetAllowlist::parse("").is_empty());
        assert!(PrivateTargetAllowlist::parse("  , ").is_empty());
    }
}
