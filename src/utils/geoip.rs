//! IP -> country resolution via an IP2Location LITE database (PMS-657).
//!
//! Reads the same IP2Location LITE `.BIN` DB the ecosystem already deploys
//! (`IP2LOCATION_DB_PATH`, e.g. `/data/IP2LOCATION-LITE-DB11.BIN`, as used by
//! dmarc-reporter and bunyip). It is used only to detect a country-level change
//! between a user's logins; when no DB is configured the login-location-alert
//! feature is disabled (this service is never constructed). Lookups are offline:
//! no per-login external call, and no client IP is sent to a third party.

use std::net::IpAddr;

use ip2location::{Record, DB};

use crate::utils::error::{AppError, AppResult};

/// An opened IP2Location database, queried for the country of a client IP.
pub struct GeoIpService {
    db: DB,
}

impl GeoIpService {
    /// Open the IP2Location `.BIN` database at `db_path`. Fails loudly if the
    /// path is set but unreadable, so a misconfiguration surfaces at startup
    /// rather than silently disabling alerts.
    pub fn new(db_path: &str) -> AppResult<Self> {
        let db = DB::from_file(db_path)
            .map_err(|e| AppError::internal(format!("IP2Location DB load failed: {e}")))?;
        Ok(Self { db })
    }

    /// The ISO 3166-1 alpha-2 country code for `ip`, or `None` when the IP is not
    /// resolvable (private / reserved / unknown ranges carry no country).
    pub fn country_code(&self, ip: IpAddr) -> Option<String> {
        let raw = match self.db.ip_lookup(ip).ok()? {
            Record::LocationDb(rec) => rec.country.map(|c| c.short_name),
            Record::ProxyDb(_) => None,
        }?;
        normalize_country_code(&raw)
    }
}

/// Normalize an IP2Location country field into a usable ISO 3166-1 alpha-2 code,
/// or `None`. IP2Location stores `"-"` (and occasionally a blank) for unknown /
/// reserved ranges; those are not real countries and must never be treated as a
/// login-location change (PMS-657).
fn normalize_country_code(raw: &str) -> Option<String> {
    let code = raw.trim();
    if code.is_empty() || code == "-" {
        None
    } else {
        Some(code.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_country_code;

    #[test]
    fn rejects_placeholder_and_blank() {
        assert_eq!(normalize_country_code("-"), None);
        assert_eq!(normalize_country_code(""), None);
        assert_eq!(normalize_country_code("   "), None);
    }

    #[test]
    fn keeps_and_trims_iso2() {
        assert_eq!(normalize_country_code("US"), Some("US".to_string()));
        assert_eq!(normalize_country_code(" GB "), Some("GB".to_string()));
    }
}
