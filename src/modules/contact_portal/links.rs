//! MAPPS-779: the one place a customer-facing portal URL is built.
//!
//! PMS-1168 made `BillingService::portal_pay_link` the single builder of the
//! invoice link, because two `format!` copies of it had drifted from the
//! router together: mokosh-apps retired the whole `/portal/*` customer route
//! family, and both copies went on emailing `/portal/invoices/{id}` to the
//! SPA's 404 page. That fix lived in billing, and the quote email - built by a
//! third `format!` in `QuotesService` - went on emailing `/portal/quotes/{id}`
//! to the same 404 for the same reason. One function per module is how the
//! same defect shipped twice; this is the one function for the portal.
//!
//! The shape is the company's portal login, not the document. `/quotes/{id}`
//! and `/invoices/{id}` sit behind the SPA's guard, and an unauthenticated
//! visitor there is bounced to the STAFF login, which is the wrong plane for a
//! customer. `?next=` carries the document through sign-in: the client's
//! `next_target` restores it only when it parses as a real route, and never
//! percent-decodes it, which is why it is appended here unencoded.

/// The portal login for a company, optionally returning the customer to `next`
/// once they are signed in.
///
/// `portal_id` is the company's 9-digit handle (migration 174). A company
/// without one gets `/portal/login`, which asks for the Company ID: the honest
/// landing for a contact whose company was never given a handle, and better
/// than a `/portal//login` that matches nothing.
///
/// `None` when the deployment has no portal origin, because a relative link in
/// an email resolves against the mail client and goes nowhere.
///
/// `next` must be an in-app path starting with a single `/`. Anything else is
/// dropped rather than sent: the client would refuse it anyway, and a link
/// that silently loses its destination is better than one that carries
/// something the client treats as hostile.
pub fn portal_login_link(
    origin: &str,
    portal_id: Option<i64>,
    next: Option<&str>,
) -> Option<String> {
    let origin = origin.trim().trim_end_matches('/');
    if origin.is_empty() {
        return None;
    }
    let base = match portal_id {
        Some(handle) => format!("{origin}/portal/{handle}/login"),
        None => format!("{origin}/portal/login"),
    };
    match next.filter(|n| is_in_app_path(n)) {
        Some(next) => Some(format!("{base}?next={next}")),
        None => Some(base),
    }
}

/// An absolute path within this app: one leading slash, not two (which a
/// browser reads as another host), and nothing that would end or split the
/// query value it is placed in.
fn is_in_app_path(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//") && !path.contains(['?', '#', '&', ' ', '\\'])
}

#[cfg(test)]
mod tests {
    use super::portal_login_link;

    /// The quote link: the company's login, returning to the quote.
    #[test]
    fn a_document_link_is_the_companys_login_returning_to_the_document() {
        assert_eq!(
            portal_login_link("https://msp.example", Some(123456789), Some("/quotes/abc"))
                .as_deref(),
            Some("https://msp.example/portal/123456789/login?next=/quotes/abc")
        );
        assert_eq!(
            portal_login_link("https://msp.example", None, Some("/quotes/abc")).as_deref(),
            Some("https://msp.example/portal/login?next=/quotes/abc")
        );
    }

    /// No destination is the invoice link's current shape, unchanged.
    #[test]
    fn no_destination_is_the_bare_login() {
        assert_eq!(
            portal_login_link("https://msp.example/", Some(1), None).as_deref(),
            Some("https://msp.example/portal/1/login")
        );
    }

    /// No origin, no link: a relative URL in an email goes nowhere.
    #[test]
    fn a_blank_origin_yields_no_link() {
        assert_eq!(portal_login_link("  ", Some(1), Some("/quotes/abc")), None);
    }

    /// Nothing that could leave the origin, or break the query, is carried.
    #[test]
    fn a_destination_that_is_not_an_in_app_path_is_dropped() {
        for hostile in [
            "//evil.example",
            "https://evil.example",
            "quotes/abc",
            "/a?b",
            "/a#b",
            "/a&b=c",
        ] {
            assert_eq!(
                portal_login_link("https://msp.example", Some(1), Some(hostile)).as_deref(),
                Some("https://msp.example/portal/1/login"),
                "{hostile:?} must not be carried"
            );
        }
    }

    /// The retired route family must never come back out of this function.
    #[test]
    fn the_retired_portal_document_routes_are_never_emitted() {
        let link = portal_login_link("https://msp.example", Some(1), Some("/quotes/abc")).unwrap();
        assert!(!link.contains("/portal/quotes/"), "{link}");
        assert!(!link.contains("/portal/invoices/"), "{link}");
    }
}
