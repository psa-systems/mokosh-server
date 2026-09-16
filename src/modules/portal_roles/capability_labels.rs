//! Human-facing labels for every capability the SPA renders in the
//! role editor. The `key` field aligns 1:1 with
//! `contact_portal::capabilities::ALL_CAPABILITIES`; a unit test in
//! this file pins the two lists together so a new capability is a
//! compile-time flag rather than a silent UI gap.
//!
//! PMS-1199: every `description` is written in second person, addressed
//! to the contact reading their own role ("You can ..."), not third
//! person ("the contact's ...") and not a subject-less imperative
//! ("Create a new ticket ..."). `descriptions_are_second_person` (below)
//! enforces this on every entry so a new capability landing in either of
//! the other two registers fails the build instead of drifting the file
//! back toward three voices.

use super::models::CapabilityDescriptor;
use crate::modules::contact_portal::capabilities as caps;

pub fn descriptors() -> Vec<CapabilityDescriptor> {
    vec![
        CapabilityDescriptor {
            key: caps::TICKETS_READ.to_string(),
            label: "View tickets".to_string(),
            group: "Tickets".to_string(),
            description: "You can see tickets scoped to your own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_WRITE.to_string(),
            label: "Open tickets".to_string(),
            group: "Tickets".to_string(),
            description: "You can create a new ticket on behalf of your Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_COMMENT.to_string(),
            label: "Comment on tickets".to_string(),
            group: "Tickets".to_string(),
            description: "You can post a public comment on an existing ticket.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_REOPEN.to_string(),
            label: "Reopen closed tickets".to_string(),
            group: "Tickets".to_string(),
            description: "You can reopen a resolved or closed ticket so your MSP works on it again."
                .to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_ATTACH_FILE.to_string(),
            label: "Attach files to tickets".to_string(),
            group: "Tickets".to_string(),
            description:
                "You can upload attachments to open tickets so your MSP can see screenshots and logs."
                    .to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_EDIT_OWN.to_string(),
            label: "Edit own tickets".to_string(),
            group: "Tickets".to_string(),
            description: "You can correct the title or description on a ticket you opened. You cannot change status, priority, or assignee (your MSP owns those).".to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_REQUEST_APPROVAL.to_string(),
            label: "Request approval".to_string(),
            group: "Tickets".to_string(),
            description: "You can ask your MSP for formal approval on a ticket (e.g. approve out-of-scope work, sign off on a resolution).".to_string(),
        },
        CapabilityDescriptor {
            key: caps::APPROVALS_DECIDE.to_string(),
            label: "Decide approvals".to_string(),
            group: "Approvals".to_string(),
            description: "You can see the approvals your MSP has addressed to you and approve or reject each one (e.g. sign off on a change request or on out-of-scope work).".to_string(),
        },
        CapabilityDescriptor {
            key: caps::INVOICES_READ.to_string(),
            label: "View invoices".to_string(),
            group: "Invoices".to_string(),
            description: "You can see invoices scoped to your own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::INVOICES_PAY.to_string(),
            label: "Pay invoices".to_string(),
            group: "Invoices".to_string(),
            description: "You can start a payment checkout for an outstanding invoice.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::INVOICES_PAY_PARTIAL.to_string(),
            label: "Pay a partial amount".to_string(),
            group: "Invoices".to_string(),
            description: "You can pay less than the outstanding balance on an invoice (a chosen amount between your MSP's minimum and the balance).".to_string(),
        },
        CapabilityDescriptor {
            key: caps::INVOICES_DOWNLOAD_PDF.to_string(),
            label: "Download invoice PDFs".to_string(),
            group: "Invoices".to_string(),
            description: "You can download the PDF version of any invoice for your Company's records."
                .to_string(),
        },
        CapabilityDescriptor {
            key: caps::PAYMENT_METHODS_MANAGE_OWN.to_string(),
            label: "Manage own payment methods".to_string(),
            group: "Invoices".to_string(),
            description: "You can save cards for future invoices, remove ones you no longer use, and pick which card is your default. Card data is typed into your payment provider's page and never touches your MSP.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::QUOTES_READ.to_string(),
            label: "View quotes".to_string(),
            group: "Quotes".to_string(),
            description: "You can see quotes scoped to your own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::QUOTES_ACCEPT.to_string(),
            label: "Accept or decline quotes".to_string(),
            group: "Quotes".to_string(),
            description: "You can sign off a quote on behalf of your Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::QUOTES_DOWNLOAD_PDF.to_string(),
            label: "Download quote PDFs".to_string(),
            group: "Quotes".to_string(),
            description: "You can download the PDF version of any quote for your own records."
                .to_string(),
        },
        CapabilityDescriptor {
            key: caps::CONTRACTS_READ.to_string(),
            label: "View contracts".to_string(),
            group: "Contracts".to_string(),
            description: "You can see contracts scoped to your own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::ASSETS_READ.to_string(),
            label: "View assets".to_string(),
            group: "Assets".to_string(),
            description: "You can see configuration items scoped to your own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::ASSETS_REPORT_ISSUE.to_string(),
            label: "Report an asset issue".to_string(),
            group: "Assets".to_string(),
            description: "You can file a new ticket linked to a specific asset for troubleshooting."
                .to_string(),
        },
        CapabilityDescriptor {
            key: caps::PROJECTS_READ.to_string(),
            label: "View projects".to_string(),
            group: "Projects".to_string(),
            description: "You can see projects scoped to your own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::KB_READ.to_string(),
            label: "Read knowledge base".to_string(),
            group: "Knowledge Base".to_string(),
            description: "You can read published knowledge-base articles visible to your Company."
                .to_string(),
        },
        CapabilityDescriptor {
            key: caps::NOTIFICATIONS_READ.to_string(),
            label: "Read notifications".to_string(),
            group: "Notifications".to_string(),
            description: "You can read notifications addressed to you.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::SETTINGS_MANAGE_OWN.to_string(),
            label: "Manage own profile".to_string(),
            group: "Settings".to_string(),
            description: "You can edit your own profile, password, MFA, and active sessions.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::SETTINGS_MANAGE_COMPANY_BRANDING.to_string(),
            label: "Manage portal branding".to_string(),
            group: "Settings".to_string(),
            description: "You can edit the portal's logo, colors, background, display name, and support contact block for your Company. Your MSP's defaults still show through wherever a field is not overridden.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::CONTACTS_INVITE_SUB_USER.to_string(),
            label: "Invite sub-users".to_string(),
            group: "Sub-users".to_string(),
            description: "You can invite a colleague at your Company to the portal.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::CONTACTS_MANAGE_SUB_USER.to_string(),
            label: "Manage sub-users".to_string(),
            group: "Sub-users".to_string(),
            description:
                "You can assign roles, resend invites, and deactivate sub-users at your Company."
                    .to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capability_has_a_descriptor() {
        let descriptors = descriptors();
        let keys: std::collections::HashSet<String> =
            descriptors.iter().map(|d| d.key.clone()).collect();
        for cap in caps::ALL_CAPABILITIES {
            assert!(
                keys.contains(*cap),
                "capability `{cap}` has no descriptor in portal_roles::capability_labels"
            );
        }
    }

    #[test]
    fn every_descriptor_has_a_capability() {
        for d in descriptors() {
            assert!(
                caps::ALL_CAPABILITIES.iter().any(|k| *k == d.key),
                "descriptor key `{}` is not a real capability",
                d.key
            );
        }
    }

    /// PMS-1199: the registry must read as one document in one
    /// grammatical person. Every descriptor's `description` is written
    /// second person, addressed to the contact reading their own role:
    /// it must say "you" or "your" somewhere, must not say "the
    /// contact" / "the contact's" (third person), and must not open
    /// with a subject-less imperative (a bare verb with no "You" in
    /// front of it).
    #[test]
    fn descriptions_are_second_person() {
        let descriptors = descriptors();
        assert!(
            descriptors.len() >= 26,
            "expected at least 26 descriptors, found {}",
            descriptors.len()
        );
        for d in &descriptors {
            let lower = d.description.to_lowercase();
            assert!(
                d.description.starts_with("You "),
                "descriptor `{}` opens with a subject-less imperative instead of \"You ...\": {:?}",
                d.key,
                d.description
            );
            assert!(
                lower.contains("you") || lower.contains("your"),
                "descriptor `{}` is not phrased in second person: {:?}",
                d.key,
                d.description
            );
            assert!(
                !lower.contains("the contact"),
                "descriptor `{}` uses third person (\"the contact\"): {:?}",
                d.key,
                d.description
            );
        }
    }

    #[test]
    fn labels_and_groups_are_non_empty() {
        for d in descriptors() {
            assert!(!d.label.trim().is_empty(), "empty label for {}", d.key);
            assert!(!d.group.trim().is_empty(), "empty group for {}", d.key);
            assert!(
                !d.description.trim().is_empty(),
                "empty description for {}",
                d.key
            );
        }
    }
}
