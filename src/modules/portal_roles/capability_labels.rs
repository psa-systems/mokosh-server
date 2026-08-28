//! Human-facing labels for every capability the SPA renders in the
//! role editor. The `key` field aligns 1:1 with
//! `contact_portal::capabilities::ALL_CAPABILITIES`; a unit test in
//! this file pins the two lists together so a new capability is a
//! compile-time flag rather than a silent UI gap.

use super::models::CapabilityDescriptor;
use crate::modules::contact_portal::capabilities as caps;

pub fn descriptors() -> Vec<CapabilityDescriptor> {
    vec![
        CapabilityDescriptor {
            key: caps::TICKETS_READ.to_string(),
            label: "View tickets".to_string(),
            group: "Tickets".to_string(),
            description: "See tickets scoped to the contact's own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_WRITE.to_string(),
            label: "Open tickets".to_string(),
            group: "Tickets".to_string(),
            description: "Create a new ticket on behalf of the Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_COMMENT.to_string(),
            label: "Comment on tickets".to_string(),
            group: "Tickets".to_string(),
            description: "Post a public comment on an existing ticket.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_REOPEN.to_string(),
            label: "Reopen closed tickets".to_string(),
            group: "Tickets".to_string(),
            description: "Reopen a resolved or closed ticket so the MSP works on it again."
                .to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_ATTACH_FILE.to_string(),
            label: "Attach files to tickets".to_string(),
            group: "Tickets".to_string(),
            description:
                "Upload attachments to open tickets so the MSP can see screenshots and logs."
                    .to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_EDIT_OWN.to_string(),
            label: "Edit own tickets".to_string(),
            group: "Tickets".to_string(),
            description: "Correct the title or description on a ticket you opened. Cannot change status, priority, or assignee (staff owns those).".to_string(),
        },
        CapabilityDescriptor {
            key: caps::TICKETS_REQUEST_APPROVAL.to_string(),
            label: "Request approval".to_string(),
            group: "Tickets".to_string(),
            description: "Ask your MSP for formal approval on a ticket (e.g. approve out-of-scope work, sign off on a resolution).".to_string(),
        },
        CapabilityDescriptor {
            key: caps::INVOICES_READ.to_string(),
            label: "View invoices".to_string(),
            group: "Invoices".to_string(),
            description: "See invoices scoped to the contact's own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::INVOICES_PAY.to_string(),
            label: "Pay invoices".to_string(),
            group: "Invoices".to_string(),
            description: "Start a payment checkout for an outstanding invoice.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::INVOICES_DOWNLOAD_PDF.to_string(),
            label: "Download invoice PDFs".to_string(),
            group: "Invoices".to_string(),
            description: "Download the PDF version of any invoice for the Company's records."
                .to_string(),
        },
        CapabilityDescriptor {
            key: caps::QUOTES_READ.to_string(),
            label: "View quotes".to_string(),
            group: "Quotes".to_string(),
            description: "See quotes scoped to the contact's own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::QUOTES_ACCEPT.to_string(),
            label: "Accept or decline quotes".to_string(),
            group: "Quotes".to_string(),
            description: "Sign off a quote on behalf of the Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::QUOTES_DOWNLOAD_PDF.to_string(),
            label: "Download quote PDFs".to_string(),
            group: "Quotes".to_string(),
            description: "Download the PDF version of any quote for internal review.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::CONTRACTS_READ.to_string(),
            label: "View contracts".to_string(),
            group: "Contracts".to_string(),
            description: "See contracts scoped to the contact's own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::ASSETS_READ.to_string(),
            label: "View assets".to_string(),
            group: "Assets".to_string(),
            description: "See configuration items scoped to the contact's own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::ASSETS_REPORT_ISSUE.to_string(),
            label: "Report an asset issue".to_string(),
            group: "Assets".to_string(),
            description: "File a new ticket linked to a specific asset for troubleshooting."
                .to_string(),
        },
        CapabilityDescriptor {
            key: caps::PROJECTS_READ.to_string(),
            label: "View projects".to_string(),
            group: "Projects".to_string(),
            description: "See projects scoped to the contact's own Company.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::KB_READ.to_string(),
            label: "Read knowledge base".to_string(),
            group: "Knowledge Base".to_string(),
            description: "Read published knowledge-base articles visible to the Company."
                .to_string(),
        },
        CapabilityDescriptor {
            key: caps::FORMS_SUBMIT.to_string(),
            label: "Submit request forms".to_string(),
            group: "Forms".to_string(),
            description: "Submit an MSP-published request form.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::NOTIFICATIONS_READ.to_string(),
            label: "Read notifications".to_string(),
            group: "Notifications".to_string(),
            description: "Read notifications addressed to the contact.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::SETTINGS_MANAGE_OWN.to_string(),
            label: "Manage own profile".to_string(),
            group: "Settings".to_string(),
            description: "Edit own profile, password, MFA, and active sessions.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::SETTINGS_MANAGE_COMPANY_BRANDING.to_string(),
            label: "Manage portal branding".to_string(),
            group: "Settings".to_string(),
            description: "Edit the portal's logo, colors, background, display name, and support contact block for this Company. MSP defaults still show through wherever a field is not overridden.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::CONTACTS_INVITE_SUB_USER.to_string(),
            label: "Invite sub-users".to_string(),
            group: "Sub-users".to_string(),
            description: "Invite a colleague at the same Company to the portal.".to_string(),
        },
        CapabilityDescriptor {
            key: caps::CONTACTS_MANAGE_SUB_USER.to_string(),
            label: "Manage sub-users".to_string(),
            group: "Sub-users".to_string(),
            description:
                "Assign roles, resend invites, and deactivate sub-users at the same Company."
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
