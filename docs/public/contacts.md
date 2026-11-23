# Contacts

A contact is a person at a client's company. Contacts hold the MSP's working relationship with the client: who to email about an incident, who approves a quote, who receives an invoice, who logs in to the customer portal.

## The company mirror

Every contact names the company they belong to. For reporting and quick reads, the contact row carries a mirror of the primary company's id (the `company_id` field on the contact). The source of truth is the contact-to-company link table; the mirror is rebuilt from the link on every update.

What this means for an operator or integrator:

- Create a contact, and you must give it a company link. A contact with no link stops showing up on the company's contact list.
- Edit a contact, and the mirror re-derives. You do not patch `company_id` directly; the server computes it from the link.
- Delete the link, and the mirror nulls on the next edit of any field. This is the right behavior: a contact with no company is an orphan the MSP should notice.

The server enforces this invariant in code. A write path that inserts a contact without the matching company link fails the build, not a runtime check.

## Portal access

A contact reaches the customer portal when the MSP admin assigns them a portal role. The portal role is a capability bundle (`tickets:read`, `tickets:write`, `kb:read`, `invoices:read`, `invoices:pay`, and so on). A contact with no portal role has no portal access at all.

Portal roles are tenant-scoped templates. Build one role per archetype (billing contact, technical contact, read-only auditor) and assign; a contact can hold more than one role, taking the union of their capabilities.

## Ticket notes

A ticket carries public notes (visible to the contact) and internal notes (staff only). Who can edit a note is tenant policy:

- `off`: nobody edits a saved note. The write path answers 403.
- `author_or_admin`: the author of the note, or an admin, edits. This is the default.
- `author_or_manager`: the author or a manager edits.

Three rules refuse to let a note be edited regardless of policy:

- A customer's own words (a note written by a contact) are never editable by staff.
- A public note that has already been emailed out cannot be edited; the client already has a copy.
- A time-entry mirror (a note auto-generated from a time entry) cannot be edited directly; edit the time entry.

Every note write (edit, delete, restore) records an audit row the journal shows. An edited note shows the edit history in the UI.

## Mail audiences

Transactional mail serves one audience. A staff password-reset and a client-portal password-reset are separate templates, not one template with a conditional. A welcome mail to a new staff user and a welcome mail to a new portal admin are separate templates.

The server's mail renderer is a flat `{{key}}` replacer with no conditionals; a template with a `{% if %}` would ship literal text to the recipient. The right shape is one template per audience with the right context keys, seeded at tenant creation and copied to new tenants.

A deployment adding a new transactional mail checks whether its dispatch sites share an audience and a context contract. Two audiences, two templates; two contracts, two templates.

## Contact sync

An MSP can import contacts from Google Workspace, Microsoft 365, or an iCloud CardDAV address book. Each provider connects per-tenant through OAuth, selects a set of labels or groups to import, and polls on a cadence the admin configures.

The connection and the cadence both live in the contact-sync surface, not in the integrations catalog:

- The integrations catalog lists Contact Sync as a connector; writes against it answer "the connection is managed under Contact Sync".
- The contact-sync page owns the OAuth state, the label filter, and the per-connection interval.

This matters because a cadence read from one table while the connection lives in another is the split that causes drift when one side changes.

## The label filter

The label (or group) selection is the import filter. A record that carries none of the selected labels is skipped. The selection is the admin's intent: the MSP wants to import the "Clients" label and nothing else.

A blank selection does not mean "import everything". A sync with no selected labels refuses to run and answers a specific validation error. If you want to import everything, you set an explicit all-contacts sentinel; this is a deliberate choice an admin makes, never the default state of a fresh connection.

Moving a contact out of the selected label stops future updates for that contact. The contact is not tombstoned (the MSP still holds the data); it just stops receiving updates from the source. Moving them back resumes the sync.

Minimum sync interval is 5 minutes (a third party's rate limiter cares). Maximum is 24 hours (longer means "turn off the sync, do not pretend"). An admin wanting to pause a provider turns the per-provider switch off, which is distinct from the cadence.
