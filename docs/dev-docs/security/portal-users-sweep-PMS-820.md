# Where a portal request path touches `users` (PMS-820)

PMS-820 fixed one crossing: a customer resetting their portal password reached
the platform reset endpoint, which resolves the account by email against
`users`, and reset a staff login instead. Fixing only the two endpoints named
in the issue would leave the question "where else does a portal request reach
`users`?" unanswered, so this is the full sweep, kept as reference rather than
as a claim that has to be re-derived next time.

**Invariant.** A request arriving on `/api/v1/portal/*` never resolves, writes
or authorizes against a `users` row. Portal identity is the `contacts` row; the
`users` table may only be *read*, and only for display or for an FK the schema
requires, never as the acting identity and never as a credential.

**Search shape.** Every handler mounted by `portal_routes`
(`src/modules/portal/routes.rs:74`) and `portal_attachment_routes`
(`src/modules/tickets/attachments.rs:482`), followed into every service method
they call, grepped for `FROM users` / `JOIN users` / `INTO users` /
`UPDATE users` and for any lookup keyed on an email address. Line numbers are
as of the PMS-820 branch (`main` at `f12e8cc` plus this change).

| Site | What it does with `users` | Classification |
| --- | --- | --- |
| `portal/routes.rs:203` `forgot_password` -> `portal/service.rs:305` `request_password_reset` | nothing: resolves a `contacts` row by `(tenant_slug, email, is_portal_user)` and writes `portal_setup_tokens` | **changed** - this is the fix; before PMS-820 the only reset in the product resolved `users` by email |
| `portal/routes.rs:234` `reset_password` -> `portal/service.rs:437` | nothing: redeems the contact-bound token, writes `contacts.portal_password_hash` | **changed** - new in PMS-820 |
| `auth/routes.rs` `/auth/forgot-password`, `/auth/reset-password` | resolves `users` by email within the resolved tenant | **unchanged** - it is the platform path and stays that way. It is no longer reachable *from* the portal now that the portal has its own, and a portal-only address has no `users` row to find, so it silently 200s. Pinned by `portal_and_platform_resets_never_touch_each_other` |
| `portal/service.rs:76` `login` | none: `contacts` INNER JOIN `tenants` | not applicable |
| `portal/service.rs:454` `setup_password`, `:542` `set_password` | none: `portal_setup_tokens` + `contacts` | not applicable |
| `portal/service.rs:252` `contact_names` (portal middleware hydration) | none: `contacts` | not applicable |
| `tickets/service.rs:2006` `create_portal_ticket` | READ `SELECT id FROM users ... role IN (super_admin, admin, manager) LIMIT 1` for `tickets.created_by_id` | **unchanged** - `created_by_id` is NOT NULL with an FK to `users` and a contact has no row there. The acting identity is still the contact (`contact_id` is stamped separately, `source = 'portal'`); nothing is written to `users` and nothing authorizes off it |
| `tickets/service.rs:2222` `create_portal_ticket_note` | READ the same fallback admin for `ticket_notes.created_by_id` | **unchanged** - same NOT NULL FK, same reason; the contact is recorded in `created_by_contact_id` |
| `tickets/service.rs:2108` `list_portal_ticket_notes` | READ `LEFT JOIN users` for the note author's display name | **unchanged** - read-only display, tenant-scoped, no credential or authorization effect |
| `tickets/service.rs:2068` `list_portal_tickets`, `:2088` `get_portal_ticket` (via `TICKET_RESPONSE_SELECT`) | READ `LEFT JOIN users` for assignee / creator display names | **unchanged** - read-only display; the rows themselves are scoped by tenant AND the contact's company |
| `tickets/attachments.rs:603` `upload_portal` | writes `created_by_contact_id` and leaves `uploaded_by_id` (the FK to `users`) NULL | **unchanged** - already contact-attributed by construction |
| `quotes/service.rs` `decide_quote` -> `notify_owner_of_decision` | passes `recipient_user_id = quote.requested_by_id`; the dispatcher reads that `users` row's address | **unchanged** - an outbound staff notification about the client's decision. Read-only, and the recipient is the quote's owner, not the caller |
| `audit::AuditCtx` on the portal quote-decision routes | none: the extractor reads `AuthState`, which the portal tree never populates, so the actor is empty and `audit_log.user_id` is NULL | not applicable |
| `knowledge_base/service.rs:865` `list_portal_articles_for_company`; `billing` portal invoice list / get / pay | no `users` reference at all | not applicable |
| `audit/service.rs` (`LEFT JOIN users`, `:107`, `:130`) | not on a portal request path: the audit list is an agent-only route | not applicable |

**Result.** One crossing existed and it is the one PMS-820 removed. Every
remaining hit is a read: three of them satisfy a NOT NULL FK that points at
`users` because the schema has no contact-shaped alternative, the rest are
display joins or a staff-facing notification. No portal request path writes a
`users` row, and none authorizes off one.

**The FK residue is not a defect, but it is worth knowing about.**
`tickets.created_by_id` and `ticket_notes.created_by_id` force a portal-created
row to name an arbitrary active admin, which is why the "created by" of a
customer's own ticket reads as a staff member with the real author in a second
column. Changing that is a schema question (a nullable `created_by_id`, or a
polymorphic actor), well outside a password-reset fix, and it is not a security
boundary: the contact is recorded, and the fallback admin grants nobody
anything.
