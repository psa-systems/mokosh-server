# Knowledge base

The knowledge base holds articles the MSP writes once and reads often: how-to guides, runbooks, client-specific documentation, boilerplate responses. Articles live in categories; versions record who edited what and why; comments give staff a private discussion thread.

## Articles

An article has a title, body (Markdown), category, visibility, and an edited-by user. Writing an article is a manager or admin action; reading depends on visibility:

- **Internal**: staff only. Not visible on the portal.
- **Public**: visible on the portal to every contact with the `kb:read` capability.
- **Client-specific**: visible on the portal only to contacts of a named company.

A technician reads every internal article. A contact reads only the public and the specifically-scoped articles their company reaches.

## Versions

Every save of an article creates a version row. Each version records:

- The editor's user id (never missing; attribution has always been there).
- A change kind (`create` for the first version, `edit` for a normal save, `restore` for a restore of a past version).
- An optional change note explaining the edit.
- The full body as of that save.

Restoring a past version is an action a manager (or admin) takes. The restore writes a new version with kind `restore` and a reference back to the version it restored from; the prior history stays intact.

The last editor on an article, as shown in listings, is the article's own `updated_by` user (or the latest version's editor if the article has not been touched otherwise). Old articles pre-dating the attribution field still read their latest-version editor.

## Comments

Articles carry a staff-plane comment thread. A comment is one of:

- A new comment on the article (a "root").
- A reply to a root (one level deep; a reply to a reply is not supported).

Comments are staff-only, always. A contact never sees a comment, never writes one, and never gets notified of one. This is enforced by routing: every comment endpoint sits behind the knowledge-base module gate that a contact bearer never satisfies.

An author (or an admin, but deliberately not a manager) can edit or delete their own comment. A soft delete tombstones the row with the deletion recorded in the audit log.

## Mentions

A comment can mention another staff user with `@handle`. The server parses mentions server-side (handle, first name, or dotted-full-name with no ambiguity) and notifies each mentioned user once per comment. A token that could name two people names nobody; add more of the name and try again.

A mention points at the same person the UI chipped it as: if a comment chips `@aisha`, the notification goes to the Aisha the chip picked, never a different one. This is why the parser lives on the server, not in the client.

## Anchors

A root comment can anchor to a specific stretch of text in the article's rendered body. The anchor is a W3C text-quote selector (prefix, exact, suffix), stamped with the article version the anchor was taken against. The server validates the anchor's shape but does not resolve it; the client displays comments on the anchor spot it finds in the current render, or marks the comment orphaned if the text has changed too much to re-anchor.

## Template variables

An article can declare template variables (name, label, allowed values, default). A rendered article substitutes the values:

- A staff caller renders through `POST /api/v1/kb/articles/{id}/render` with a values object.
- A contact caller does the same, scoped to what they can read.
- A declared variable with no value renders as `[missing: NAME]`, not as an error.
- A variable not declared on the article but supplied in the call is rejected with 400.

An article with no template variables renders byte-identically to its stored body; the template engine is skipped entirely, so stray `{{` sequences in untemplated Markdown are never parsed.

## Attachments

Article attachments are images the Markdown body embeds. Uploads are manager-gated; the read is public (because an `<img>` tag cannot carry a bearer). Attachments carry their own size cap, configured by `KB_ATTACHMENT_MAX_BYTES`.

## KB executions on tickets

A ticket can execute a KB article as a runbook. Each step in the article can be toggled done on that execution. This is staff-plane only; the contact plane sees the article, not the execution.
