# Documents

The PDFs Mokosh renders (invoices, credit notes, statements, quotes) are the artefacts a client keeps. The server treats them accordingly: identity frozen at issue, bytes preserved for seven years, fonts embedded, glyphs subsetted so the stored file is small.

## The issuer is frozen at first send

An invoice carries the MSP's identity (legal name, tax id, postal address, logo) frozen at the moment it was first sent. Not at creation (the branding might still change), not at the SMTP relay's success callback (which is best-effort), but in the same transaction that moves the invoice to `sent`.

The frozen snapshot holds the logo bytes, not a URL. The live logo lives at one key per tenant and is overwritten when the MSP replaces it; a stored reference would re-render every sent invoice with whatever logo is current. The snapshot keeps a content-addressed copy keyed by digest, so two distinct logos are two objects and one logo is one object regardless of how many invoices use it.

What this means in practice:

- Replacing the tenant logo does not change the rendered image on invoices already sent.
- Renaming the MSP does not retroactively re-name past invoices.
- A reprint of a past invoice shows the identity that was sent.
- A draft invoice (not yet sent) renders with the live branding; it changes as the branding changes until it is sent.

## The issued bytes are kept, not reproduced

When an invoice first moves to `sent`, Mokosh renders the PDF and writes the bytes to its file store under the retention kind "financial document". A later `GET /invoices/{id}/pdf` serves those stored bytes, not a re-render.

A credit note's bytes are stored the instant it is created (a credit note is issued at creation, not at a later `sent`).

The point of this rule is narrow: it defends against the codebase changing, not against the data changing. The branding is already frozen (above) and `pdf::render` is deterministic, so a re-render would agree with what was sent, until somebody edits the renderer, at which point every past document would silently reprint differently. The stored bytes make that impossible.

Retention is declared at seven years for financial documents, which matches the retention most jurisdictions require for tax records. Nothing in Mokosh automatically deletes them; the declaration is operator-facing, and a sweep (if you want one) is an operator task on top. A test in the codebase fails the day a sweep appears, so the declaration cannot quietly become a promise.

A draft invoice has no stored bytes; it renders live. So does an invoice issued before this storage rule shipped (the stored-bytes-or-live-render fallback carries it forward).

## Statements render live

A statement is a read model with no stored row. It renders the company's current balance from current branding every time you ask for it. It does not freeze and does not store.

This is why `GET /statements/pdf` always reflects the tenant's current look, and a statement from yesterday is not a historical document in the same way an invoice is.

## Addressing: bill-to and recipient

Every document addresses the customer. A line on the document names the work (date, work type, ticket, description); the document header addresses the customer (company name, billing address, billing contact).

The billing-to block is resolved beside the issuer: the company's billing address falls back to its postal address, the billing contact falls back to the company's default billing contact. The result is handed to every document type (invoice, credit note, statement); they differ only in where the contact comes from.

An invoice reads the contact column on its own row, written when it was first sent. A credit note reads the column of the invoice it corrects. A statement reads the company's current default billing contact. The first two are historical because a reprint must name who received the document; the statement is not because it is a read model that always reflects today.

## Fonts

Every PDF Mokosh renders embeds Noto Sans regular and bold. The base-14 PDF fonts cover only Latin-1, which silently turned every code point above U+00FF into `?`: Latin Extended (Polish, Czech), Greek, Cyrillic, and the euro sign all mangled on a document the customer keeps. Noto Sans covers the Unicode range the MSP's customers write their names in.

Noto Sans stops at its own coverage, mainly CJK. A character outside the coverage still prints as `?`, but the renderer emits exactly one warning naming the characters and the document, because a silent substitution is what let it reach a customer in the first place.

## Glyph subsetting

Each PDF embeds only the glyphs it actually drew. A one-line invoice used to carry about 460 KB of font; subsetting takes it to about 11 KB. This matters per document, because the stored bytes above are kept for seven years and a 2 KB-per-year font tax adds up.

Subsetting is deterministic, so two documents differing only in content differ in size (that is what proves subsetting rather than coincidental smallness). A subsetter that refuses a glyph set logs an error and the whole face is embedded; the document is still correct, just larger. An invoice is never withheld over its size.

## Templates

A tenant picks a document template: `classic`, `modern`, or `compact`. The template controls layout, spacing, accent color, and footer; the content is the same.

`classic` is the default and matches the layout the server rendered before templates existed, so an existing tenant sees no change on upgrade unless they switch.

The template is a tenant setting resolved once beside the issuer. It freezes into the invoice's snapshot on first send along with the identity, so reprints reproduce the layout the document was sent in. A template-specific need (such as whether the footer is drawn) is a flag on the template, not a caller asking "if Modern" in the renderer.

An MSP whose brand is pale yellow does not get white-on-white text in the accent band; the text color is computed from the accent's relative luminance against WCAG contrast, never hardcoded to white.

## What document a client receives

Not every document carries a template:

- Invoices and credit notes carry the template and their stored bytes.
- Statements render live without a template (read model).
- Report exports (CSV, PDF reports) do not carry a template; they are not documents the client receives.

## Downloading

- `GET /api/v1/invoices/{id}/pdf`: finance and admin on the staff plane; the invoice-owning contact on the contact plane.
- `GET /api/v1/credit-notes/{id}/pdf`: same gates.
- `GET /api/v1/statements/pdf?company_id=`: same gates, read live.
