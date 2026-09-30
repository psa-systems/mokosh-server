# Google Contacts seed data

Two vCard files that put PMS-1216's awkward account into a Google account, so the verification pass in
[`../google-contacts-verification.md`](../google-contacts-verification.md) starts from typing nothing.

| File | Contacts | What to do with it |
|---|---|---|
| `clients.vcf` | 6 | Import, then label all six exactly `Clients` |
| `ungrouped.vcf` | 1 | Import, apply no label at all |

## Why these values

They are the ones `tests/contact_sync_engine.rs::the_awkward_account_imports_through_the_engine` drives through the
real engine offline: several emails and phones with the primary first, a contact with no email, a single name, a
non-Latin name, two records that resolve to one Mokosh contact, and one record outside every label. Keeping the two
in step is what lets a failure during the pass be read as "Google does not behave the way the stub says" rather than
"the data was different this time". Change one and change the other, or the pass stops meaning that.

## Shape notes

vCard 3.0 with CRLF line endings, which is what the specification asks for and what every importer accepts.

The primary email and phone are simply first in the card and additionally carry `PREF`. Google's People API reports
the first of each as primary, so the order is what decides it; the `PREF` is belt and braces for importers that read
it.

`王小明` is in the given-name field rather than as a display name with an empty `N`. A card with an empty `N` is
legal and some importers drop it, and the assertion this seeds (`first_name` holding the name byte for byte) reads
the same either way.

Every address is under `.example` (RFC 2606), so nothing here can reach a real mailbox.
