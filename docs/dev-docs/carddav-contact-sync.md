# CardDAV contact sync: design (PMS-1292)

Status: **design only, nothing built.** Part of PSA-70 (the vCard addendum).
Written 2026-09-21 against `main` after PMS-1288, PMS-1289 and PMS-1290
merged. This is a decision record for the build issues that would follow it,
and it goes stale the day the first of them lands.

## Summary

CardDAV (RFC 6352) is one client for iCloud, Fastmail, Nextcloud and most
self-hosted contact servers. Every card it serves is a vCard, so the reader
from PMS-1289 (`contact_sync::vcard`) parses it unchanged.

- **The canonical model and the provider interface need no change.**
  `SourceContact` and `ContactSyncProvider` take it as they are. There is one
  small change to the vCard reader: it has to expose group cards rather than
  only count them (see "Groups").
- **The schema needs a small change, not none.** Two things are required: the
  provider `CHECK` on `contact_sync_connections` gains `carddav`, with
  `provider::SUPPORTED` in step (the existing guard test holds them together).
  Beyond that, one nullable column is recommended for the address book URL (see
  "Credentials"). No new table.
- **iCloud has no third-party OAuth.** The credential is an Apple ID plus an
  app-specific password, stored only through `SecretProvider`.
- **Google stays on the People API.** Google does serve CardDAV, but the People
  API exposes contact groups, which the opt-in selection depends on (PSA-70 E).

Estimated build: four server issues and one apps issue, roughly one and a half
to two weeks for one developer. The breakdown is at the end.

## Servers in scope

| Server | Base for discovery | Credential | Groups are | Notes |
|---|---|---|---|---|
| iCloud | `https://contacts.icloud.com` (`contacts.icloud.com.cn` for China accounts) | Apple ID + app-specific password | separate group vCards | Partitioned hosts (`pNN-contacts.icloud.com`) come back from discovery. `addressbook-multiget` refuses absolute-URI hrefs with 400, and absolute-path hrefs work. Sync tokens are invalidated occasionally. |
| Fastmail | `https://fastmail.com` (DAVx5's documented entry; the service itself is `carddav.messagingengine.com`) | app password with contacts access | separate group vCards | Offers OAuth to clients it has registered, which is not something Mokosh could use without registering with Fastmail. |
| Nextcloud | `https://<host>/remote.php/dav` | app password (required with 2FA) | `CATEGORIES` | Its Contacts app uses only `CATEGORIES`. Often self-hosted on a private network (see "Outbound safety"). |
| Any RFC 6352 server (Radicale, Baïkal, SOGo, ...) | `/.well-known/carddav` on the host | username + password | either | Radicale is the candidate for CI (see "Testing"). |

## Fit with what exists

| Piece | Change |
|---|---|
| `provider::SourceContact` | None. A card is a vCard; `vcard::read_vcards` already produces this. |
| `provider::ContactSyncProvider` | None. `list_groups`, `changes_since` and the default `lists_everything() == true` are what CardDAV is: an address book IS the whole directory, so absence from a full read is a deletion, exactly as for Google. |
| `mapping`, `matching`, `sync::ContactSyncEngine` | None. |
| `contact_sync_connections` | `CHECK (provider IN ('google', 'vcard', 'carddav'))`, plus one recommended nullable column, `collection_url`. `account_email` holds the username. `sync_token` holds the DAV sync token. `selected_groups` holds group ids as for Google. The live index keeps one CardDAV account per tenant, the PSA-70 B decision. |
| `contact_sync_links`, `_candidates`, `_runs`, `_suppressions` | None. |
| `secrets::SecretKind::ContactSync { provider, connection_id }` | None. The app password is stored under `provider = "carddav"`, the key the Google refresh token already uses. |
| `vcard` reader | Expose group cards (`KIND:group`, `X-ADDRESSBOOKSERVER-KIND:group`) with their UID, name and members. Today it counts them in `group_cards` and drops them. |
| `runs::ContactSyncRunner` | Choose the source by provider: the Google factory, the stored file, or the CardDAV factory. Today it is a two-way `if`. |
| `integrations/google_contacts_enabled` | Today the runner applies this switch to every non-file provider, so it would also govern CardDAV. Add `integrations/carddav_contacts_enabled` and make the runner's check a match on provider. |

## Protocol

All requests go to the tenant-supplied host, so every one of them passes the
outbound gate below.

**Discovery (RFC 6764, then RFC 5397 and RFC 6352 section 7).**

1. From what the admin typed (a host, or an email domain), try `GET` or
   `PROPFIND` on `/.well-known/carddav`, following redirects hop by hop
   through the gate. SRV and TXT lookup (`_carddavs._tcp`) is optional in the
   RFC. It is deferred: the three named servers answer the well-known URI, and
   Nextcloud's is a redirect to `/remote.php/dav`.
2. `PROPFIND` (Depth 0) for `DAV:current-user-principal`.
3. `PROPFIND` on the principal for `CARDDAV:addressbook-home-set`.
4. `PROPFIND` (Depth 1) on the home set for collections whose `resourcetype`
   includes `CARDDAV:addressbook`, with `displayname` and
   `DAV:supported-report-set`.
5. The admin picks one address book. Its URL is stored as `collection_url`.
   iCloud has one, and Nextcloud often has several.

**Listing and deltas (RFC 6578).** `changes_since(token)` maps onto a
`DAV:sync-collection` REPORT on the collection:

- **`token == None`:** a sync-collection with an empty token, which returns
  every member href with its `getetag` and a new token. This is a full read.
- **`token == Some`:** the members changed since that token. A member deleted
  since then comes back as an href with status `404` and no properties. It
  becomes `SourceContact { deleted: true, external_id: href, .. }`.
- **Truncation:** status `507` with `DAV:number-of-matches-within-limits`.
  Keep requesting with each new token until the set is complete. A full read
  stays all or nothing, per the trait's rule: pages are collected and returned
  together, never partly.
- **Refused token:** the `DAV:valid-sync-token` precondition fails. RFC 6578
  does not fix the status, and servers answer 403 or 409. Treat either one,
  when the body names that precondition, as `was_full_resync = true`, the
  shape Google's `410 EXPIRED_SYNC_TOKEN` already has. iCloud invalidates
  tokens occasionally, so this path is routine, not exceptional.
- **No `sync-collection` in `supported-report-set`:** fall back to `PROPFIND`
  (Depth 1) for `getetag` on every run. That fallback is always a full read.
  All three named servers support the report.

**Fetching cards (RFC 6352 section 8.7).** An `addressbook-multiget` REPORT
for the changed hrefs, in batches of about 100, requesting `getetag` and
`CARDDAV:address-data`. Hrefs are sent as absolute paths, never absolute
URIs, because iCloud answers 400 to the latter. Each `address-data` body goes
through `vcard::read_vcards` under the same `Limits`, one card at a time.

## Identity, versions and deletions

- **`external_id` is the member href, not the vCard `UID`.** A deletion in
  `sync-collection` arrives as an href and a 404 with no card data, so the href
  is the only identity a deletion can be matched on. The `UID` is still read
  (it is what group membership names, below). Matching a CardDAV contact to one
  imported from Google or from a file happens by email, through the existing
  policy, and never by id.
- **`etag` is the DAV `getetag`.** An unchanged etag is the engine's existing
  "nothing to do".
- **Deletions are flagged, never deleted** (PSA-70 I), unchanged.

## Groups and the selection

The selection unit is a group, as for Google labels and file categories. A
card's `group_ids` is the union of two kinds:

- **Categories:** each `CATEGORIES` value is its own group (Nextcloud).
- **Group cards:** a vCard with `KIND:group` (4.0) or
  `X-ADDRESSBOOKSERVER-KIND:group` (Apple and Fastmail) lists its members as
  `MEMBER:urn:uuid:<UID>` or `X-ADDRESSBOOKSERVER-MEMBER:urn:uuid:<UID>`. The
  group id is the group card's href and its name is the card's `FN`. A contact
  belongs to every group card that names its `UID`.

`list_groups` offers both kinds, plus `provider::UNGROUPED_ID` for cards in
neither. That is the same "No category" the file import offers, and it is
never written as a tag.

**A delta that touches a group card is served as a full read.** Adding
someone to a group changes the group card, not the person's card. A delta
would report only the group card, and the member's own etag has not moved, so
the engine would skip the member and the new selection would never reach them.
Rather than keep a UID-to-href map between runs (state the trait has nowhere to
hold), the provider answers such a delta by doing a full read and saying
`was_full_resync = true`. That is correct, because a full read is complete,
and it is cheap, because group edits are rare.

## Credentials

- **Where:** the username goes in `account_email`, shown in Settings. The
  password (an iCloud app-specific password, or a Fastmail or Nextcloud app
  password) is stored through `SecretProvider` under
  `SecretKey::contact_sync(tenant, "carddav", connection_id)`. It never goes in
  a column, a log, an audit row or an error body. The PMS-968 ordering applies:
  mint the id, store the secret, then insert the row.
- **The collection URL is not a secret,** so it goes in the recommended
  `collection_url` column rather than in the secret payload. Settings shows it,
  every request is screened against it, and reading a secret to render a page
  is the pattern to avoid.
- **Auth scheme:** HTTP Basic over TLS. `https` is required except for a host
  on `OUTBOUND_PRIVATE_ALLOWLIST`, where an operator has deliberately named an
  internal server. A 401 maps to `SourceError::Unauthorized`, which sets
  `reconnect_required`, the state an admin can act on. iCloud revokes an
  app-specific password when the Apple ID password changes, so this path is
  expected.
- **Disconnect** deletes the stored password after the row is marked, as the
  Google disconnect does.

## Outbound safety

The server URL is tenant-supplied, so this is an SSRF surface, and the one
with the most redirects in it (discovery is built on them).

- Every request, and every redirect hop, goes through
  `utils::net::guard_outbound_url`. The client is built with
  `reqwest::redirect::Policy::none()` and follows hops itself, screening each
  one, which is the shape `TacticalRmmProvider` and the automation webhook
  already have. No second copy of the resolve-and-screen logic: the
  `exactly_one_definition_in_the_crate` test enforces that.
- A self-hosted Nextcloud on a private network is refused by default. The
  operator escape hatch is `OUTBOUND_PRIVATE_ALLOWLIST`, as for a private RMM,
  and the refusal message should say so.
- The residual PMS-805 names still applies: DNS rebinding between the screen
  and the connect is not covered without an IP-pinned connector.
- A card's `PHOTO` or `URL` is never fetched, as in the file import. The reader
  cannot make requests, and a source-scan test already proves it.

## Read-only by construction

The client has no method that writes. Its request builder can issue `GET`,
`PROPFIND` and `REPORT`, and nothing else. A source-scan test in the module
fails on `PUT`, `DELETE`, `PROPPATCH`, `MKCOL`, `MOVE` or `COPY`. That is the
CardDAV form of the Google connection's `contacts.readonly` scope: an app
password cannot be scoped read-only on these servers, so the guarantee has to
be the code's.

## Rate limits and failures

| Answer | Maps to |
|---|---|
| 429, or 503 with `Retry-After` | `SourceError::Throttled` (backoff, run re-queued, reads as `throttled`) |
| 401 | `SourceError::Unauthorized` (`reconnect_required`) |
| `valid-sync-token` precondition (403 or 409) | full read, `was_full_resync = true` |
| 507 with `number-of-matches-within-limits` | continue with the new token |
| a card the reader refuses | a `RecordFailure` for that href; the rest land |
| anything else | `SourceError::Failed`, in this codebase's words, never the server's body |

## Apps

- **A CardDAV card under Settings > Integrations.** It takes a server
  (with presets for iCloud and Fastmail, and a URL for anything else), a
  username and an app password, with a note saying which kind of password
  each preset needs. Then comes the address book picker from discovery. The
  consent dialog states what moves, as the Google one does.
- **After connecting,** the Google import wizard's selection, review and run
  steps apply unchanged. The review queue and provenance already name the
  source per record (MAPPS-916), so a `carddav` provider needs only its name
  in `provider_name`.

## Testing

- **Unit:** XML request bodies built and responses parsed, from captured
  fixtures of iCloud, Fastmail and Nextcloud responses. That includes the
  iCloud absolute-path quirk, a 507 truncation, a 404 deletion, and a
  `valid-sync-token` refusal.
- **Integration:** a Radicale server in CI (a Python package, pinned and
  checksum-verified, started in the job the way `tests/s3_storage.rs` starts
  MinIO) with a seeded collection. That covers a full read, a delta, a
  deletion, a group-card edit forcing a full read, a revoked password, and a
  redirect to a private address being refused.
- **Real-account verification** against iCloud, Fastmail and Nextcloud, the
  PMS-1216 and PMS-1291 shape.

## Building it

| Issue | Repo | Scope | Size |
|---|---|---|---|
| WebDAV client and discovery | server | `quick-xml` (a new dependency; nothing XML-shaped is in the graph today, and it has no dependencies of its own), a read-only request builder, redirect-by-hop through the gate, discovery to a collection list, the source-scan test | largest, about 4 days |
| `CarddavProvider` | server | `sync-collection` with truncation and refused-token handling, the `PROPFIND` fallback, `multiget` batching, group cards and categories, group-card deltas as full reads; the `vcard` reader exposing group cards | about 3 days |
| Connect, credential and runner | server | migration (CHECK, `collection_url`, granted per PMS-1265), connect and disconnect routes, `SecretKind` use, `carddav_contacts_enabled`, the runner choosing a source by provider | about 2 days |
| Radicale in CI | server | pinned binary in `integration.yml`, the integration suite above | about 1 day |
| CardDAV card | apps | connect form with presets, address book picker, reuse of the import wizard | about 2 days |

## Open questions

- **One CardDAV account per tenant** follows the live index and PSA-70 B. An
  MSP wanting iCloud and Nextcloud at once would need that index relaxed for
  `carddav`. That is not a reason to build it now.
- **Several address books in one account** (Nextcloud) are one pick at
  connect. Importing more than one would make the collection part of the
  identity, and it is deferred.
- **SRV discovery** is deferred until a server that needs it is named.

## Sources

- RFC 6352, CardDAV: <https://www.rfc-editor.org/rfc/rfc6352.html>
- RFC 6578, Collection Synchronization for WebDAV: <https://www.rfc-editor.org/rfc/rfc6578.html>
- RFC 6764, Locating CalDAV and CardDAV Services: <https://www.rfc-editor.org/rfc/rfc6764.html>
- RFC 5397, WebDAV Current Principal Extension: <https://www.rfc-editor.org/rfc/rfc5397.html>
- DAVx5, tested with iCloud: <https://www.davx5.com/tested-with/icloud>
- DAVx5, tested with Fastmail: <https://www.davx5.com/tested-with/fastmail>
- DAVx5, tested with Nextcloud: <https://www.davx5.com/tested-with/nextcloud>
- iCloud rejecting absolute-URI hrefs in `addressbook-multiget`: <https://github.com/kenn-io/msgvault/issues/849>
- Fastmail app passwords: <https://fastmail.help/hc/en-us/articles/360058752854>
