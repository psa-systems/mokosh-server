# Google Contacts: verification against a real account

PSA-70 phase 10 (PMS-1216). This is the pass that cannot be automated here, and this file exists so it is one
sitting rather than an afternoon of rediscovering how to force each condition.

## What this covers, and what it does not

The suites already drive every shape below through the real engine against a real Postgres, with the provider
faked: `tests/contact_sync_engine.rs::the_awkward_account_imports_through_the_engine` imports one account holding
all six awkward shapes and asserts what lands in `contacts`, and `contact_sync::google`'s own tests drive the
People API's wire format against a stub that answers pages, a `410`, a `429` and a `403`.

What no test here can do is tell you Google's real answers match those stubs. That is the whole point of this
pass: the field mask returning what the mapping expects, a real `syncToken` expiring the way the documentation
says, and a consent screen that grants what was asked for. Everything else is already pinned, so if a step below
fails, suspect the assumption about Google rather than the code, and check the stub in
`src/modules/contact_sync/google.rs` that encodes it.

## Before you start

- The HOST's Google client configured (PMS-1430). This is the operator's job, not the tester's and not a tenant's:
  the pair is a governed application-tier secret (`GOOGLE_CONTACTS_CLIENT_ID`, `GOOGLE_CONTACTS_CLIENT_SECRET`)
  served by whichever provider `SECRET_BACKEND` names, which on the hosted deployment is Infisical under `/app`.
  There is no Settings form: a tenant admin sees "configured" or "not available on this deployment".
  The registration procedure is at the end of this file.
- Its authorised redirect URI must be, exactly, `<PUBLIC_API_BASE_URL>/api/v1/public/contact-sync/google/callback`.
  One character out and the consent screen refuses before Mokosh is involved.
- A throwaway Google account. You will be signing into it on a screen and revoking its tokens.
- A Mokosh tenant you are an admin of, and one you are willing to leave imported records in.
- `just check` green in both repos before you begin, so a failure during the pass is the pass's.

## Seed the account

Import the two files in [`google-contacts-seed/`](google-contacts-seed/) rather than typing seven contacts. They
hold the same values the offline test drives
(`tests/contact_sync_engine.rs::the_awkward_account_imports_through_the_engine`), so a difference in what lands is
a difference in Google rather than in the data, which is the whole point of this pass.

At <https://contacts.google.com>, left rail, Import, Select file:

1. `google-contacts-seed/clients.vcf`, six contacts. Google offers the imported set straight after; select all six
   and apply a label named exactly `Clients`.
2. `google-contacts-seed/ungrouped.vcf`, one contact, and apply NO label to it. This one is the filter's test: it
   must never reach Mokosh.

Two files rather than one, because the alternative is "select all except that one", which is the step somebody
skips and then spends an hour explaining a seventh contact.

| # | Shape | In the file |
|---|---|---|
| 1 | Several emails and phones | Grace Hopper, two of each, the primary first in the card |
| 2 | No email | Nomail Person, a phone only |
| 3 | A single name | `Prince`, given name only, family name empty |
| 4 | A non-Latin script name | `王小明`, with an address |
| 5 + 6 | Two records that should match one Mokosh record | Ada Lovelace and A. Lovelace, both on `ada@acme.example` |
| 7 | Outside every group | Not Selected, in `ungrouped.vcf` |

Two things the files cannot do for you. **Create the Mokosh contact that 5 and 6 match**, before syncing: Contacts,
New contact, email `ada@acme.example`. Without it there is nothing for the twins to link to and run 1's expectation
about the review queue does not apply. And **the primary flag on contact 1** is Google's to decide: the People API
reports the first email and phone as primary, which is the order the card is written in, so what this pass checks
is that Mokosh preserves what Google reports rather than that the vCard dictated it.

The cards use `.example` addresses (RFC 2606), so nothing here can reach a real mailbox.

## The runs

Each one says how to drive it and what to look at. "The card" is Settings, Integrations, Google Contacts.

### 1. Connect and first import

Connect the account, then Choose labels. Tick `Clients` only.

- The per-label figures should say 6 records for `Clients`, not 7.
- Start the import. When it finishes: contact 3 lands as `first_name = Prince` with an EMPTY `last_name`, contact
  4 lands as `first_name = 王小明` byte for byte, contact 2 lands with no email, contact 1 keeps both numbers with
  the primary flagged, one of 5/6 links to the existing Mokosh contact and the other is in the review queue, and
  contact 7 is nowhere.
- `SELECT first_name, last_name, email FROM contacts WHERE id IN (...)` is the check that matters; the list page
  renders a display name and will hide an empty `last_name` either way.

### 2. The same sync twice

Press Sync now without touching anything.

- Every counter on the second run reads zero: nothing created, linked, queued or failed.
- If anything moves, the etag comparison is not doing its job and that is a real defect, not a flake.

### 3. A contact edited in Mokosh after linking

Edit one imported contact's job title in Mokosh, then change something ELSE about the same person in Google (their
phone, say), then Sync now.

- The Google change lands, and the title you typed is still there.
- The contact's provenance card lists the field you edited under Locked fields.

### 4. A contact deleted in Google

Delete contact 2 in Google. Sync now.

- Nothing about the Mokosh contact changes: same name, same email, same company.
- The card says one contact was deleted in the source, and the contact's provenance says so. It is a flag for a
  person to act on, never a deletion.

### 5. A forced expired sync token

Google's tokens last about seven days, so force it rather than wait:

```sql
UPDATE contact_sync_connections
   SET sync_token = 'a-token-google-will-refuse'
 WHERE provider = 'google' AND tenant_id = '<your tenant>';
```

Sync now.

- The run completes rather than failing, and it is a FULL read: the run row's total is the whole selection again,
  not a delta.
- Nothing is duplicated, and nothing is tombstoned. A full read is also what decides deletions, so a wrongly
  reported deletion here is the failure to watch for.

### 6. A revoked token

At `myaccount.google.com`, Data and privacy, Third-party apps, remove Mokosh's access. Sync now.

- The card reads that Google has revoked the connection and asks you to connect the account again.
- No records changed: the run failed before reading anything.
- Reconnecting the SAME Google account puts the card back to healthy and keeps the connection, its selection and
  its review queue. A DIFFERENT account is refused, naming the connected one.

### 7. A rate-limited response

This one cannot be forced politely, and that is worth saying rather than faking: Google rate-limits by project
quota, and hammering it to provoke a `429` also poisons the quota for the rest of the pass. The behaviour is
covered by `a_rate_limit_is_retried_then_succeeds` and `a_rate_limit_that_persists_is_throttled_not_failed`
against the stub. If you do see it naturally, the card must read Waiting and the run must go back to queued with
a later `not_before`, never Failed.

### 8. Disconnect

Disconnect from the card.

- Every imported contact is still in Mokosh, and each still says where it came from.
- Nothing is deleted from Google.

## What to record on the ticket

For each run: what you did, what the card said, and the row counts you checked. Where a step passed, one line is
enough. Where it did not, include the run row (`SELECT * FROM contact_sync_runs ORDER BY created_at DESC LIMIT 1`)
and the connection's `last_error`, because those carry the provider's own words and the log does not repeat them.

## Registering the host's Google client (operator)

Done once per deployment, by whoever runs it. A tenant never does this, which is the whole of PMS-1430.

1. In the Google Cloud console, create a project or pick one.
2. APIs and Services, Library: enable the **Google People API**. Without it every import fails with `SERVICE_DISABLED`.
3. Google Auth Platform (older consoles call it the OAuth consent screen): fill in Branding, set Audience, and while
   the app is in Testing add the accounts that may consent.
4. Data access: add exactly three scopes, `https://www.googleapis.com/auth/contacts.readonly`, `openid` and `email`.
   They are what `contact_sync::oauth::SCOPES` requests; a scope missing here is a consent screen granting less than
   the sync needs.
5. Clients, Create client, application type **Web application**, with the redirect URI above under Authorized
   redirect URIs. No JavaScript origins: the code exchange happens on the server.
6. Put the id and the secret in the provider this deployment DECLARES. Both or neither: one without the other is
   a boot error naming the missing half.

   On a deployment somebody can already sign in to, Settings has a page for this (PMS-1444): two fields, the
   secret write-only, and the value is live as soon as it saves, with no restart. That is the normal path and it
   needs no shell.

   What follows is the BOOTSTRAP path, for a deployment with nobody signed in yet, which is every deployment on
   its first day (PMS-1441).

   ```
   MOKOSH_SECRET_INPUT=<the id>     mokosh-server provider-set --secret GOOGLE_CONTACTS_CLIENT_ID     --from-env MOKOSH_SECRET_INPUT
   MOKOSH_SECRET_INPUT=<the secret> mokosh-server provider-set --secret GOOGLE_CONTACTS_CLIENT_SECRET --from-env MOKOSH_SECRET_INPUT
   mokosh-server provider-status --text
   ```

   The value goes in by the NAME of a variable, never as an argument, so it stays out of `ps`, shell history and
   a one-off container's argv. `provider-status` must then show both keys held and served by the declared
   provider; anything else means stop. Restart before expecting it to work: the pair is resolved once at boot.

   Which provider is declared is not a choice made here. `SECRET_BACKEND` unset means the hosting profile's
   default, which for `saas` is the DATABASE, not Infisical, on every deployment today (PMS-1440). Creating the
   entries in Infisical instead would leave them found by the boot survey and not by the reader, which is
   `Misplaced` and refuses to start. Run `provider-status` first if unsure; it names the declared provider.

Two properties of the Google application, which belong to this procedure rather than to the code:

- An **External** app still in **Testing** gets refresh tokens Google expires after **seven days**. Fine for a
  verification pass, fatal for a deployment anyone relies on.
- Publishing without Google's OAuth verification caps the app at **100 users** and shows each of them an unverified
  warning. `contacts.readonly` is a sensitive scope, so verification needs a verified domain, a homepage describing
  the data use, a published privacy policy, a consistent name and logo, a justification per scope and a demo video;
  it does NOT need the annual third-party security assessment, which applies to restricted scopes.

A client nobody owns is one nobody renews, so what follows is the record rather than an instruction to keep one.

## Who owns this client (as of 2026-09-30)

| | |
|---|---|
| Google Cloud project | `psa-systems-495317`, project number `106937243070` |
| Owner | david@niceguyit.biz |
| Developer contact | david@niceguyit.biz |
| User support email | vas@niceguyit.biz |
| Application home page | not recorded |
| Privacy policy URL | not recorded |
| Authorized domains | not recorded |
| Publishing status | In production, unverified (confirmed 2026-10-01: the app was published rather than left in Testing) |
| Verification status | not recorded |

The project number is also the first field of every client id it issues
(`106937243070-....apps.googleusercontent.com`), which is the quickest way to confirm a client belongs to this
project without opening the console.

The blanks are written down as blanks on purpose. Each one is a thing Google needs before `contacts.readonly` can
be verified, and a gap in a table is findable in a way an unasked question is not. Three of them are the same
question in different clothes: which domain this application claims as its own.

### Two things this record makes visible

### What "In production, unverified" costs, and what it does not

The seven-day refresh-token expiry does NOT apply. That is a property of an External app left in **Testing**, and this one is published, so a tenant that connects stays connected. The procedure above still describes the Testing rule because a self-hosted operator following it may well be in Testing, but it is not this deployment's situation.

What publishing unverified does cost, until verification completes:

- every person reaching the consent screen sees "Google hasn't verified this app" and has to click through an advanced-options warning
- the app is capped at **100 grants**, cumulatively, after which no new user can connect at all

The cap is the one with a hard edge. It is not 100 concurrent users or 100 per tenant; it is 100 users who have ever granted, so for a product sold to MSPs whose staff each connect an account it is a ceiling that arrives without warning and cannot be raised except by verification.

**One Owner, one named person.** The accounts are on the `niceguyit.biz` Workspace rather than personal Gmail,
which is better than the common case, but `david@` is the single Owner of the project every deployment's Google
Contacts integration depends on. If that account is suspended, offboarded or simply loses access, the client
cannot be rotated and the integration cannot be repaired on any deployment at once. The fix is one console action:
add a second Owner (`vas@` is already the support contact) or hand the project to a Workspace group. Worth doing
before verification rather than after, because Google's correspondence goes to the developer contact and a
transfer mid-review restarts it.

**The product and the project are on different domains.** The account domain is `niceguyit.biz`; the product,
its API and its apex are `psa.systems`. Google requires the home page and the privacy policy to sit on a domain
verified to the submitting account, so verification needs `psa.systems` verified in Search Console by an account
with access to this project, and the authorized-domains list has to name the domain actually used. `psa.systems`
is served by bunyip-web, which is the natural host for the policy page. That is the thing to settle before
submitting, because a privacy-policy URL that 404s or sits on an unverified domain is a rejection rather than a
question.

### What sends it back through verification

Not a judgement call, it is Google's published list, and any one of these is a re-review:

- adding or changing scopes, above all a new sensitive or restricted one
- changing the app name, the logo, the user support email or the developer contact
- changing the home page URL, the privacy policy URL, or the authorized domains
- moving from Testing to In production, or republishing after a return to Testing
- transferring project ownership, or moving the project between organisations

Reference: <https://support.google.com/cloud/answer/13463073>. Google corresponds through the developer contact,
so an address nobody reads is how verification lapses without anyone noticing.
