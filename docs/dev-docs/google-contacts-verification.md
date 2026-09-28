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

- A Google Cloud project with the People API enabled, and an OAuth client of type **Web application**.
- Its authorised redirect URI must be, exactly, `<PUBLIC_API_BASE_URL>/api/v1/public/contact-sync/google/callback`.
  Copy it from the Settings card rather than typing it; one character out and the consent screen refuses before
  Mokosh is involved.
- A throwaway Google account. You will be signing into it on a screen and revoking its tokens.
- A Mokosh tenant you are an admin of, and one you are willing to leave imported records in.
- `just check` green in both repos before you begin, so a failure during the pass is the pass's.

## Seed the account

Same six shapes the offline test uses, so a difference is a difference in Google rather than in the data. Put the
first six in a label called `Clients`; leave the seventh in no label at all.

| # | Shape | Concretely |
|---|---|---|
| 1 | Several emails and phones | Two addresses and two numbers, one of each marked primary in Google |
| 2 | No email | A name and a phone number only |
| 3 | A single name | One name in the given-name field, family name empty (`Prince`) |
| 4 | A non-Latin script name | `王小明`, with an address |
| 5 + 6 | Two records that should match one Mokosh record | Both carrying the SAME address as an existing Mokosh contact, with slightly different names |
| 7 | Outside every group | Any contact, in no label |

Then, in Mokosh, make sure a contact already exists with the address you used for 5 and 6, so there is something
for them to match.

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
