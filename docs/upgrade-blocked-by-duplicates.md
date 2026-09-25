# Upgrade blocked: a unique-name migration cannot build its index

An upgrade stops with a message like this, and the server does not start:

```
error: while executing migration 153: error returned from database:
could not create unique index "tenants_name_ci_unique_idx"
```

The database holds rows that a migration is about to make unique, and it will
not finish until they are deduplicated by hand. This page is that repair.

## Who this can happen to

Only a database whose data predates the migration named in the error AND that
has never applied it. A database that has already applied it recorded a
checksum for it and will never run it again, and a fresh install has no user
data by the time it reaches these migrations. In practice that means a
long-lived deployment being upgraded across a gap, or an old backup restored
and then upgraded.

The repair has to happen BEFORE the upgrade, on the database as it stands.
`sqlx` applies migrations in version order and stops at the first failure, so
nothing later in the sequence can clean up for it: a fix shipped as migration
250 never runs on the database that is stuck at 153. The migrations themselves
cannot carry the dedupe either, because editing one that any database has
already applied changes its checksum and makes THAT database refuse to boot
(`migration N was previously applied but has been modified`), which is how
v0.4.0 took nc-01 down.

## The five indexes that can block an upgrade

Each row gives the migration, what it makes unique, and which rows it looks at.
Run the DETECT query first: if it returns nothing, that migration is not your
problem.

### 153, one name per tenant

```sql
-- DETECT
SELECT LOWER(name) AS collides_on, count(*), array_agg(id) AS rows
FROM tenants WHERE personal_owner_id IS NULL
GROUP BY 1 HAVING count(*) > 1;

-- REPAIR: keep the oldest, suffix the rest
WITH ranked AS (
  SELECT id, row_number() OVER (PARTITION BY LOWER(name) ORDER BY created_at, id) AS n
  FROM tenants WHERE personal_owner_id IS NULL
)
UPDATE tenants t SET name = t.name || ' (' || r.n || ')'
FROM ranked r WHERE t.id = r.id AND r.n > 1;
```

### 155, one active team name per tenant

```sql
-- DETECT
SELECT tenant_id, LOWER(name), count(*)
FROM teams WHERE is_active
GROUP BY 1, 2 HAVING count(*) > 1;

-- REPAIR
WITH ranked AS (
  SELECT id, row_number() OVER (
    PARTITION BY tenant_id, LOWER(name) ORDER BY created_at, id) AS n
  FROM teams WHERE is_active
)
UPDATE teams t SET name = t.name || ' (' || r.n || ')'
FROM ranked r WHERE t.id = r.id AND r.n > 1;
```

### 177, one portal-role name per scope

Two indexes, and a role is in exactly one of them: tenant-wide roles
(`company_id IS NULL`) and company-scoped roles are separate namespaces.

```sql
-- DETECT (tenant-wide)
SELECT tenant_id, LOWER(name), count(*)
FROM portal_roles WHERE company_id IS NULL
GROUP BY 1, 2 HAVING count(*) > 1;

-- DETECT (company-scoped)
SELECT tenant_id, company_id, LOWER(name), count(*)
FROM portal_roles WHERE company_id IS NOT NULL
GROUP BY 1, 2, 3 HAVING count(*) > 1;

-- REPAIR: one statement covers both, because the partition includes
-- company_id and NULL partitions separately from a real id.
WITH ranked AS (
  SELECT id, row_number() OVER (
    PARTITION BY tenant_id, company_id, LOWER(name) ORDER BY created_at, id) AS n
  FROM portal_roles
)
UPDATE portal_roles p SET name = p.name || ' (' || r.n || ')'
FROM ranked r WHERE p.id = r.id AND r.n > 1;
```

Renaming a built-in role is safe as far as the index goes, but check
`contact_role_assignments` afterwards if your integration looks roles up by
name rather than by id.

### 183, one portal login per email per company

The only one where renaming is the wrong repair: an email address identifies a
person, and appending a suffix would produce an address nobody can receive
mail at. Decide which row is the real portal user and demote the others.

```sql
-- DETECT
SELECT tenant_id, company_id, LOWER(email), count(*), array_agg(id) AS rows
FROM contacts
WHERE email IS NOT NULL AND company_id IS NOT NULL AND is_portal_user
GROUP BY 1, 2, 3 HAVING count(*) > 1;

-- REPAIR: keep the oldest portal login, leave the duplicates as ordinary
-- contacts. They keep their email, their history and their links; they just
-- stop being a login, which is what the index is asserting.
WITH ranked AS (
  SELECT id, row_number() OVER (
    PARTITION BY tenant_id, company_id, LOWER(email) ORDER BY created_at, id) AS n
  FROM contacts
  WHERE email IS NOT NULL AND company_id IS NOT NULL AND is_portal_user
)
UPDATE contacts c SET is_portal_user = FALSE
FROM ranked r WHERE c.id = r.id AND r.n > 1;
```

Check the demoted rows before you upgrade: if the newer row is the one the
customer actually signs in as, demote the older one instead by inverting the
`ORDER BY`.

### 157, one seat per person per tenant

A different shape from the four above: nothing here is about a name, and the
index that rejects the row is on `tenant_memberships`, not on the table holding
the duplicates.

```
error: while executing migration 157: error returned from database:
duplicate key value violates unique constraint
"tenant_memberships_identity_id_tenant_id_key"
```

`users` has a case-SENSITIVE `UNIQUE (tenant_id, email)`, so one tenant can
hold `Bob@acme.com` and `bob@acme.com`. Migration 157 folds both into a single
identity (`DISTINCT ON (lower(email))`) and then gives every `users` row a
membership, which asks for two `(identity, tenant)` rows where only one may
exist. The dual-write trigger the same migration installs already carries
`ON CONFLICT (identity_id, tenant_id) DO UPDATE`, so this is a one-time
backfill problem and not a live one: a case-variant user created today is
absorbed rather than rejected.

```sql
-- DETECT
SELECT tenant_id, LOWER(email) AS collides_on, count(*), array_agg(email) AS addresses
FROM users GROUP BY 1, 2 HAVING count(*) > 1;
```

There is no mechanical repair, because the rows mean something the new model
cannot express: one human holding two seats in one tenant. Decide which case
the pair is.

**Two different people, one of whom has a typo'd address.** Correct the wrong
one. Both keep their seat, their history and their links, and they become two
identities, which is what they are.

```sql
UPDATE users SET email = 'the.address.they.actually.use@example.com'
WHERE id = '<the row with the wrong address>';
```

**One person with a duplicate row.** Decide which row is the seat they use.
Give the other a distinct, parked address so the backfill can proceed, then
retire it through the application (deactivate the user) rather than deleting
the row: a `users` row is referenced by time entries, tickets and audit rows,
and deleting it takes their history with it.

```sql
UPDATE users SET email = 'bob+duplicate@acme.com'
WHERE id = '<the row that is not the real seat>';
```

Either way the addresses end up distinct, which is all the backfill needs.

## After the repair

Run the upgrade again. It resumes at the migration that failed, because a
failed migration records nothing, and continues to the end.

## Verified

Two of these were run against a real database rather than reasoned about.

Migration 153 (PMS-1229): migrated to 152, seeded the documented `Acme Corp` /
`Acme corp` pair, watched 153 abort with the error at the top of this page,
applied the repair, and re-ran the upgrade, which applied every migration
through to the head.

Migration 157 (PMS-1231): migrated to 156, seeded `Bob@acme.com` and
`bob@acme.com` in one tenant, watched 157 abort on
`tenant_memberships_identity_id_tenant_id_key`, made the two addresses
distinct, and re-ran the upgrade, which again reached the head.

The remaining queries are the same shape, read off their own index
definitions.
