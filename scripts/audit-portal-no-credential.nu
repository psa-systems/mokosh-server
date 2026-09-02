#!/usr/bin/env nu
# MAPPS-647 / PMS-917 AC3: survey portal contacts that hold no credential.
#
# PMS-917 was filed when David reproduced a no-password portal sign-in live
# on a call. Every contact-plane auth path now refuses `portal_password_hash
# IS NULL` (see src/modules/contact_portal/service.rs and the negative tests
# in tests/contact_auth.rs), but the ticket also demands a survey of existing
# rows so we know how many contacts sit in that state today and can watch
# the count trend to zero.
#
# The `grant_portal_access` flow legitimately creates a row with a NULL
# hash and mails a setup token that the contact has to redeem before they
# can sign in, so a non-zero row count is expected on any live deployment.
# What we're looking for is the shape of that queue: how many rows per
# tenant / Company sit un-redeemed, and whether any contact has been in
# that state longer than the setup-token lifetime (in which case the row
# is unreachable and should be tidied).
#
# Usage:
#   DATABASE_URL='postgres://user:pass@host:5432/mokosh' \
#     nu scripts/audit-portal-no-credential.nu
#
# The script reads via `psql` (never `psql --command` with interpolated
# values) so the query is fixed and cannot be shell-quoted around. Output
# is a per-row table plus a per-tenant summary; feed the redacted totals
# into a PMS-917 comment.

def main [] {
    let database_url = ($env.DATABASE_URL? | default "")
    if ($database_url | is-empty) {
        error make {msg: "DATABASE_URL is required (point it at the target deployment)."}
    }

    let query = "
        SELECT
            tenant_id::text                                              AS tenant_id,
            company_id::text                                             AS company_id,
            id::text                                                     AS contact_id,
            email,
            (created_at AT TIME ZONE 'UTC')::text                         AS created_at_utc,
            EXTRACT(EPOCH FROM (NOW() - created_at))::bigint / 86400      AS age_days
        FROM contacts
        WHERE is_portal_user = TRUE
          AND portal_password_hash IS NULL
        ORDER BY tenant_id, company_id, created_at
    "

    let rows = (
        ^psql $database_url --no-align --field-separator=$"(char tab)" --tuples-only --command $query
        | lines
        | where {|l| ($l | str trim | is-not-empty)}
        | each {|line|
            let parts = ($line | split row (char tab))
            {
                tenant_id:   ($parts | get 0)
                company_id:  ($parts | get 1)
                contact_id:  ($parts | get 2)
                email:       ($parts | get 3)
                created_at:  ($parts | get 4)
                age_days:    (($parts | get 5) | into int)
            }
        }
    )

    print $"contacts with is_portal_user = TRUE AND portal_password_hash IS NULL: ($rows | length)"
    print ""

    if ($rows | is-empty) {
        print "no rows -> all portal contacts hold a credential."
        return
    }

    print "per-row detail (safe to redact email column before pasting on the ticket):"
    print ($rows | table --index false)
    print ""

    let summary = (
        $rows
        | group-by tenant_id
        | transpose tenant_id rows
        | each {|g|
            {
                tenant_id:        $g.tenant_id
                rows:             ($g.rows | length)
                companies:        ($g.rows | get company_id | uniq | length)
                oldest_age_days:  ($g.rows | get age_days | math max)
            }
        }
    )

    print "per-tenant summary (safe to paste on PMS-917):"
    print ($summary | table --index false)

    # A row older than ~7 days is beyond the default setup-token lifetime
    # in migrations/042_portal_setup_tokens.sql; those contacts cannot
    # redeem their original invite and are effectively stranded.
    let stale = ($rows | where age_days > 7 | length)
    if $stale > 0 {
        print ""
        print $"WARNING: ($stale) row\(s) are older than 7 days and are beyond the setup-token lifetime; they are unreachable and should be resent an invite or tidied."
    }
}
