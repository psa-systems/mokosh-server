#!/usr/bin/env nu
# Service Desk slice demo (Milestone 1).
#
# Drives the live mokosh-server API through the exact path the integration
# test covers, but as a human-readable walkthrough with two real actors:
#
#   technician  -> open a ticket -> start a timer -> stop it -> a rounded,
#                  billable, ticket-linked time entry -> submit the week
#   manager     -> approve the technician's week
#
# The technician is seeded once (idempotent) with a known dev password so the
# walkthrough can log in as a second actor; everything else goes through the
# public API. Run against a fully-up dev stack.
#
# Usage:
#   nu scripts/demo-service-desk.nu
#
# Environment (all optional; defaults target the dev stack):
#   API_BASE        default http://localhost:4301
#   ADMIN_EMAIL     default admin@example.com
#   ADMIN_PASSWORD  default devpassword12
#   DATABASE_URL    default postgres://postgres:postgres@localhost:5433/mokosh

def main [] {
    let api = ($env.API_BASE? | default "http://localhost:4301")
    let admin_email = ($env.ADMIN_EMAIL? | default "admin@example.com")
    let admin_password = ($env.ADMIN_PASSWORD? | default "devpassword12")
    let database_url = ($env.DATABASE_URL? | default "postgres://postgres:postgres@localhost:5433/mokosh")
    let tenant_id = "00000000-0000-0000-0000-000000000001"
    let tech_email = "demo-tech@example.com"
    let tech_password = "demo-tech-pw-12345"
    # argon2id hash of $tech_password, produced by the server's
    # utils::crypto::hash_password. A dev-only credential, parallel to the
    # plaintext ADMIN_PASSWORD already committed in .env.
    let tech_hash = '$argon2id$v=19$m=19456,t=2,p=1$epQf5rzgTD00HFlV8A6YcA$oVrjEGYFnbXbPyzbY1HROSA+in0C81tZDlhmB7V0Njs'

    print "1/9 Seeding technician (idempotent)..."
    let seed_sql = r#'
INSERT INTO users (
    id, tenant_id, email, password_hash,
    first_name, last_name, role, status, email_verified_at
)
SELECT gen_random_uuid(), :'tenant', :'email', :'hash',
       'Tess', 'Tech', 'technician', 'active', NOW()
WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = :'email');
'#
    (psql $database_url
        --variable $"tenant=($tenant_id)"
        --variable $"email=($tech_email)"
        --variable $"hash=($tech_hash)"
        --quiet --command $seed_sql)

    print "2/9 Manager login..."
    let admin_token = (
        http post --content-type application/json $"($api)/api/v1/auth/login" {
            email: $admin_email, password: $admin_password
        } | get access_token
    )
    let admin_auth = {Authorization: $"Bearer ($admin_token)"}

    print "3/9 Create a company..."
    let company_id = (
        http post --content-type application/json --headers $admin_auth $"($api)/api/v1/contacts/companies" {
            name: "Demo Co"
        } | get id
    )

    print "4/9 Open a ticket..."
    let ticket_id = (
        http post --content-type application/json --headers $admin_auth $"($api)/api/v1/tickets" {
            title: "Printer down",
            company_id: $company_id,
            description: "PCL errors on every job.",
            custom_fields: {}
        } | get id
    )

    print "5/9 Technician login..."
    let tech_token = (
        http post --content-type application/json $"($api)/api/v1/auth/login" {
            email: $tech_email, password: $tech_password
        } | get access_token
    )
    let tech_auth = {Authorization: $"Bearer ($tech_token)"}
    let tech_id = (http get --headers $tech_auth $"($api)/api/v1/auth/me" | get id)

    # Pick a seeded work type (Remote Support sorts first) to classify + price.
    let work_type_id = (
        http get --headers $admin_auth $"($api)/api/v1/work-types" | first | get id
    )

    print "6/9 Technician starts a timer on the ticket..."
    let timer_id = (
        http post --content-type application/json --headers $tech_auth $"($api)/api/v1/timers/start" {
            ticket_id: $ticket_id,
            company_id: $company_id,
            work_type_id: $work_type_id,
            notes: "Diagnosing printer"
        } | get id
    )

    print "7/9 Technician stops the timer (rounds + prices the entry)..."
    let entry = (
        http post --content-type application/json --headers $tech_auth $"($api)/api/v1/timers/($timer_id)/stop" {}
    )
    let entry_date = $entry.date

    print "8/9 Technician submits the week..."
    let submitted = (
        http post --content-type application/json --headers $tech_auth $"($api)/api/v1/timesheets/($tech_id)/($entry_date)/submit" {}
    )

    print "9/9 Manager approves the week..."
    let approved = (
        http post --content-type application/json --headers $admin_auth $"($api)/api/v1/timesheets/($tech_id)/($entry_date)/approve" {}
    )

    print ""
    print "Service Desk slice complete:"
    [
        [step value];
        ["entry duration (min)" $entry.duration_minutes]
        ["entry billable" $entry.is_billable]
        ["entry hourly_rate" $entry.hourly_rate]
        ["entry total_amount" $entry.total_amount]
        ["week after submit" $submitted.approval_status]
        ["week after approve" $approved.approval_status]
    ] | table
}
